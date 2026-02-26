package match

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Engine struct {
	db            *sql.DB
	queryAffected *sql.Stmt
	queryAliases  *sql.Stmt
	queryRefs     *sql.Stmt
	queryRanges   *sql.Stmt
	opts          EngineOptions
}

type affectedRecord struct {
	affectedID  int64
	vulnID      string
	packagePURL string
	severity    string
}

type runCache struct {
	enabled  bool
	affected sync.Map
	aliases  sync.Map
	refs     sync.Map
	ranges   sync.Map
}

type componentResult struct {
	findings []Finding
	err      error
}

func NewEngine(db *sql.DB) (*Engine, error) {
	return NewEngineWithOptions(db, EngineOptions{
		EnableCache: true,
	})
}

func NewEngineWithOptions(db *sql.DB, opts EngineOptions) (*Engine, error) {
	if db == nil {
		return nil, fmt.Errorf("nil db")
	}

	if opts.WorkerCount <= 0 {
		opts.WorkerCount = defaultWorkerCount()
	}
	if opts.ProgressEvery <= 0 {
		opts.ProgressEvery = 250
	}

	e := &Engine{db: db, opts: opts}
	var err error

	e.queryAffected, err = db.Prepare(`
SELECT ap.affected_id, ap.vuln_id, ap.package_purl, v.severity
FROM affected_packages ap
JOIN vulnerabilities v ON v.vuln_id = ap.vuln_id
WHERE ap.ecosystem = ? AND ap.name = ?
`)
	if err != nil {
		return nil, fmt.Errorf("prepare affected query: %w", err)
	}

	e.queryAliases, err = db.Prepare(`SELECT alias FROM aliases WHERE vuln_id = ? ORDER BY alias`)
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("prepare aliases query: %w", err)
	}

	e.queryRefs, err = db.Prepare(`SELECT url FROM references_data WHERE vuln_id = ? ORDER BY url`)
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("prepare references query: %w", err)
	}

	e.queryRanges, err = db.Prepare(`
SELECT ar.range_id, ar.range_type, re.event_order, re.introduced, re.fixed, re.last_affected, re.limit_value
FROM affected_ranges ar
LEFT JOIN range_events re ON re.range_id = ar.range_id
WHERE ar.affected_id = ?
ORDER BY ar.range_id ASC, re.event_order ASC
`)
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("prepare ranges query: %w", err)
	}

	return e, nil
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	var errs []string
	for _, stmt := range []*sql.Stmt{e.queryAffected, e.queryAliases, e.queryRefs, e.queryRanges} {
		if stmt == nil {
			continue
		}
		if err := stmt.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close statements: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (e *Engine) MatchComponents(ctx context.Context, components []Component) ([]Finding, error) {
	if len(components) == 0 {
		return []Finding{}, nil
	}
	if e == nil || e.queryAffected == nil {
		return nil, fmt.Errorf("engine is not initialized")
	}

	workerCount := e.opts.WorkerCount
	if workerCount <= 0 {
		workerCount = 1
	}
	if workerCount > len(components) {
		workerCount = len(components)
	}
	if workerCount <= 0 {
		workerCount = 1
	}

	cache := &runCache{enabled: e.opts.EnableCache}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan Component)
	results := make(chan componentResult, workerCount)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for component := range jobs {
				if runCtx.Err() != nil {
					return
				}
				findings, err := e.matchComponent(runCtx, cache, component)
				if err != nil {
					select {
					case results <- componentResult{err: err}:
					default:
					}
					cancel()
					return
				}
				select {
				case results <- componentResult{findings: findings}:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, component := range components {
			select {
			case <-runCtx.Done():
				return
			case jobs <- component:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	seen := map[string]bool{}
	findings := make([]Finding, 0, len(components))
	processed := 0
	matched := 0
	var firstErr error

	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
			cancel()
		}
		if result.err == nil {
			for _, finding := range result.findings {
				key := strings.Join([]string{finding.VulnID, finding.PackagePURL, finding.InstalledVersion}, "|")
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, finding)
			}
			matched += len(result.findings)
		}
		processed++
		e.emitProgress(processed, len(components), matched)
	}

	if firstErr != nil {
		return nil, firstErr
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].VulnID != findings[j].VulnID {
			return findings[i].VulnID < findings[j].VulnID
		}
		if findings[i].PackagePURL != findings[j].PackagePURL {
			return findings[i].PackagePURL < findings[j].PackagePURL
		}
		return findings[i].InstalledVersion < findings[j].InstalledVersion
	})
	return findings, nil
}

func (e *Engine) emitProgress(processed, total, matched int) {
	if e.opts.Progress == nil {
		return
	}
	step := e.opts.ProgressEvery
	if step <= 0 {
		step = 250
	}
	if processed < total && processed%step != 0 {
		return
	}
	e.opts.Progress(Progress{
		Processed: processed,
		Total:     total,
		Matched:   matched,
	})
}

func (e *Engine) matchComponent(ctx context.Context, cache *runCache, component Component) ([]Finding, error) {
	coord, err := parseComponentPURL(component.PURL)
	if err != nil {
		return []Finding{}, nil
	}

	version := strings.TrimSpace(component.Version)
	if version == "" {
		version = coord.version
	}
	if strings.TrimSpace(version) == "" {
		return []Finding{}, nil
	}

	records, err := e.loadAffected(ctx, cache, coord.ecosystem, coord.name)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return []Finding{}, nil
	}

	out := make([]Finding, 0, len(records))
	seen := map[string]bool{}
	for _, record := range records {
		rangesByType, err := e.loadRanges(ctx, cache, record.affectedID)
		if err != nil {
			return nil, err
		}

		matched := false
		fixedVersion := ""
		for rangeType, events := range rangesByType {
			affected, fixed := isAffected(rangeType, version, events)
			if affected {
				matched = true
				if fixedVersion == "" && fixed != "" {
					fixedVersion = fixed
				}
			}
		}
		if !matched {
			continue
		}

		aliases, err := e.loadAliases(ctx, cache, record.vulnID)
		if err != nil {
			return nil, err
		}
		references, err := e.loadReferences(ctx, cache, record.vulnID)
		if err != nil {
			return nil, err
		}

		finding := Finding{
			VulnID:           record.vulnID,
			Aliases:          aliases,
			PackagePURL:      record.packagePURL,
			InstalledVersion: version,
			FixedVersion:     fixedVersion,
			Scope:            strings.ToLower(strings.TrimSpace(component.Scope)),
			Severity:         record.severity,
			References:       references,
		}
		key := strings.Join([]string{finding.VulnID, finding.PackagePURL, finding.InstalledVersion}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding)
	}
	return out, nil
}

func (e *Engine) loadAffected(ctx context.Context, cache *runCache, ecosystem, name string) ([]affectedRecord, error) {
	key := strings.Join([]string{ecosystem, name}, "|")
	if cache.enabled {
		if value, ok := cache.affected.Load(key); ok {
			if items, ok := value.([]affectedRecord); ok {
				return cloneAffected(items), nil
			}
		}
	}

	rows, err := e.queryAffected.QueryContext(ctx, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("query affected packages for %s/%s: %w", ecosystem, name, err)
	}
	defer rows.Close()

	records := make([]affectedRecord, 0)
	for rows.Next() {
		record := affectedRecord{}
		if err := rows.Scan(&record.affectedID, &record.vulnID, &record.packagePURL, &record.severity); err != nil {
			return nil, fmt.Errorf("scan affected package row: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate affected packages: %w", err)
	}

	if cache.enabled {
		cache.affected.Store(key, cloneAffected(records))
	}
	return records, nil
}

func (e *Engine) loadAliases(ctx context.Context, cache *runCache, vulnID string) ([]string, error) {
	if cache.enabled {
		if value, ok := cache.aliases.Load(vulnID); ok {
			if aliases, ok := value.([]string); ok {
				return append([]string{}, aliases...), nil
			}
		}
	}

	rows, err := e.queryAliases.QueryContext(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query aliases for %s: %w", vulnID, err)
	}
	defer rows.Close()

	aliases := []string{}
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate aliases: %w", err)
	}

	if cache.enabled {
		cache.aliases.Store(vulnID, append([]string{}, aliases...))
	}
	return aliases, nil
}

func (e *Engine) loadReferences(ctx context.Context, cache *runCache, vulnID string) ([]string, error) {
	if cache.enabled {
		if value, ok := cache.refs.Load(vulnID); ok {
			if refs, ok := value.([]string); ok {
				return append([]string{}, refs...), nil
			}
		}
	}

	rows, err := e.queryRefs.QueryContext(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query references for %s: %w", vulnID, err)
	}
	defer rows.Close()

	refs := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, fmt.Errorf("scan reference: %w", err)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate references: %w", err)
	}

	if cache.enabled {
		cache.refs.Store(vulnID, append([]string{}, refs...))
	}
	return refs, nil
}

func (e *Engine) loadRanges(ctx context.Context, cache *runCache, affectedID int64) (map[string][]rangeEvent, error) {
	key := strconv.FormatInt(affectedID, 10)
	if cache.enabled {
		if value, ok := cache.ranges.Load(key); ok {
			if rangesByType, ok := value.(map[string][]rangeEvent); ok {
				return cloneRanges(rangesByType), nil
			}
		}
	}

	rows, err := e.queryRanges.QueryContext(ctx, affectedID)
	if err != nil {
		return nil, fmt.Errorf("query ranges for affected_id=%d: %w", affectedID, err)
	}
	defer rows.Close()

	type grouped struct {
		rangeType string
		events    []rangeEvent
	}
	groups := map[int64]*grouped{}
	orderedIDs := []int64{}

	for rows.Next() {
		var rangeID int64
		var rangeType string
		var eventOrder sql.NullInt64
		var introduced sql.NullString
		var fixed sql.NullString
		var lastAffected sql.NullString
		var limit sql.NullString

		if err := rows.Scan(&rangeID, &rangeType, &eventOrder, &introduced, &fixed, &lastAffected, &limit); err != nil {
			return nil, fmt.Errorf("scan range row: %w", err)
		}

		group, exists := groups[rangeID]
		if !exists {
			group = &grouped{
				rangeType: strings.ToUpper(strings.TrimSpace(rangeType)),
				events:    []rangeEvent{},
			}
			groups[rangeID] = group
			orderedIDs = append(orderedIDs, rangeID)
		}

		if eventOrder.Valid {
			group.events = append(group.events, rangeEvent{
				introduced:   strings.TrimSpace(introduced.String),
				fixed:        strings.TrimSpace(fixed.String),
				lastAffected: strings.TrimSpace(lastAffected.String),
				limit:        strings.TrimSpace(limit.String),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ranges: %w", err)
	}

	out := map[string][]rangeEvent{}
	for _, id := range orderedIDs {
		group := groups[id]
		out[group.rangeType] = append(out[group.rangeType], group.events...)
	}

	if cache.enabled {
		cache.ranges.Store(key, cloneRanges(out))
	}
	return out, nil
}

func cloneAffected(items []affectedRecord) []affectedRecord {
	return append([]affectedRecord{}, items...)
}

func cloneRanges(input map[string][]rangeEvent) map[string][]rangeEvent {
	out := make(map[string][]rangeEvent, len(input))
	for key, events := range input {
		out[key] = append([]rangeEvent{}, events...)
	}
	return out
}

func defaultWorkerCount() int {
	n := runtime.NumCPU()
	if n < 1 {
		return 1
	}
	if n > 8 {
		return 8
	}
	return n
}
