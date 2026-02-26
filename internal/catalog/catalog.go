package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const schemaVersion = "vulngate-internal-sbom-v1"
const cacheSchemaVersion = "catalog-cache-v1"

func Build(ctx context.Context, opts BuildOptions) (Report, error) {
	target := strings.TrimSpace(opts.TargetPath)
	if target == "" {
		target = "."
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return Report{}, fmt.Errorf("resolve target path: %w", err)
	}

	if _, err := os.Stat(absTarget); err != nil {
		return Report{}, fmt.Errorf("target path is not accessible: %w", err)
	}

	emitProgress(opts.Progress, Progress{
		Stage:   "discover",
		Current: 0,
		Total:   1,
		Message: "discovering lockfiles and manifests",
	})

	finder := newFileFinder(absTarget)
	if err := finder.walk(ctx); err != nil {
		return Report{}, err
	}

	lockfiles := finder.lockfiles()
	emitProgress(opts.Progress, Progress{
		Stage:   "discover",
		Current: 1,
		Total:   1,
		Message: fmt.Sprintf("discovered %d candidate file(s)", len(lockfiles)),
	})

	cacheEnabled := strings.TrimSpace(opts.CacheDir) != "" && !opts.DisableCache
	cacheMeta := &CacheMetadata{
		Enabled: cacheEnabled,
		Hit:     false,
	}
	cachePath := ""
	cacheKey := ""
	if cacheEnabled {
		key, err := computeLockfileHash(absTarget, lockfiles)
		if err == nil && strings.TrimSpace(key) != "" {
			cacheKey = key
			cachePath = filepath.Join(opts.CacheDir, "catalog-"+cacheKey+".json")
			cacheMeta.Key = cacheKey
			cacheMeta.Path = filepath.ToSlash(cachePath)
			if cached, hit := loadCache(cachePath, absTarget); hit {
				emitProgress(opts.Progress, Progress{
					Stage:   "cache",
					Current: 1,
					Total:   1,
					Message: "catalog cache hit",
				})
				cached.Cache = cacheMeta
				cached.Cache.Hit = true
				cached.Generated = time.Now().UTC()
				return cached, nil
			}
			emitProgress(opts.Progress, Progress{
				Stage:   "cache",
				Current: 1,
				Total:   1,
				Message: "catalog cache miss",
			})
		}
	}

	builder := newBuilder(absTarget, opts.Progress, len(lockfiles))
	builder.parseNPM(finder.packageLockFiles)
	builder.parsePNPM(finder.pnpmLockFiles)
	builder.parsePoetry(finder.poetryLockFiles)
	builder.parseRequirements(finder.requirementsFiles)
	builder.parseGoModules(finder.goModFiles)
	builder.parseGoSums(finder.goSumFiles)

	report := Report{
		Schema:     schemaVersion,
		TargetPath: absTarget,
		Generated:  time.Now().UTC(),
		Cache:      cacheMeta,
		Warnings:   builder.warnings,
		Components: builder.componentsSorted(),
	}
	report.Summary = summarize(report.Components, builder.filesParsed, builder.filesErrored)
	if !cacheEnabled {
		report.Cache = nil
	}

	if cacheEnabled && cachePath != "" {
		_ = writeCache(cachePath, report)
	}

	emitProgress(opts.Progress, Progress{
		Stage:   "complete",
		Current: 1,
		Total:   1,
		Message: fmt.Sprintf("catalog complete components=%d parsed=%d errored=%d", report.Summary.TotalComponents, report.Summary.FilesParsed, report.Summary.FilesErrored),
	})
	return report, nil
}

func summarize(components []Component, filesParsed, filesErrored int) Summary {
	byEcosystem := map[string]int{}
	byScope := map[string]int{}
	for _, c := range components {
		byEcosystem[string(c.Ecosystem)]++
		byScope[string(c.Scope)]++
	}

	return Summary{
		TotalComponents: len(components),
		ByEcosystem:     byEcosystem,
		ByScope:         byScope,
		FilesParsed:     filesParsed,
		FilesErrored:    filesErrored,
	}
}

type fileFinder struct {
	root              string
	packageLockFiles  []string
	pnpmLockFiles     []string
	poetryLockFiles   []string
	requirementsFiles []string
	goModFiles        []string
	goSumFiles        []string
}

func newFileFinder(root string) *fileFinder {
	return &fileFinder{root: root}
}

func (f *fileFinder) walk(ctx context.Context) error {
	return filepath.WalkDir(f.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".hg", ".svn":
				return filepath.SkipDir
			}
			return nil
		}

		switch d.Name() {
		case "package-lock.json":
			f.packageLockFiles = append(f.packageLockFiles, path)
		case "pnpm-lock.yaml":
			f.pnpmLockFiles = append(f.pnpmLockFiles, path)
		case "poetry.lock":
			f.poetryLockFiles = append(f.poetryLockFiles, path)
		case "requirements.txt":
			f.requirementsFiles = append(f.requirementsFiles, path)
		case "go.mod":
			f.goModFiles = append(f.goModFiles, path)
		case "go.sum":
			f.goSumFiles = append(f.goSumFiles, path)
		}
		return nil
	})
}

func (f *fileFinder) lockfiles() []string {
	set := map[string]bool{}
	for _, paths := range [][]string{
		f.packageLockFiles,
		f.pnpmLockFiles,
		f.poetryLockFiles,
		f.requirementsFiles,
		f.goModFiles,
		f.goSumFiles,
	} {
		for _, path := range paths {
			set[path] = true
		}
	}
	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

type builder struct {
	targetRoot string
	warnings   []string

	filesParsed  int
	filesErrored int

	componentsByKey map[string]Component
	goDirectByDir   map[string]map[string]Scope
	progress        ProgressFunc
	progressTotal   int
	progressCurrent int
}

func newBuilder(targetRoot string, progress ProgressFunc, progressTotal int) *builder {
	return &builder{
		targetRoot:      targetRoot,
		warnings:        []string{},
		componentsByKey: map[string]Component{},
		goDirectByDir:   map[string]map[string]Scope{},
		progress:        progress,
		progressTotal:   progressTotal,
	}
}

func (b *builder) addWarning(path string, err error) {
	b.filesErrored++
	b.warnings = append(b.warnings, fmt.Sprintf("%s: %v", relPath(b.targetRoot, path), err))
}

func (b *builder) addComponents(path string, parsed []Component) {
	for _, component := range parsed {
		if component.PURL == "" || component.Name == "" {
			continue
		}
		component.Locations = append([]string{}, component.Locations...)
		if len(component.Locations) == 0 {
			component.Locations = []string{relPath(b.targetRoot, path)}
		} else {
			for i := range component.Locations {
				component.Locations[i] = relPath(b.targetRoot, component.Locations[i])
			}
		}

		key := strings.Join([]string{component.PURL, string(component.Scope), string(component.Ecosystem)}, "|")
		if existing, ok := b.componentsByKey[key]; ok {
			existing.Locations = mergeLocations(existing.Locations, component.Locations)
			b.componentsByKey[key] = existing
			continue
		}
		component.Locations = mergeLocations(nil, component.Locations)
		b.componentsByKey[key] = component
	}
}

func (b *builder) componentsSorted() []Component {
	out := make([]Component, 0, len(b.componentsByKey))
	for _, c := range b.componentsByKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].PURL < out[j].PURL
	})
	return out
}

func (b *builder) parseNPM(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		components, err := parsePackageLock(path)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
	}
}

func (b *builder) parsePNPM(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		components, err := parsePNPMLock(path)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
	}
}

func (b *builder) parsePoetry(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		components, err := parsePoetryLock(path)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
	}
}

func (b *builder) parseRequirements(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		components, err := parseRequirements(path)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
	}
}

func (b *builder) parseGoModules(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		components, direct, err := parseGoMod(path)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
		b.goDirectByDir[filepath.Dir(path)] = direct
	}
}

func (b *builder) parseGoSums(paths []string) {
	sort.Strings(paths)
	for _, path := range paths {
		b.advanceProgress(path)
		direct := b.goDirectByDir[filepath.Dir(path)]
		components, err := parseGoSum(path, direct)
		if err != nil {
			b.addWarning(path, err)
			continue
		}
		b.filesParsed++
		b.addComponents(path, components)
	}
}

func (b *builder) advanceProgress(path string) {
	if b.progress == nil {
		return
	}
	b.progressCurrent++
	total := b.progressTotal
	if total <= 0 {
		total = b.progressCurrent
	}
	b.progress(Progress{
		Stage:   "parse",
		Current: b.progressCurrent,
		Total:   total,
		Message: relPath(b.targetRoot, path),
	})
}

func emitProgress(progress ProgressFunc, event Progress) {
	if progress == nil {
		return
	}
	progress(event)
}

func computeLockfileHash(root string, lockfiles []string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(cacheSchemaVersion))
	hasher.Write([]byte{0})
	hasher.Write([]byte(schemaVersion))
	hasher.Write([]byte{0})

	sorted := append([]string{}, lockfiles...)
	sort.Strings(sorted)

	for _, path := range sorted {
		rel := relPath(root, path)
		hasher.Write([]byte(rel))
		hasher.Write([]byte{0})
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read lockfile %s: %w", rel, err)
		}
		sum := sha256.Sum256(raw)
		hasher.Write(sum[:])
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func loadCache(path string, targetPath string) (Report, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Report{}, false
	}
	var cached Report
	if err := json.Unmarshal(raw, &cached); err != nil {
		return Report{}, false
	}
	if cached.Schema != schemaVersion {
		return Report{}, false
	}
	cached.TargetPath = targetPath
	return cached, true
}

func writeCache(path string, report Report) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func mergeLocations(existing, incoming []string) []string {
	set := map[string]bool{}
	for _, item := range existing {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[item] = true
	}
	for _, item := range incoming {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[item] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func relPath(root, path string) string {
	if root == "" || path == "" {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	if rel == "." {
		return rel
	}
	return filepath.ToSlash(rel)
}
