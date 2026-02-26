package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var packageManagerFiles = map[string]bool{
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"requirements.txt":  true,
	"poetry.lock":       true,
	"go.mod":            true,
	"go.sum":            true,
}

type Renderer struct {
	toolName    string
	toolVersion string
}

func New(toolName, toolVersion string) *Renderer {
	name := strings.TrimSpace(toolName)
	if name == "" {
		name = "VulnGate"
	}
	version := strings.TrimSpace(toolVersion)
	if version == "" {
		version = "dev"
	}
	return &Renderer{toolName: name, toolVersion: version}
}

func (r *Renderer) Render(ctx Context, findings []Finding, decision Decision) ([]byte, error) {
	normalized := normalizeAndDeduplicate(findings)

	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(normalized))

	for _, finding := range normalized {
		if finding.vulnID == "" {
			continue
		}

		rulesByID[finding.vulnID] = sarifRule{
			ID:               finding.vulnID,
			Name:             finding.vulnID,
			ShortDescription: sarifMessage{Text: "Open-source vulnerability"},
			Properties: map[string]string{
				"severity": finding.severity,
			},
		}

		locations := make([]sarifLocation, 0, len(finding.locations))
		for _, loc := range finding.locations {
			artifactURI := loc.Path
			if strings.TrimSpace(artifactURI) == "" {
				artifactURI = ctx.TargetPath
			}

			pl := sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: toSlash(artifactURI)},
			}
			if loc.Line > 0 {
				pl.Region = &sarifRegion{StartLine: loc.Line}
				if loc.Column > 0 {
					pl.Region.StartColumn = loc.Column
				}
			}
			locations = append(locations, sarifLocation{PhysicalLocation: pl})
		}
		if len(locations) == 0 {
			locations = append(locations, sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: toSlash(ctx.TargetPath)},
				},
			})
		}

		stablePath := nearestStablePath(finding.locations, ctx.TargetPath)
		pmLocation := packageManagerLocation(finding.locations)
		contextHash := hashHex(strings.Join([]string{finding.vulnID, finding.packagePURL, stablePath, pmLocation}, "|"))

		results = append(results, sarifResult{
			RuleID:    finding.vulnID,
			Level:     severityToLevel(finding.severity),
			Message:   sarifMessage{Text: findingMessage(finding)},
			Locations: locations,
			PartialFingerprints: map[string]string{
				"contextHash":     contextHash,
				"vulnPurlVersion": hashHex(strings.Join([]string{finding.vulnID, finding.packagePURL, finding.installedVersion}, "|")),
			},
			Properties: map[string]any{
				"packagePURL":       finding.packagePURL,
				"installedVersion":  finding.installedVersion,
				"fixedVersion":      finding.fixedVersion,
				"tier1Reachable":    finding.tier1Status,
				"tier1Reason":       finding.tier1Reason,
				"tier2Reachable":    finding.tier2Status,
				"tier2Reason":       finding.tier2Reason,
				"tier2Evidence":     finding.tier2Evidence,
				"runtimeReachable":  finding.runtimeStatus,
				"reachable_runtime": finding.runtimeStatus == "true",
				"runtimeReason":     finding.runtimeReason,
				"runtimeCallCount":  finding.runtimeCallCount,
				"runtimeSymbols":    finding.runtimeSymbols,
				"runtimeFirstSeen":  finding.runtimeFirstSeen,
				"runtimeLastSeen":   finding.runtimeLastSeen,
				"references":        finding.references,
				"stablePath":        stablePath,
				"packageManager":    pmLocation,
			},
		})
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		li := results[i].PartialFingerprints["vulnPurlVersion"]
		lj := results[j].PartialFingerprints["vulnPurlVersion"]
		return li < lj
	})

	log := sarifLogFile{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.toolName,
				Version:        r.toolVersion,
				InformationURI: "https://github.com/GlitchOrb/vulngate",
				Rules:          rules,
			}},
			Properties: copyMap(ctx.RunProperties),
			Results:    results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: !decision.Fail,
				Properties: map[string]any{
					"policy": map[string]any{
						"fail":       decision.Fail,
						"reason":     decision.Reason,
						"violations": decision.Violations,
					},
				},
			}},
		}},
	}

	payload, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sarif: %w", err)
	}
	return append(payload, '\n'), nil
}

type normalizedFinding struct {
	vulnID           string
	packagePURL      string
	installedVersion string
	fixedVersion     string
	severity         string
	tier1Status      string
	tier1Reason      string
	tier2Status      string
	tier2Reason      string
	tier2Evidence    string
	runtimeStatus    string
	runtimeReason    string
	runtimeSymbols   []string
	runtimeCallCount uint64
	runtimeFirstSeen string
	runtimeLastSeen  string
	references       []string
	locations        []Location
}

func normalizeAndDeduplicate(findings []Finding) []normalizedFinding {
	groups := map[string]*normalizedFinding{}
	order := []string{}

	for _, finding := range findings {
		vulnID := strings.TrimSpace(finding.VulnID)
		purl := strings.TrimSpace(finding.PackagePURL)
		version := strings.TrimSpace(finding.InstalledVersion)
		if vulnID == "" || purl == "" {
			continue
		}
		key := strings.Join([]string{vulnID, purl, version}, "|")

		entry, exists := groups[key]
		if !exists {
			entry = &normalizedFinding{
				vulnID:           vulnID,
				packagePURL:      purl,
				installedVersion: version,
				fixedVersion:     strings.TrimSpace(finding.FixedVersion),
				severity:         normalizeSeverity(finding.Severity),
				tier1Status:      normalizeTier1Status(finding.Tier1Status),
				tier1Reason:      strings.TrimSpace(finding.Tier1Reason),
				tier2Status:      normalizeTier1Status(finding.Tier2Status),
				tier2Reason:      strings.TrimSpace(finding.Tier2Reason),
				tier2Evidence:    strings.TrimSpace(finding.Tier2Evidence),
				runtimeStatus:    normalizeTier1Status(finding.RuntimeStatus),
				runtimeReason:    strings.TrimSpace(finding.RuntimeReason),
				runtimeSymbols:   uniqueSortedStrings(finding.RuntimeSymbols),
				runtimeCallCount: finding.RuntimeCallCount,
				runtimeFirstSeen: strings.TrimSpace(finding.RuntimeFirstSeen),
				runtimeLastSeen:  strings.TrimSpace(finding.RuntimeLastSeen),
				references:       uniqueSortedStrings(finding.References),
				locations:        uniqueSortedLocations(finding.Locations),
			}
			groups[key] = entry
			order = append(order, key)
			continue
		}

		entry.severity = maxSeverity(entry.severity, normalizeSeverity(finding.Severity))
		entry.tier1Status = mergeTier1Status(entry.tier1Status, normalizeTier1Status(finding.Tier1Status))
		entry.tier1Reason = mergeReasons(entry.tier1Reason, strings.TrimSpace(finding.Tier1Reason))
		entry.tier2Status = mergeTier1Status(entry.tier2Status, normalizeTier1Status(finding.Tier2Status))
		entry.tier2Reason = mergeReasons(entry.tier2Reason, strings.TrimSpace(finding.Tier2Reason))
		entry.tier2Evidence = mergeReasons(entry.tier2Evidence, strings.TrimSpace(finding.Tier2Evidence))
		entry.runtimeStatus = mergeTier1Status(entry.runtimeStatus, normalizeTier1Status(finding.RuntimeStatus))
		entry.runtimeReason = mergeReasons(entry.runtimeReason, strings.TrimSpace(finding.RuntimeReason))
		entry.runtimeSymbols = uniqueSortedStrings(append(entry.runtimeSymbols, finding.RuntimeSymbols...))
		entry.runtimeCallCount = maxUint64(entry.runtimeCallCount, finding.RuntimeCallCount)
		entry.runtimeFirstSeen = earlierTimestamp(entry.runtimeFirstSeen, strings.TrimSpace(finding.RuntimeFirstSeen))
		entry.runtimeLastSeen = laterTimestamp(entry.runtimeLastSeen, strings.TrimSpace(finding.RuntimeLastSeen))
		if entry.fixedVersion == "" {
			entry.fixedVersion = strings.TrimSpace(finding.FixedVersion)
		}
		entry.references = uniqueSortedStrings(append(entry.references, finding.References...))
		entry.locations = uniqueSortedLocations(append(entry.locations, finding.Locations...))
	}

	sort.Strings(order)
	out := make([]normalizedFinding, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	return out
}

func uniqueSortedStrings(items []string) []string {
	set := map[string]bool{}
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		set[value] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedLocations(items []Location) []Location {
	set := map[string]Location{}
	for _, item := range items {
		key := strings.Join([]string{toSlash(strings.TrimSpace(item.Path)), fmt.Sprintf("%d", item.Line), fmt.Sprintf("%d", item.Column)}, ":")
		set[key] = Location{Path: toSlash(strings.TrimSpace(item.Path)), Line: item.Line, Column: item.Column}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Location, 0, len(keys))
	for _, key := range keys {
		out = append(out, set[key])
	}
	return out
}

func normalizeSeverity(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "low"
	}
}

func maxSeverity(a, b string) string {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if order[b] > order[a] {
		return b
	}
	return a
}

func normalizeTier1Status(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "false", "unknown":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "unknown"
	}
}

func mergeTier1Status(a, b string) string {
	if a == "true" || b == "true" {
		return "true"
	}
	if a == "false" || b == "false" {
		return "false"
	}
	if a == "unknown" || b == "unknown" {
		return "unknown"
	}
	return "unknown"
}

func mergeReasons(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch {
	case a == "" && b == "":
		return ""
	case a == "":
		return b
	case b == "":
		return a
	case a == b:
		return a
	default:
		return a + "; " + b
	}
}

func severityToLevel(severity string) string {
	s := normalizeSeverity(severity)
	switch s {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func findingMessage(f normalizedFinding) string {
	if strings.TrimSpace(f.installedVersion) == "" {
		return fmt.Sprintf("%s affects %s", f.vulnID, f.packagePURL)
	}
	if purlHasVersion(f.packagePURL, f.installedVersion) {
		return fmt.Sprintf("%s affects %s", f.vulnID, f.packagePURL)
	}
	return fmt.Sprintf("%s affects %s@%s", f.vulnID, f.packagePURL, f.installedVersion)
}

func purlHasVersion(rawPURL, version string) bool {
	purl := strings.TrimSpace(rawPURL)
	want := strings.TrimSpace(version)
	if purl == "" || want == "" {
		return false
	}

	body := purl
	if idx := strings.Index(body, "#"); idx >= 0 {
		body = body[:idx]
	}
	if idx := strings.Index(body, "?"); idx >= 0 {
		body = body[:idx]
	}

	at := strings.LastIndex(body, "@")
	if at < 0 {
		return false
	}
	return strings.TrimSpace(body[at+1:]) == want
}

func nearestStablePath(locations []Location, fallback string) string {
	if len(locations) == 0 {
		return toSlash(strings.TrimSpace(fallback))
	}

	manager := packageManagerLocation(locations)
	if manager != "" {
		dir := filepath.Dir(manager)
		if dir == "." {
			return ""
		}
		return toSlash(dir)
	}

	candidates := make([]string, 0, len(locations))
	for _, loc := range locations {
		path := strings.TrimSpace(loc.Path)
		if path == "" {
			continue
		}
		dir := filepath.Dir(path)
		if dir == "." {
			dir = path
		}
		candidates = append(candidates, toSlash(dir))
	}
	if len(candidates) == 0 {
		return toSlash(strings.TrimSpace(fallback))
	}
	sort.Slice(candidates, func(i, j int) bool {
		si := strings.Count(candidates[i], "/")
		sj := strings.Count(candidates[j], "/")
		if si != sj {
			return si < sj
		}
		return candidates[i] < candidates[j]
	})
	return candidates[0]
}

func packageManagerLocation(locations []Location) string {
	candidates := []string{}
	for _, loc := range locations {
		path := toSlash(strings.TrimSpace(loc.Path))
		if path == "" {
			continue
		}
		if packageManagerFiles[strings.ToLower(filepath.Base(path))] {
			candidates = append(candidates, path)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func toSlash(path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(path)
}

func hashHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func earlierTimestamp(a, b string) string {
	aa := strings.TrimSpace(a)
	bb := strings.TrimSpace(b)
	switch {
	case aa == "":
		return bb
	case bb == "":
		return aa
	}

	at, errA := time.Parse(time.RFC3339Nano, aa)
	bt, errB := time.Parse(time.RFC3339Nano, bb)
	if errA != nil || errB != nil {
		if aa <= bb {
			return aa
		}
		return bb
	}
	if bt.Before(at) {
		return bb
	}
	return aa
}

func laterTimestamp(a, b string) string {
	aa := strings.TrimSpace(a)
	bb := strings.TrimSpace(b)
	switch {
	case aa == "":
		return bb
	case bb == "":
		return aa
	}

	at, errA := time.Parse(time.RFC3339Nano, aa)
	bt, errB := time.Parse(time.RFC3339Nano, bb)
	if errA != nil || errB != nil {
		if aa >= bb {
			return aa
		}
		return bb
	}
	if bt.After(at) {
		return bb
	}
	return aa
}

type sarifLogFile struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Properties  map[string]any    `json:"properties,omitempty"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Properties          map[string]any `json:"properties,omitempty"`
}

func copyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
