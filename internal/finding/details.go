package finding

import (
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityUnknown  SeverityLevel = "unknown"
)

type Severity struct {
	Level     SeverityLevel `json:"level"`
	CVSSScore *float64      `json:"cvssScore,omitempty"`
}

type Affected struct {
	PURL             string `json:"purl"`
	Ecosystem        string `json:"ecosystem"`
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
}

type EvidenceLocation struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	LineStart int    `json:"lineStart,omitempty"`
	LineEnd   int    `json:"lineEnd,omitempty"`
	Note      string `json:"note,omitempty"`
}

type Reachability struct {
	Tier1       string `json:"tier1"`
	Tier2Static string `json:"tier2_static"`
	Tier2Runtime string `json:"tier2_runtime"`
	Rationale   string `json:"rationale,omitempty"`
}

type Evidence struct {
	Locations    []EvidenceLocation `json:"locations"`
	Reachability Reachability       `json:"reachability"`
}

type Remediation struct {
	UpgradeTo       string   `json:"upgradeTo,omitempty"`
	PatchedVersions []string `json:"patchedVersions,omitempty"`
	Guidance        string   `json:"guidance,omitempty"`
}

type FindingDetails struct {
	ID         string      `json:"id"`
	Aliases    []string    `json:"aliases,omitempty"`
	Title      string      `json:"title"`
	Summary    string      `json:"summary,omitempty"`
	Severity   Severity    `json:"severity"`
	Affected   Affected    `json:"affected"`
	Evidence   Evidence    `json:"evidence"`
	Remediation Remediation `json:"remediation"`
	References []string    `json:"references,omitempty"`
}

func NormalizeSeverity(raw string) SeverityLevel {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

func NormalizeReachability(raw string, value bool) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "true", "false", "unknown":
		return status
	}
	if value {
		return "true"
	}
	return "unknown"
}

func ClampSummary(raw string, maxLen int) string {
	value := strings.TrimSpace(raw)
	if value == "" || maxLen <= 0 {
		return value
	}
	if utf8.RuneCountInString(value) <= maxLen {
		return value
	}
	runes := []rune(value)
	return strings.TrimSpace(string(runes[:maxLen]))
}

func Normalize(d FindingDetails) FindingDetails {
	d.ID = strings.TrimSpace(d.ID)
	if d.ID == "" {
		d.ID = "UNKNOWN"
	}

	d.Aliases = uniqueSortedStrings(filterNot(d.Aliases, d.ID))
	d.Title = strings.TrimSpace(d.Title)
	if d.Title == "" {
		d.Title = d.ID
	}
	d.Summary = ClampSummary(d.Summary, 400)
	d.Severity.Level = NormalizeSeverity(string(d.Severity.Level))

	d.Affected.PURL = strings.TrimSpace(d.Affected.PURL)
	d.Affected.Ecosystem = strings.ToLower(strings.TrimSpace(d.Affected.Ecosystem))
	d.Affected.Name = strings.TrimSpace(d.Affected.Name)
	d.Affected.InstalledVersion = strings.TrimSpace(d.Affected.InstalledVersion)
	d.Affected.FixedVersion = strings.TrimSpace(d.Affected.FixedVersion)

	locs := make([]EvidenceLocation, 0, len(d.Evidence.Locations))
	for _, loc := range d.Evidence.Locations {
		path := filepath.ToSlash(strings.TrimSpace(loc.Path))
		if path == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(loc.Kind))
		if kind == "" {
			kind = DetectLocationKind(path)
		}
		lineStart := loc.LineStart
		lineEnd := loc.LineEnd
		if lineStart < 0 {
			lineStart = 0
		}
		if lineEnd < 0 {
			lineEnd = 0
		}
		if lineEnd > 0 && lineStart == 0 {
			lineStart = lineEnd
		}
		if lineEnd > 0 && lineStart > lineEnd {
			lineEnd = lineStart
		}
		locs = append(locs, EvidenceLocation{
			Kind:      kind,
			Path:      path,
			LineStart: lineStart,
			LineEnd:   lineEnd,
			Note:      strings.TrimSpace(loc.Note),
		})
	}
	d.Evidence.Locations = uniqueSortedLocations(locs)

	d.Evidence.Reachability = Reachability{
		Tier1:        NormalizeReachability(d.Evidence.Reachability.Tier1, false),
		Tier2Static:  NormalizeReachability(d.Evidence.Reachability.Tier2Static, false),
		Tier2Runtime: NormalizeReachability(d.Evidence.Reachability.Tier2Runtime, false),
		Rationale:    strings.TrimSpace(d.Evidence.Reachability.Rationale),
	}

	d.Remediation.UpgradeTo = strings.TrimSpace(d.Remediation.UpgradeTo)
	d.Remediation.PatchedVersions = uniqueSortedStrings(d.Remediation.PatchedVersions)
	d.Remediation.Guidance = strings.TrimSpace(d.Remediation.Guidance)
	d.References = sanitizeReferences(d.References)

	return d
}

func DetectLocationKind(path string) string {
	p := strings.ToLower(filepath.Base(filepath.ToSlash(strings.TrimSpace(path))))
	switch p {
	case "package-lock.json", "pnpm-lock.yaml", "poetry.lock", "requirements.txt", "go.mod", "go.sum":
		return "lockfile"
	case "bom.json", "sbom.json", "cyclonedx.json", "spdx.json":
		return "sbom"
	}
	if strings.Contains(strings.ToLower(path), "layer") || strings.Contains(strings.ToLower(path), "sha256:") {
		return "image"
	}
	return "source"
}

func DefaultLockfilePath(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "package-lock.json"
	case "pypi", "python":
		return "requirements.txt"
	case "golang", "go":
		return "go.sum"
	default:
		return "sbom.json"
	}
}

func uniqueSortedLocations(items []EvidenceLocation) []EvidenceLocation {
	set := map[string]EvidenceLocation{}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(item.Kind)),
			filepath.ToSlash(strings.TrimSpace(item.Path)),
			intToString(item.LineStart),
			intToString(item.LineEnd),
			strings.TrimSpace(item.Note),
		}, "|")
		if _, ok := set[key]; !ok {
			keys = append(keys, key)
		}
		set[key] = item
	}
	sort.Strings(keys)
	out := make([]EvidenceLocation, 0, len(keys))
	for _, key := range keys {
		out = append(out, set[key])
	}
	return out
}

func sanitizeReferences(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		value := strings.TrimSpace(ref)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err == nil && parsed.Scheme != "" && parsed.Host != "" {
			parsed.User = nil
			parsed.RawQuery = ""
			parsed.Fragment = ""
			value = parsed.String()
		}
		out = append(out, value)
	}
	return uniqueSortedStrings(out)
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

func filterNot(items []string, reject string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(reject)) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func intToString(v int) string {
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return sign + string(buf[i:])
}
