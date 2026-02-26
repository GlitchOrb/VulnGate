package db

import "strings"

type osvEntry struct {
	ID               string              `json:"id"`
	Aliases          []string            `json:"aliases"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details"`
	Modified         string              `json:"modified"`
	Severity         []osvSeverity       `json:"severity"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
	References       []osvReference      `json:"references"`
	Affected         []osvAffected       `json:"affected"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Repo   string     `json:"repo"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

func normalizeEcosystem(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "npm":
		return "npm"
	case "pypi", "python":
		return "pypi"
	case "go", "golang":
		return "golang"
	default:
		return value
	}
}

func normalizePackageName(ecosystem, name string) string {
	n := strings.TrimSpace(name)
	switch normalizeEcosystem(ecosystem) {
	case "pypi":
		n = strings.ToLower(n)
		n = strings.ReplaceAll(n, "_", "-")
		n = strings.ReplaceAll(n, ".", "-")
		for strings.Contains(n, "--") {
			n = strings.ReplaceAll(n, "--", "-")
		}
	case "npm", "golang":
		n = strings.ToLower(n)
	}
	return n
}

func deriveSeverity(raw []osvSeverity, dbSeverity string) string {
	if len(raw) == 0 {
		return normalizeSeverityValue(dbSeverity)
	}
	for _, s := range raw {
		v := strings.TrimSpace(strings.ToLower(s.Score))
		switch v {
		case "critical", "high", "medium", "low":
			return v
		}
	}
	return normalizeSeverityValue(dbSeverity)
}

func normalizeSeverityValue(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "critical", "high", "medium", "low":
		return v
	case "moderate":
		return "medium"
	default:
		return "unknown"
	}
}
