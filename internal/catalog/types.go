package catalog

import "time"

type Ecosystem string

const (
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPython Ecosystem = "python"
	EcosystemGo     Ecosystem = "go"
)

type Scope string

const (
	ScopeRequired   Scope = "required"
	ScopeDev        Scope = "dev"
	ScopeTest       Scope = "test"
	ScopeTransitive Scope = "transitive"
	ScopeOptional   Scope = "optional"
	ScopeUnknown    Scope = "unknown"
)

type Component struct {
	PURL      string    `json:"purl"`
	Name      string    `json:"name"`
	Version   string    `json:"version,omitempty"`
	Scope     Scope     `json:"scope"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Locations []string  `json:"locations,omitempty"`
}

type Progress struct {
	Stage   string `json:"stage"`
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Message string `json:"message,omitempty"`
}

type ProgressFunc func(Progress)

type Summary struct {
	TotalComponents int            `json:"totalComponents"`
	ByEcosystem     map[string]int `json:"byEcosystem"`
	ByScope         map[string]int `json:"byScope"`
	FilesParsed     int            `json:"filesParsed"`
	FilesErrored    int            `json:"filesErrored"`
}

type CacheMetadata struct {
	Enabled bool   `json:"enabled"`
	Hit     bool   `json:"hit"`
	Key     string `json:"key,omitempty"`
	Path    string `json:"path,omitempty"`
}

type Report struct {
	Schema     string         `json:"schema"`
	TargetPath string         `json:"targetPath"`
	Generated  time.Time      `json:"generated"`
	Summary    Summary        `json:"summary"`
	Cache      *CacheMetadata `json:"cache,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Components []Component    `json:"components"`
}

type BuildOptions struct {
	TargetPath   string
	CacheDir     string
	DisableCache bool
	Progress     ProgressFunc
}
