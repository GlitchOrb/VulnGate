package match

type Component struct {
	PURL    string
	Version string
	Scope   string
}

type Finding struct {
	VulnID           string
	Aliases          []string
	PackagePURL      string
	InstalledVersion string
	FixedVersion     string
	Scope            string
	Severity         string
	References       []string
}

type Progress struct {
	Processed int
	Total     int
	Matched   int
}

type ProgressFunc func(Progress)

type EngineOptions struct {
	WorkerCount   int
	EnableCache   bool
	ProgressEvery int
	Progress      ProgressFunc
}
