package sarif

type Location struct {
	Path   string
	Line   int
	Column int
}

type Finding struct {
	VulnID           string
	PackagePURL      string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Tier1Status      string
	Tier1Reason      string
	Tier2Status      string
	Tier2Reason      string
	Tier2Evidence    string
	RuntimeStatus    string
	RuntimeReason    string
	RuntimeSymbols   []string
	RuntimeCallCount uint64
	RuntimeFirstSeen string
	RuntimeLastSeen  string
	References       []string
	Locations        []Location
}

type Context struct {
	TargetPath    string
	RunProperties map[string]any
}

type Decision struct {
	Fail       bool
	Reason     string
	Violations int
}
