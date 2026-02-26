package attest

import "time"

const BundleSchema = "vulngate-attestation-bundle-v1"

type ToolMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

type DatabaseMetadata struct {
	Path          string `json:"path,omitempty"`
	SchemaVersion int    `json:"schemaVersion,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

type SourceMetadata struct {
	RepoPath  string `json:"repoPath,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
	GitBranch string `json:"gitBranch,omitempty"`
}

type BuildEnvironment struct {
	GOOS       string            `json:"goos,omitempty"`
	GOARCH     string            `json:"goarch,omitempty"`
	GoVersion  string            `json:"goVersion,omitempty"`
	CI         bool              `json:"ci"`
	CIProvider string            `json:"ciProvider,omitempty"`
	Hints      map[string]string `json:"hints,omitempty"`
}

type Provenance struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Tool        ToolMetadata     `json:"tool"`
	Database    DatabaseMetadata `json:"database"`
	Source      SourceMetadata   `json:"source"`
	BuildEnv    BuildEnvironment `json:"buildEnv"`
}

type ArtifactInput struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	MediaType string `json:"mediaType,omitempty"`
	Path      string `json:"path,omitempty"`
	Content   []byte `json:"-"`
}

type SignatureMaterial struct {
	Signature   string `json:"signature,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Bundle      string `json:"bundle,omitempty"`
}

type ArtifactRecord struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	MediaType string            `json:"mediaType,omitempty"`
	Path      string            `json:"path,omitempty"`
	SHA256    string            `json:"sha256"`
	Size      int64             `json:"size"`
	Signed    bool              `json:"signed"`
	Signer    string            `json:"signer,omitempty"`
	Signature SignatureMaterial `json:"signature,omitempty"`
	SignError string            `json:"signError,omitempty"`
}

type Bundle struct {
	Schema      string           `json:"schema"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Provenance  Provenance       `json:"provenance"`
	Artifacts   []ArtifactRecord `json:"artifacts"`
}

type SignConfig struct {
	Mode          string
	CosignBinary  string
	KeyRef        string
	IdentityToken string
}

type BundleOptions struct {
	Provenance Provenance
	Artifacts  []ArtifactInput
	Signing    SignConfig
	Signer     Signer
	TempDir    string
}
