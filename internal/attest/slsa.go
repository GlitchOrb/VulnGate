package attest

import "context"

type SLSAProvenanceProvider interface {
	GenerateBuildProvenance(ctx context.Context, req SLSABuildRequest) (SLSABuildProvenance, error)
}

type SLSABuildRequest struct {
	BuilderID    string
	BuildType    string
	InvocationID string
	SourceURI    string
	SourceDigest string
}

type SLSABuildProvenance struct {
	PredicateType string            `json:"predicateType"`
	BuilderID     string            `json:"builderID"`
	BuildType     string            `json:"buildType"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type HardwareAttestor interface {
	AttestBuild(ctx context.Context, req HardwareAttestationRequest) (HardwareAttestation, error)
}

type HardwareAttestationRequest struct {
	BuilderID string
	Artifact  string
}

type HardwareAttestation struct {
	Provider string `json:"provider"`
	Quote    string `json:"quote,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}
