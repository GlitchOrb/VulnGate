package store

import (
	"context"

	"github.com/GlitchOrb/vulngate/services/graph/model"
)

type GraphStore interface {
	UpsertService(ctx context.Context, name string) error
	UpsertArtifact(ctx context.Context, artifact model.Artifact) error
	LinkServiceArtifact(ctx context.Context, service string, artifactID string) error

	UpsertPackage(ctx context.Context, pkg model.Package) error
	LinkArtifactPackage(ctx context.Context, artifactID string, purl string) error
	LinkPackageDependency(ctx context.Context, fromPURL string, toPURL string) error

	UpsertVulnerability(ctx context.Context, vuln model.Vulnerability) error
	LinkPackageVulnerability(ctx context.Context, packagePURL string, vulnID string, source string) error
	RecordVEXStatement(ctx context.Context, statement model.VEXStatement) error

	UpsertAttestation(ctx context.Context, att model.Attestation) error
	LinkArtifactAttestation(ctx context.Context, artifactID string, attestationID string) error

	QueryServicesByVulnerability(ctx context.Context, vulnID string) (model.ServicesByVulnResult, error)
	QueryBlastRadius(ctx context.Context, packagePURL string) (model.BlastRadiusResult, error)
	QueryVulnerabilitiesByService(ctx context.Context, service string) (model.VulnsByServiceResult, error)

	Close() error
}
