package ingest

import (
	"context"
	"fmt"

	"github.com/GlitchOrb/vulngate/services/graph/store"
)

type BundleIngestRequest struct {
	CycloneDX    *CycloneDXIngestRequest   `json:"cyclonedx,omitempty"`
	OpenVEX      *OpenVEXIngestRequest     `json:"openvex,omitempty"`
	Attestations *AttestationIngestRequest `json:"attestations,omitempty"`
}

func IngestBundle(ctx context.Context, graph store.GraphStore, req BundleIngestRequest) (IngestResult, error) {
	if graph == nil {
		return IngestResult{}, fmt.Errorf("graph store is nil")
	}

	result := IngestResult{}
	if req.CycloneDX != nil {
		r, err := IngestCycloneDX(ctx, graph, *req.CycloneDX)
		if err != nil {
			return result, err
		}
		result = result.add(r)
	}
	if req.OpenVEX != nil {
		r, err := IngestOpenVEX(ctx, graph, *req.OpenVEX)
		if err != nil {
			return result, err
		}
		result = result.add(r)
	}
	if req.Attestations != nil {
		r, err := IngestAttestations(ctx, graph, *req.Attestations)
		if err != nil {
			return result, err
		}
		result = result.add(r)
	}
	return result, nil
}

func (r IngestResult) add(other IngestResult) IngestResult {
	return IngestResult{
		Services:        r.Services + other.Services,
		Artifacts:       r.Artifacts + other.Artifacts,
		Packages:        r.Packages + other.Packages,
		Dependencies:    r.Dependencies + other.Dependencies,
		Vulnerabilities: r.Vulnerabilities + other.Vulnerabilities,
		Attestations:    r.Attestations + other.Attestations,
		VEXStatements:   r.VEXStatements + other.VEXStatements,
	}
}
