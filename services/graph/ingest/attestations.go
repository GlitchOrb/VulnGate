package ingest

import (
	"context"
	"fmt"
	"strings"

	"github.com/GlitchOrb/vulngate/services/graph/model"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

type AttestationIngestRequest struct {
	Service      string              `json:"service,omitempty"`
	Artifact     model.Artifact      `json:"artifact"`
	Attestations []model.Attestation `json:"attestations"`
}

func IngestAttestations(ctx context.Context, graph store.GraphStore, req AttestationIngestRequest) (IngestResult, error) {
	if graph == nil {
		return IngestResult{}, fmt.Errorf("graph store is nil")
	}

	service := strings.TrimSpace(req.Service)
	artifact := req.Artifact
	artifact.ID = strings.TrimSpace(artifact.ID)
	if artifact.ID == "" {
		return IngestResult{}, fmt.Errorf("artifact id is required for attestation ingest")
	}

	result := IngestResult{}
	if service != "" {
		if err := graph.UpsertService(ctx, service); err != nil {
			return result, err
		}
		result.Services++
	}
	if err := graph.UpsertArtifact(ctx, artifact); err != nil {
		return result, err
	}
	result.Artifacts++
	if service != "" {
		if err := graph.LinkServiceArtifact(ctx, service, artifact.ID); err != nil {
			return result, err
		}
	}

	for _, att := range req.Attestations {
		att.ID = strings.TrimSpace(att.ID)
		if att.ID == "" {
			continue
		}
		if err := graph.UpsertAttestation(ctx, att); err != nil {
			return result, err
		}
		if err := graph.LinkArtifactAttestation(ctx, artifact.ID, att.ID); err != nil {
			return result, err
		}
		result.Attestations++
	}

	return result, nil
}
