package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/services/graph/model"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

type OpenVEXIngestRequest struct {
	Service    string          `json:"service,omitempty"`
	ArtifactID string          `json:"artifactID,omitempty"`
	Document   OpenVEXDocument `json:"document"`
}

type OpenVEXDocument struct {
	Context    string             `json:"@context,omitempty"`
	ID         string             `json:"@id,omitempty"`
	Author     string             `json:"author,omitempty"`
	Timestamp  string             `json:"timestamp,omitempty"`
	Version    int                `json:"version,omitempty"`
	Statements []OpenVEXStatement `json:"statements,omitempty"`
}

type OpenVEXStatement struct {
	ID            string           `json:"id,omitempty"`
	Vulnerability OpenVEXVulnRef   `json:"vulnerability"`
	Products      []OpenVEXProduct `json:"products,omitempty"`
	Status        string           `json:"status"`
	Justification string           `json:"justification,omitempty"`
}

type OpenVEXVulnRef struct {
	Name string `json:"name"`
}

type OpenVEXProduct struct {
	ID string `json:"@id"`
}

func (p *OpenVEXProduct) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "\"") {
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		p.ID = strings.TrimSpace(raw)
		return nil
	}

	type alias OpenVEXProduct
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.ID = strings.TrimSpace(a.ID)
	return nil
}

func IngestOpenVEX(ctx context.Context, graph store.GraphStore, req OpenVEXIngestRequest) (IngestResult, error) {
	if graph == nil {
		return IngestResult{}, fmt.Errorf("graph store is nil")
	}

	result := IngestResult{}
	service := strings.TrimSpace(req.Service)
	artifactID := strings.TrimSpace(req.ArtifactID)

	if service != "" {
		if err := graph.UpsertService(ctx, service); err != nil {
			return result, err
		}
		result.Services++
	}
	if artifactID != "" {
		if err := graph.UpsertArtifact(ctx, model.Artifact{ID: artifactID}); err != nil {
			return result, err
		}
		result.Artifacts++
		if service != "" {
			if err := graph.LinkServiceArtifact(ctx, service, artifactID); err != nil {
				return result, err
			}
		}
	}

	ts := time.Time{}
	if strings.TrimSpace(req.Document.Timestamp) != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.Document.Timestamp)); err == nil {
			ts = parsed.UTC()
		}
	}

	for i, statement := range req.Document.Statements {
		vulnID := strings.TrimSpace(statement.Vulnerability.Name)
		if vulnID == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(statement.Status))
		if status == "" {
			status = "under_investigation"
		}
		for _, product := range statement.Products {
			packagePURL := strings.TrimSpace(product.ID)
			if packagePURL == "" {
				continue
			}
			parts, err := parsePURL(packagePURL)
			if err != nil {
				continue
			}

			pkg := model.Package{PURL: parts.PURL, Name: parts.Name, Version: parts.Version, Ecosystem: parts.Ecosystem}
			if err := graph.UpsertPackage(ctx, pkg); err != nil {
				return result, err
			}
			result.Packages++

			if artifactID != "" {
				if err := graph.LinkArtifactPackage(ctx, artifactID, parts.PURL); err != nil {
					return result, err
				}
			}

			statementID := strings.TrimSpace(statement.ID)
			if statementID == "" {
				statementID = fmt.Sprintf("%s-%d-%s", strings.TrimSpace(req.Document.ID), i, parts.PURL)
			}
			if err := graph.RecordVEXStatement(ctx, model.VEXStatement{
				ID:            statementID,
				VulnID:        vulnID,
				PackagePURL:   parts.PURL,
				Status:        status,
				Justification: strings.TrimSpace(statement.Justification),
				ArtifactID:    artifactID,
				Timestamp:     ts,
			}); err != nil {
				return result, err
			}
			result.VEXStatements++

			if status == "affected" {
				if err := graph.UpsertVulnerability(ctx, model.Vulnerability{ID: vulnID}); err != nil {
					return result, err
				}
				if err := graph.LinkPackageVulnerability(ctx, parts.PURL, vulnID, "openvex"); err != nil {
					return result, err
				}
				result.Vulnerabilities++
			}
		}
	}

	return result, nil
}
