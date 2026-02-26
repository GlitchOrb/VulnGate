package ingest

import (
	"context"
	"fmt"
	"strings"

	"github.com/GlitchOrb/vulngate/services/graph/model"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

type CycloneDXIngestRequest struct {
	Service  string         `json:"service"`
	Artifact model.Artifact `json:"artifact"`
	SBOM     CycloneDXBOM   `json:"sbom"`
}

type CycloneDXBOM struct {
	BomFormat       string                   `json:"bomFormat,omitempty"`
	SpecVersion     string                   `json:"specVersion,omitempty"`
	SerialNumber    string                   `json:"serialNumber,omitempty"`
	Metadata        CycloneDXMetadata        `json:"metadata,omitempty"`
	Components      []CycloneDXComponent     `json:"components,omitempty"`
	Dependencies    []CycloneDXDependency    `json:"dependencies,omitempty"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities,omitempty"`
}

type CycloneDXMetadata struct {
	Component CycloneDXComponent `json:"component,omitempty"`
}

type CycloneDXComponent struct {
	BOMRef  string `json:"bom-ref,omitempty"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type CycloneDXVulnerability struct {
	ID      string                     `json:"id"`
	Ratings []CycloneDXVulnRating      `json:"ratings,omitempty"`
	Affects []CycloneDXVulnAffectedRef `json:"affects,omitempty"`
}

type CycloneDXVulnRating struct {
	Severity string `json:"severity,omitempty"`
}

type CycloneDXVulnAffectedRef struct {
	Ref string `json:"ref,omitempty"`
}

type IngestResult struct {
	Services        int `json:"services"`
	Artifacts       int `json:"artifacts"`
	Packages        int `json:"packages"`
	Dependencies    int `json:"dependencies"`
	Vulnerabilities int `json:"vulnerabilities"`
	Attestations    int `json:"attestations"`
	VEXStatements   int `json:"vexStatements"`
}

func IngestCycloneDX(ctx context.Context, graph store.GraphStore, req CycloneDXIngestRequest) (IngestResult, error) {
	if graph == nil {
		return IngestResult{}, fmt.Errorf("graph store is nil")
	}

	service := strings.TrimSpace(req.Service)
	if service == "" {
		service = "unknown-service"
	}

	artifact := req.Artifact
	artifact.ID = strings.TrimSpace(artifact.ID)
	if artifact.ID == "" {
		artifact.ID = firstNonEmpty(strings.TrimSpace(req.SBOM.SerialNumber), strings.TrimSpace(req.SBOM.Metadata.Component.BOMRef), "unknown-artifact")
	}
	if artifact.Name == "" {
		artifact.Name = firstNonEmpty(strings.TrimSpace(req.SBOM.Metadata.Component.Name), artifact.ID)
	}

	result := IngestResult{}

	if err := graph.UpsertService(ctx, service); err != nil {
		return result, err
	}
	result.Services++

	if err := graph.UpsertArtifact(ctx, artifact); err != nil {
		return result, err
	}
	if err := graph.LinkServiceArtifact(ctx, service, artifact.ID); err != nil {
		return result, err
	}
	result.Artifacts++

	refToPURL := map[string]string{}
	for _, component := range req.SBOM.Components {
		componentRef := strings.TrimSpace(component.BOMRef)
		componentPURL := strings.TrimSpace(component.PURL)
		if componentPURL == "" {
			componentPURL = fallbackPURL(component.Name, component.Version)
		}
		parts, err := parsePURL(componentPURL)
		if err != nil {
			continue
		}
		pkg := model.Package{
			PURL:      parts.PURL,
			Name:      strings.TrimSpace(component.Name),
			Version:   firstNonEmpty(strings.TrimSpace(component.Version), parts.Version),
			Ecosystem: parts.Ecosystem,
		}
		if pkg.Name == "" {
			pkg.Name = parts.Name
		}
		if err := graph.UpsertPackage(ctx, pkg); err != nil {
			return result, err
		}
		if err := graph.LinkArtifactPackage(ctx, artifact.ID, pkg.PURL); err != nil {
			return result, err
		}
		result.Packages++

		if componentRef != "" {
			refToPURL[componentRef] = pkg.PURL
		}
		refToPURL[pkg.PURL] = pkg.PURL
	}

	for _, dep := range req.SBOM.Dependencies {
		fromPURL := resolveRefToPURL(dep.Ref, refToPURL)
		if fromPURL == "" {
			continue
		}
		for _, toRef := range dep.DependsOn {
			toPURL := resolveRefToPURL(toRef, refToPURL)
			if toPURL == "" {
				continue
			}
			if err := graph.LinkPackageDependency(ctx, fromPURL, toPURL); err != nil {
				return result, err
			}
			result.Dependencies++
		}
	}

	for _, vuln := range req.SBOM.Vulnerabilities {
		vulnID := strings.TrimSpace(vuln.ID)
		if vulnID == "" {
			continue
		}
		severity := ""
		for _, rating := range vuln.Ratings {
			if strings.TrimSpace(rating.Severity) == "" {
				continue
			}
			severity = strings.ToLower(strings.TrimSpace(rating.Severity))
			break
		}
		if err := graph.UpsertVulnerability(ctx, model.Vulnerability{ID: vulnID, Severity: severity}); err != nil {
			return result, err
		}
		result.Vulnerabilities++

		for _, affected := range vuln.Affects {
			purl := resolveRefToPURL(affected.Ref, refToPURL)
			if purl == "" {
				continue
			}
			if err := graph.LinkPackageVulnerability(ctx, purl, vulnID, "cyclonedx"); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

func resolveRefToPURL(ref string, table map[string]string) string {
	cleanRef := strings.TrimSpace(ref)
	if cleanRef == "" {
		return ""
	}
	if resolved, ok := table[cleanRef]; ok {
		return resolved
	}
	if strings.HasPrefix(strings.ToLower(cleanRef), "pkg:") {
		if parts, err := parsePURL(cleanRef); err == nil {
			return parts.PURL
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
