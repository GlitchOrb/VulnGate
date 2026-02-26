package export

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/catalog"
	"github.com/GlitchOrb/vulngate/services/graph/ingest"
	"github.com/GlitchOrb/vulngate/services/graph/model"
)

type CycloneDXExportRequest struct {
	Service      string         `json:"service"`
	Artifact     model.Artifact `json:"artifact"`
	InternalSBOM catalog.Report `json:"internalSBOM"`
}

func ToCycloneDX(req CycloneDXExportRequest) (ingest.CycloneDXIngestRequest, error) {
	artifact := req.Artifact
	if strings.TrimSpace(artifact.ID) == "" {
		artifact.ID = firstNonEmpty(strings.TrimSpace(req.InternalSBOM.TargetPath), "unknown-artifact")
	}
	if strings.TrimSpace(artifact.Name) == "" {
		artifact.Name = artifact.ID
	}

	components := make([]ingest.CycloneDXComponent, 0, len(req.InternalSBOM.Components))
	for _, c := range req.InternalSBOM.Components {
		purl := strings.TrimSpace(c.PURL)
		if purl == "" {
			purl = fallbackPURL(c.Name, c.Version)
		}
		components = append(components, ingest.CycloneDXComponent{
			BOMRef:  purl,
			Type:    "library",
			Name:    strings.TrimSpace(c.Name),
			Version: strings.TrimSpace(c.Version),
			PURL:    purl,
		})
	}

	return ingest.CycloneDXIngestRequest{
		Service: strings.TrimSpace(req.Service),
		Artifact: model.Artifact{
			ID:     strings.TrimSpace(artifact.ID),
			Name:   strings.TrimSpace(artifact.Name),
			Type:   strings.TrimSpace(artifact.Type),
			Digest: strings.TrimSpace(artifact.Digest),
			Source: strings.TrimSpace(artifact.Source),
		},
		SBOM: ingest.CycloneDXBOM{
			BomFormat:    "CycloneDX",
			SpecVersion:  "1.5",
			SerialNumber: buildSerial("sbom", artifact.ID, req.InternalSBOM.Generated.UTC().Format(time.RFC3339Nano)),
			Metadata: ingest.CycloneDXMetadata{Component: ingest.CycloneDXComponent{
				BOMRef: artifact.ID,
				Type:   "application",
				Name:   artifact.Name,
			}},
			Components: components,
		},
	}, nil
}

type ScanFinding struct {
	VulnID      string `json:"vulnID"`
	PackagePURL string `json:"packagePURL"`
	Severity    string `json:"severity,omitempty"`
	Reachable   bool   `json:"reachable"`
}

type OpenVEXExportRequest struct {
	Service    string        `json:"service,omitempty"`
	ArtifactID string        `json:"artifactID,omitempty"`
	Author     string        `json:"author,omitempty"`
	Findings   []ScanFinding `json:"findings"`
}

func ToOpenVEX(req OpenVEXExportRequest) (ingest.OpenVEXIngestRequest, error) {
	author := strings.TrimSpace(req.Author)
	if author == "" {
		author = "VulnGate"
	}

	type statementKey struct {
		vuln string
		purl string
	}
	statementByKey := map[statementKey]ingest.OpenVEXStatement{}

	for _, finding := range req.Findings {
		vulnID := strings.TrimSpace(finding.VulnID)
		purl := strings.ToLower(strings.TrimSpace(finding.PackagePURL))
		if vulnID == "" || purl == "" {
			continue
		}

		key := statementKey{vuln: vulnID, purl: purl}
		status := "under_investigation"
		if finding.Reachable {
			status = "affected"
		}
		statementByKey[key] = ingest.OpenVEXStatement{
			ID: fmt.Sprintf("stmt-%s", hashHex(vulnID+"|"+purl)),
			Vulnerability: ingest.OpenVEXVulnRef{
				Name: vulnID,
			},
			Products: []ingest.OpenVEXProduct{{ID: purl}},
			Status:   status,
		}
	}

	keys := make([]statementKey, 0, len(statementByKey))
	for key := range statementByKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].vuln != keys[j].vuln {
			return keys[i].vuln < keys[j].vuln
		}
		return keys[i].purl < keys[j].purl
	})

	statements := make([]ingest.OpenVEXStatement, 0, len(keys))
	for _, key := range keys {
		statements = append(statements, statementByKey[key])
	}

	docID := "urn:uuid:" + buildSerial("openvex", req.ArtifactID, time.Now().UTC().Format(time.RFC3339Nano))
	return ingest.OpenVEXIngestRequest{
		Service:    strings.TrimSpace(req.Service),
		ArtifactID: strings.TrimSpace(req.ArtifactID),
		Document: ingest.OpenVEXDocument{
			Context:    "https://openvex.dev/ns/v0.2.0",
			ID:         docID,
			Author:     author,
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Version:    1,
			Statements: statements,
		},
	}, nil
}

type SignatureMetadata struct {
	KeyID string `json:"keyID"`
	Type  string `json:"type"`
}

type AttestationsExportRequest struct {
	Service         string              `json:"service,omitempty"`
	Artifact        model.Artifact      `json:"artifact"`
	Issuer          string              `json:"issuer,omitempty"`
	BuildProvenance map[string]string   `json:"buildProvenance,omitempty"`
	Signatures      []SignatureMetadata `json:"signatures,omitempty"`
}

func ToAttestations(req AttestationsExportRequest) (ingest.AttestationIngestRequest, error) {
	artifact := req.Artifact
	artifact.ID = strings.TrimSpace(artifact.ID)
	if artifact.ID == "" {
		return ingest.AttestationIngestRequest{}, fmt.Errorf("artifact id is required")
	}

	issuer := strings.TrimSpace(req.Issuer)
	if issuer == "" {
		issuer = "vulngate"
	}

	attestations := []model.Attestation{}
	if len(req.BuildProvenance) > 0 {
		attestations = append(attestations, model.Attestation{
			ID:            "att-prov-" + hashHex(artifact.ID+"|"+issuer),
			Type:          "provenance",
			PredicateType: "https://slsa.dev/provenance/v1",
			Issuer:        issuer,
			SubjectDigest: strings.TrimSpace(artifact.Digest),
			Metadata:      req.BuildProvenance,
		})
	}

	for _, signature := range req.Signatures {
		keyID := strings.TrimSpace(signature.KeyID)
		if keyID == "" {
			continue
		}
		attestations = append(attestations, model.Attestation{
			ID:            "att-sig-" + hashHex(artifact.ID+"|"+keyID),
			Type:          "signature",
			PredicateType: firstNonEmpty(strings.TrimSpace(signature.Type), "https://sigstore.dev/attestation/signature/v1"),
			Issuer:        issuer,
			SubjectDigest: strings.TrimSpace(artifact.Digest),
			Metadata: map[string]string{
				"keyID": keyID,
			},
		})
	}

	return ingest.AttestationIngestRequest{
		Service:      strings.TrimSpace(req.Service),
		Artifact:     artifact,
		Attestations: attestations,
	}, nil
}

func buildSerial(parts ...string) string {
	return hashHex(strings.Join(parts, "|"))
}

func hashHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func fallbackPURL(name, version string) string {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	cleanVersion := strings.TrimSpace(version)
	if cleanName == "" {
		cleanName = "unknown"
	}
	purl := "pkg:generic/" + cleanName
	if cleanVersion != "" {
		purl += "@" + cleanVersion
	}
	return purl
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
