package model

import "time"

type Artifact struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Digest string `json:"digest,omitempty"`
	Source string `json:"source,omitempty"`
}

type Package struct {
	PURL      string `json:"purl"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type Vulnerability struct {
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
}

type Attestation struct {
	ID            string            `json:"id"`
	Type          string            `json:"type,omitempty"`
	PredicateType string            `json:"predicateType,omitempty"`
	Issuer        string            `json:"issuer,omitempty"`
	SubjectDigest string            `json:"subjectDigest,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type VEXStatement struct {
	ID            string    `json:"id"`
	VulnID        string    `json:"vulnID"`
	PackagePURL   string    `json:"packagePURL"`
	Status        string    `json:"status"`
	Justification string    `json:"justification,omitempty"`
	ArtifactID    string    `json:"artifactID,omitempty"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
}

type ServiceImpact struct {
	Service      string   `json:"service"`
	ArtifactIDs  []string `json:"artifactIDs,omitempty"`
	PackagePURLs []string `json:"packagePURLs,omitempty"`
}

type ServicesByVulnResult struct {
	VulnID   string          `json:"vulnID"`
	Services []ServiceImpact `json:"services"`
}

type BlastRadiusResult struct {
	PackagePURL            string   `json:"packagePURL"`
	Services               []string `json:"services,omitempty"`
	Artifacts              []string `json:"artifacts,omitempty"`
	DirectDependents       []string `json:"directDependents,omitempty"`
	TransitiveDependents   []string `json:"transitiveDependents,omitempty"`
	RelatedVulnerabilities []string `json:"relatedVulnerabilities,omitempty"`
}

type VulnerabilityImpact struct {
	VulnID       string   `json:"vulnID"`
	ArtifactIDs  []string `json:"artifactIDs,omitempty"`
	PackagePURLs []string `json:"packagePURLs,omitempty"`
}

type VulnsByServiceResult struct {
	Service string                `json:"service"`
	Vulns   []VulnerabilityImpact `json:"vulns"`
}
