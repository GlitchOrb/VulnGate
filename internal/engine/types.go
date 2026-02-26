package engine

import (
	"fmt"
	"strings"
	"time"
)

type TargetType string

const (
	TargetTypeFS    TargetType = "fs"
	TargetTypeImage TargetType = "image"
	TargetTypeSBOM  TargetType = "sbom"
)

func ParseTargetType(raw string) (TargetType, error) {
	t := TargetType(strings.ToLower(strings.TrimSpace(raw)))
	switch t {
	case TargetTypeFS, TargetTypeImage, TargetTypeSBOM:
		return t, nil
	default:
		return "", fmt.Errorf("invalid target type %q (expected fs|image|sbom)", raw)
	}
}

type RepoMetadata struct {
	Commit string `json:"commit"`
	Branch string `json:"branch"`
	URL    string `json:"url,omitempty"`
}

type CIMetadata struct {
	Provider   string `json:"provider,omitempty"`
	PipelineID string `json:"pipelineID,omitempty"`
	JobID      string `json:"jobID,omitempty"`
	RunURL     string `json:"runURL,omitempty"`
}

type TargetDescriptor struct {
	Type TargetType `json:"type"`
	Path string     `json:"path"`
}

type ScanContext struct {
	Repo        RepoMetadata     `json:"repo"`
	CI          CIMetadata       `json:"ci"`
	Target      TargetDescriptor `json:"target"`
	Provenance  map[string]any   `json:"provenance,omitempty"`
	RequestedAt time.Time        `json:"requestedAt"`
}

type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type ReachabilityFlags struct {
	Tier1            bool     `json:"tier1"`
	Tier2            bool     `json:"tier2"`
	Tier2Runtime     bool     `json:"tier2Runtime"`
	Tier1Status      string   `json:"tier1Status,omitempty"`
	Tier1Reason      string   `json:"tier1Reason,omitempty"`
	Tier2Status      string   `json:"tier2Status,omitempty"`
	Tier2Reason      string   `json:"tier2Reason,omitempty"`
	Tier2Evidence    string   `json:"tier2Evidence,omitempty"`
	RuntimeStatus    string   `json:"runtimeStatus,omitempty"`
	RuntimeReason    string   `json:"runtimeReason,omitempty"`
	RuntimeSymbols   []string `json:"runtimeSymbols,omitempty"`
	RuntimeCallCount uint64   `json:"runtimeCallCount,omitempty"`
	RuntimeFirstSeen string   `json:"runtimeFirstSeen,omitempty"`
	RuntimeLastSeen  string   `json:"runtimeLastSeen,omitempty"`
}

type Finding struct {
	VulnID           string            `json:"vulnID"`
	PackagePURL      string            `json:"packagePURL"`
	InstalledVersion string            `json:"installedVersion"`
	FixedVersion     string            `json:"fixedVersion,omitempty"`
	Scope            string            `json:"scope,omitempty"`
	Severity         string            `json:"severity"`
	References       []string          `json:"references,omitempty"`
	Locations        []Location        `json:"locations,omitempty"`
	Reachability     ReachabilityFlags `json:"reachability"`
	Fingerprints     map[string]string `json:"fingerprints,omitempty"`
}

type PackageRef struct {
	PURL             string     `json:"purl"`
	InstalledVersion string     `json:"installedVersion"`
	Scope            string     `json:"scope,omitempty"`
	Locations        []Location `json:"locations,omitempty"`
}

type IngestedTarget struct {
	Type     TargetType        `json:"type"`
	Path     string            `json:"path"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type GateDecision struct {
	Fail       bool   `json:"fail"`
	Reason     string `json:"reason"`
	Violations int    `json:"violations"`
}

type RunResult struct {
	Context  ScanContext  `json:"context"`
	Findings []Finding    `json:"findings"`
	Decision GateDecision `json:"decision"`
	SARIF    []byte       `json:"-"`
}
