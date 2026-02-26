package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityUnknown:  0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func ParseSeverity(raw string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := severityRank[s]; !ok {
		return SeverityUnknown, fmt.Errorf("invalid severity %q", raw)
	}
	return s, nil
}

func SeverityAtLeast(actual Severity, threshold Severity) bool {
	return severityRank[actual] >= severityRank[threshold]
}

type ReachabilityTier string

const (
	Tier0None       ReachabilityTier = "tier0"
	Tier1Dependency ReachabilityTier = "tier1"
	Tier2Static     ReachabilityTier = "tier2"
	Tier2Runtime    ReachabilityTier = "tier2r"
)

var tierRank = map[ReachabilityTier]int{
	Tier0None:       0,
	Tier1Dependency: 1,
	Tier2Static:     2,
	Tier2Runtime:    3,
}

func ParseReachabilityTier(raw string) (ReachabilityTier, error) {
	t := ReachabilityTier(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := tierRank[t]; !ok {
		return Tier0None, fmt.Errorf("invalid reachability tier %q", raw)
	}
	return t, nil
}

func ReachabilityAtLeast(actual ReachabilityTier, threshold ReachabilityTier) bool {
	return tierRank[actual] >= tierRank[threshold]
}

type ReachabilityMode string

const (
	ReachabilityAny       ReachabilityMode = "any"
	ReachabilityReachable ReachabilityMode = "reachable"
)

func ParseReachabilityMode(raw string) (ReachabilityMode, error) {
	m := ReachabilityMode(strings.ToLower(strings.TrimSpace(raw)))
	switch m {
	case ReachabilityAny, ReachabilityReachable:
		return m, nil
	default:
		return ReachabilityAny, fmt.Errorf("invalid reachability mode %q", raw)
	}
}

type PolicyConfig struct {
	MinSeverity         Severity
	ReachabilityMode    ReachabilityMode
	MinReachabilityTier ReachabilityTier
}

func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MinSeverity:         SeverityHigh,
		ReachabilityMode:    ReachabilityReachable,
		MinReachabilityTier: Tier1Dependency,
	}
}

type OSVRangeType string

const (
	OSVRangeSemver OSVRangeType = "SEMVER"
	OSVRangeGit    OSVRangeType = "GIT"
)

type OSVRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type OSVRange struct {
	Type   OSVRangeType    `json:"type"`
	Events []OSVRangeEvent `json:"events"`
}

type Vulnerability struct {
	ID          string     `json:"id"`
	Summary     string     `json:"summary"`
	Severity    Severity   `json:"severity"`
	PackagePURL string     `json:"package_purl"`
	Ranges      []OSVRange `json:"ranges"`
	Aliases     []string   `json:"aliases,omitempty"`
	References  []string   `json:"references,omitempty"`
}

type Dependency struct {
	PURL    string `json:"purl"`
	Version string `json:"version"`
}

type Finding struct {
	Vulnerability Vulnerability    `json:"vulnerability"`
	Dependency    Dependency       `json:"dependency"`
	Reachability  ReachabilityTier `json:"reachability"`
	Scanner       string           `json:"scanner"`
	Message       string           `json:"message"`
}

type PolicyDecision struct {
	Fail       bool      `json:"fail"`
	Reason     string    `json:"reason"`
	Violations []Finding `json:"violations,omitempty"`
}

type ScanRequest struct {
	Project      string       `json:"project"`
	TargetPath   string       `json:"target_path"`
	Dependencies []Dependency `json:"dependencies"`
	GeneratedAt  time.Time    `json:"generated_at"`
}

type Report struct {
	ToolVersion    string         `json:"tool_version"`
	Project        string         `json:"project"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Findings       []Finding      `json:"findings"`
	PolicyDecision PolicyDecision `json:"policy_decision"`
}
