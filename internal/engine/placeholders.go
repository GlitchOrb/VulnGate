package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PlaceholderTargetIngestor struct{}

func (p PlaceholderTargetIngestor) Ingest(_ context.Context, scanCtx ScanContext) (IngestedTarget, error) {
	if strings.TrimSpace(scanCtx.Target.Path) == "" {
		return IngestedTarget{}, fmt.Errorf("target path is empty")
	}

	absPath, err := filepath.Abs(scanCtx.Target.Path)
	if err != nil {
		return IngestedTarget{}, fmt.Errorf("resolve target path: %w", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return IngestedTarget{}, fmt.Errorf("target path is not accessible: %w", err)
	}

	return IngestedTarget{
		Type: scanCtx.Target.Type,
		Path: absPath,
		Metadata: map[string]string{
			"ingestor": "placeholder",
		},
	}, nil
}

type PlaceholderSBOMCataloger struct{}

func (p PlaceholderSBOMCataloger) Catalog(_ context.Context, _ ScanContext, target IngestedTarget) ([]PackageRef, error) {
	packages := []PackageRef{{
		PURL:             "pkg:generic/vulngate/placeholder@0.0.0",
		InstalledVersion: "0.0.0",
		Scope:            "required",
		Locations:        []Location{{Path: target.Path}},
	}}

	insecureMarker := filepath.Join(target.Path, ".vulngate-insecure")
	if _, err := os.Stat(insecureMarker); err == nil {
		packages = append(packages, PackageRef{
			PURL:             "pkg:generic/vulngate/insecure@0.0.0",
			InstalledVersion: "0.0.0",
			Scope:            "required",
			Locations:        []Location{{Path: insecureMarker}},
		})
	}

	insecureDevMarker := filepath.Join(target.Path, ".vulngate-insecure-dev")
	if _, err := os.Stat(insecureDevMarker); err == nil {
		packages = append(packages, PackageRef{
			PURL:             "pkg:generic/vulngate/insecure-dev@0.0.0",
			InstalledVersion: "0.0.0",
			Scope:            "dev",
			Locations:        []Location{{Path: insecureDevMarker}},
		})
	}

	return packages, nil
}

type PlaceholderMatcher struct{}

func (p PlaceholderMatcher) Match(_ context.Context, _ ScanContext, packages []PackageRef) ([]Finding, error) {
	findings := make([]Finding, 0)
	for _, pkg := range packages {
		purl := strings.ToLower(pkg.PURL)
		if !strings.Contains(purl, "insecure") && !strings.Contains(purl, "vulnerable") {
			continue
		}

		findings = append(findings, Finding{
			VulnID:           "OSV-PLACEHOLDER-0001",
			PackagePURL:      pkg.PURL,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     "0.0.1",
			Scope:            pkg.Scope,
			Severity:         "high",
			References: []string{
				"https://osv.dev/",
			},
			Locations: pkg.Locations,
		})
	}
	return findings, nil
}

type Tier1ReachabilityAnalyzer struct{}

func (a Tier1ReachabilityAnalyzer) Name() string {
	return "tier1"
}

func (a Tier1ReachabilityAnalyzer) Analyze(_ context.Context, _ ScanContext, findings []Finding) ([]Finding, error) {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		out[i].Reachability.Tier1 = true
	}
	return out, nil
}

type Tier2ReachabilityAnalyzer struct{}

func (a Tier2ReachabilityAnalyzer) Name() string {
	return "tier2"
}

func (a Tier2ReachabilityAnalyzer) Analyze(_ context.Context, _ ScanContext, findings []Finding) ([]Finding, error) {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		for _, loc := range out[i].Locations {
			if strings.HasSuffix(strings.ToLower(loc.Path), ".go") {
				out[i].Reachability.Tier2 = true
				break
			}
		}
	}
	return out, nil
}

type DefaultDeduplicatorFingerprinter struct{}

func (d DefaultDeduplicatorFingerprinter) DeduplicateAndFingerprint(_ context.Context, _ ScanContext, findings []Finding) ([]Finding, error) {
	if len(findings) == 0 {
		return []Finding{}, nil
	}

	seen := map[string]Finding{}
	keys := make([]string, 0, len(findings))

	for _, f := range findings {
		key := fingerprintKey(f)
		existing, exists := seen[key]
		if exists {
			existing.References = mergeStringSlices(existing.References, f.References)
			existing.Locations = mergeLocations(existing.Locations, f.Locations)
			existing.Reachability = ReachabilityFlags{
				Tier1:        existing.Reachability.Tier1 || f.Reachability.Tier1,
				Tier2:        existing.Reachability.Tier2 || f.Reachability.Tier2,
				Tier2Runtime: existing.Reachability.Tier2Runtime || f.Reachability.Tier2Runtime,
			}
			existing.Reachability.Tier1Status = mergeTier1Status(existing.Reachability.Tier1Status, f.Reachability.Tier1Status, existing.Reachability.Tier1)
			existing.Reachability.Tier1Reason = mergeReasons(existing.Reachability.Tier1Reason, f.Reachability.Tier1Reason)
			existing.Reachability.Tier2Status = mergeTierStatus(existing.Reachability.Tier2Status, f.Reachability.Tier2Status, existing.Reachability.Tier2)
			existing.Reachability.Tier2Reason = mergeReasons(existing.Reachability.Tier2Reason, f.Reachability.Tier2Reason)
			existing.Reachability.Tier2Evidence = mergeReasons(existing.Reachability.Tier2Evidence, f.Reachability.Tier2Evidence)
			existing.Reachability.RuntimeStatus = mergeTierStatus(existing.Reachability.RuntimeStatus, f.Reachability.RuntimeStatus, existing.Reachability.Tier2Runtime)
			existing.Reachability.RuntimeReason = mergeReasons(existing.Reachability.RuntimeReason, f.Reachability.RuntimeReason)
			existing.Reachability.RuntimeSymbols = mergeStringSlices(existing.Reachability.RuntimeSymbols, f.Reachability.RuntimeSymbols)
			existing.Reachability.RuntimeCallCount = maxUint64(existing.Reachability.RuntimeCallCount, f.Reachability.RuntimeCallCount)
			existing.Reachability.RuntimeFirstSeen = earlierRFC3339(existing.Reachability.RuntimeFirstSeen, f.Reachability.RuntimeFirstSeen)
			existing.Reachability.RuntimeLastSeen = laterRFC3339(existing.Reachability.RuntimeLastSeen, f.Reachability.RuntimeLastSeen)
			existing.Scope = chooseScope(existing.Scope, f.Scope)
			if existing.FixedVersion == "" {
				existing.FixedVersion = f.FixedVersion
			}
			seen[key] = existing
			continue
		}

		copyFinding := f
		if copyFinding.Fingerprints == nil {
			copyFinding.Fingerprints = map[string]string{}
		}
		copyFinding.Fingerprints["primary"] = sha256Hex(key)
		copyFinding.Fingerprints["vuln"] = sha256Hex(copyFinding.VulnID)
		copyFinding.Fingerprints["package"] = sha256Hex(copyFinding.PackagePURL)

		seen[key] = copyFinding
		keys = append(keys, key)
	}

	sort.Strings(keys)
	out := make([]Finding, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out, nil
}

type DefaultPolicyEngine struct {
	FailSeverities   map[string]bool
	RequireReachable bool
}

func NewDefaultPolicyEngine() DefaultPolicyEngine {
	return DefaultPolicyEngine{
		FailSeverities: map[string]bool{
			"critical": true,
			"high":     true,
		},
		RequireReachable: true,
	}
}

func (p DefaultPolicyEngine) Decide(_ context.Context, _ ScanContext, findings []Finding) (GateDecision, error) {
	violations := 0
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if !p.FailSeverities[sev] {
			continue
		}

		if p.RequireReachable {
			reachable := f.Reachability.Tier1 || f.Reachability.Tier2 || f.Reachability.Tier2Runtime
			if !reachable {
				continue
			}
		}
		violations++
	}

	if violations == 0 {
		return GateDecision{Fail: false, Reason: "policy passed", Violations: 0}, nil
	}

	return GateDecision{
		Fail:       true,
		Reason:     fmt.Sprintf("policy failed with %d violation(s)", violations),
		Violations: violations,
	}, nil
}

func fingerprintKey(f Finding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.VulnID)),
		strings.ToLower(strings.TrimSpace(f.PackagePURL)),
		strings.TrimSpace(f.InstalledVersion),
		strings.TrimSpace(f.FixedVersion),
	}
	return strings.Join(parts, "|")
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func mergeStringSlices(a, b []string) []string {
	set := map[string]bool{}
	for _, item := range a {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		set[value] = true
	}
	for _, item := range b {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		set[value] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func mergeLocations(a, b []Location) []Location {
	type key struct {
		path   string
		line   int
		column int
	}
	set := map[key]Location{}
	for _, loc := range a {
		k := key{path: strings.TrimSpace(loc.Path), line: loc.Line, column: loc.Column}
		set[k] = Location{Path: strings.TrimSpace(loc.Path), Line: loc.Line, Column: loc.Column}
	}
	for _, loc := range b {
		k := key{path: strings.TrimSpace(loc.Path), line: loc.Line, column: loc.Column}
		set[k] = Location{Path: strings.TrimSpace(loc.Path), Line: loc.Line, Column: loc.Column}
	}
	keys := make([]key, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		if keys[i].line != keys[j].line {
			return keys[i].line < keys[j].line
		}
		return keys[i].column < keys[j].column
	})
	out := make([]Location, 0, len(keys))
	for _, k := range keys {
		out = append(out, set[k])
	}
	return out
}

func chooseScope(a, b string) string {
	aa := strings.ToLower(strings.TrimSpace(a))
	bb := strings.ToLower(strings.TrimSpace(b))
	if scopeRank(bb) > scopeRank(aa) {
		return bb
	}
	return aa
}

func scopeRank(scope string) int {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "required":
		return 6
	case "transitive":
		return 5
	case "optional":
		return 4
	case "unknown":
		return 3
	case "test":
		return 2
	case "dev":
		return 1
	default:
		return 0
	}
}

func mergeTier1Status(a, b string, tier1 bool) string {
	return mergeTierStatus(a, b, tier1)
}

func mergeTierStatus(a, b string, isReachable bool) string {
	normalize := func(v string) string {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "false", "unknown":
			return strings.ToLower(strings.TrimSpace(v))
		default:
			return ""
		}
	}
	aa := normalize(a)
	bb := normalize(b)
	switch {
	case isReachable || aa == "true" || bb == "true":
		return "true"
	case aa == "false" || bb == "false":
		return "false"
	case aa == "unknown" || bb == "unknown":
		return "unknown"
	default:
		return ""
	}
}

func mergeReasons(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch {
	case a == "" && b == "":
		return ""
	case a == "":
		return b
	case b == "":
		return a
	case a == b:
		return a
	default:
		return a + "; " + b
	}
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func earlierRFC3339(a, b string) string {
	aa := strings.TrimSpace(a)
	bb := strings.TrimSpace(b)
	switch {
	case aa == "":
		return bb
	case bb == "":
		return aa
	}

	at, errA := time.Parse(time.RFC3339Nano, aa)
	bt, errB := time.Parse(time.RFC3339Nano, bb)
	if errA != nil || errB != nil {
		if aa <= bb {
			return aa
		}
		return bb
	}
	if bt.Before(at) {
		return bb
	}
	return aa
}

func laterRFC3339(a, b string) string {
	aa := strings.TrimSpace(a)
	bb := strings.TrimSpace(b)
	switch {
	case aa == "":
		return bb
	case bb == "":
		return aa
	}

	at, errA := time.Parse(time.RFC3339Nano, aa)
	bt, errB := time.Parse(time.RFC3339Nano, bb)
	if errA != nil || errB != nil {
		if aa >= bb {
			return aa
		}
		return bb
	}
	if bt.After(at) {
		return bb
	}
	return aa
}

func NewDefaultPipeline() (*Pipeline, error) {
	return NewPipeline(PipelineConfig{
		TargetIngestor: PlaceholderTargetIngestor{},
		SBOMCataloger:  PlaceholderSBOMCataloger{},
		Matcher:        PlaceholderMatcher{},
		ReachabilityAnalyzers: []ReachabilityAnalyzer{
			Tier1ReachabilityAnalyzer{},
			Tier2ReachabilityAnalyzer{},
		},
		Deduplicator: DefaultDeduplicatorFingerprinter{},
		Renderer:     NewSARIFRenderer("VulnGate"),
		PolicyEngine: NewDefaultPolicyEngine(),
	})
}
