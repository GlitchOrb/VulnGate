package autofix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
	"github.com/GlitchOrb/vulngate/internal/policy"
	reachtier1 "github.com/GlitchOrb/vulngate/internal/reach/tier1"
)

type scanSnapshot struct {
	Result       engine.RunResult
	PolicyReport policy.EvaluationReport
}

func runScanSnapshot(ctx context.Context, repoPath string, policyPath string) (scanSnapshot, error) {
	absRepo, err := filepath.Abs(strings.TrimSpace(repoPath))
	if err != nil {
		return scanSnapshot{}, fmt.Errorf("resolve repo path: %w", err)
	}
	if _, err := os.Stat(absRepo); err != nil {
		return scanSnapshot{}, fmt.Errorf("repo path is not accessible: %w", err)
	}

	resolvedPolicyPath, required := resolvePolicyPath(absRepo, policyPath)
	cfg, _, err := policy.Load(policy.LoadOptions{Path: resolvedPolicyPath, Required: required})
	if err != nil {
		return scanSnapshot{}, fmt.Errorf("load policy config: %w", err)
	}

	policyEngine, err := policy.NewEngine(cfg)
	if err != nil {
		return scanSnapshot{}, fmt.Errorf("build policy engine: %w", err)
	}

	pipeline, err := engine.NewPipeline(engine.PipelineConfig{
		TargetIngestor: engine.PlaceholderTargetIngestor{},
		SBOMCataloger:  engine.PlaceholderSBOMCataloger{},
		Matcher:        engine.PlaceholderMatcher{},
		ReachabilityAnalyzers: []engine.ReachabilityAnalyzer{
			reachtier1.NewAnalyzer(reachtier1.Options{Profile: reachtier1.ProfileFromProductionMode(cfg.Scope.ProductionMode)}),
		},
		Deduplicator: engine.DefaultDeduplicatorFingerprinter{},
		Renderer:     engine.NewSARIFRenderer("VulnGate"),
		PolicyEngine: policyEngine,
	})
	if err != nil {
		return scanSnapshot{}, fmt.Errorf("build scan pipeline: %w", err)
	}

	result, err := pipeline.Run(ctx, buildScanContext(absRepo))
	if err != nil {
		return scanSnapshot{}, err
	}

	return scanSnapshot{Result: result, PolicyReport: policyEngine.LastReport()}, nil
}

func buildScanContext(repoPath string) engine.ScanContext {
	return engine.ScanContext{
		Repo: engine.RepoMetadata{},
		CI:   engine.CIMetadata{},
		Target: engine.TargetDescriptor{
			Type: engine.TargetTypeFS,
			Path: repoPath,
		},
		RequestedAt: time.Now().UTC(),
	}
}

func resolvePolicyPath(repoPath string, policyPath string) (string, bool) {
	trimmed := strings.TrimSpace(policyPath)
	if trimmed == "" {
		return policy.ResolveDefaultPath(repoPath), false
	}
	if filepath.IsAbs(trimmed) {
		return trimmed, true
	}
	return filepath.Join(repoPath, trimmed), true
}

func detectCandidates(findings []engine.Finding, maxCandidates int) DetectReport {
	report := DetectReport{Candidates: []Candidate{}}
	for _, finding := range findings {
		severity := normalizeSeverity(finding.Severity)
		reachable := isReachable(finding)

		report.TotalFindings++
		if severity == "critical" {
			report.CriticalFindings++
		}
		if severity == "high" {
			report.HighFindings++
		}
		if reachable {
			report.ReachableFindings++
		}

		if !reachable {
			continue
		}
		if severity != "critical" && severity != "high" {
			continue
		}

		candidate := Candidate{
			VulnID:       strings.TrimSpace(finding.VulnID),
			PackagePURL:  strings.TrimSpace(finding.PackagePURL),
			Severity:     severity,
			Reachable:    reachable,
			FixedVersion: strings.TrimSpace(finding.FixedVersion),
			Locations:    locationsFromFinding(finding),
		}
		report.Candidates = append(report.Candidates, candidate)
	}

	sort.Slice(report.Candidates, func(i, j int) bool {
		si := severityRank(report.Candidates[i].Severity)
		sj := severityRank(report.Candidates[j].Severity)
		if si != sj {
			return si > sj
		}
		if report.Candidates[i].VulnID != report.Candidates[j].VulnID {
			return report.Candidates[i].VulnID < report.Candidates[j].VulnID
		}
		return report.Candidates[i].PackagePURL < report.Candidates[j].PackagePURL
	})

	if maxCandidates <= 0 {
		maxCandidates = 3
	}
	if len(report.Candidates) > maxCandidates {
		report.Candidates = report.Candidates[:maxCandidates]
	}
	return report
}

func normalizeSeverity(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "low"
	}
}

func severityRank(severity string) int {
	switch normalizeSeverity(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func isReachable(f engine.Finding) bool {
	if f.Reachability.Tier1 || f.Reachability.Tier2 || f.Reachability.Tier2Runtime {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(f.Reachability.Tier1Status), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(f.Reachability.Tier2Status), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(f.Reachability.RuntimeStatus), "true") {
		return true
	}
	return false
}

func locationsFromFinding(f engine.Finding) []string {
	set := map[string]bool{}
	for _, location := range f.Locations {
		path := filepath.ToSlash(strings.TrimSpace(location.Path))
		if path == "" {
			continue
		}
		set[path] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func candidateKey(candidate Candidate) string {
	return strings.Join([]string{strings.TrimSpace(candidate.VulnID), strings.ToLower(strings.TrimSpace(candidate.PackagePURL))}, "|")
}

func findingsToCandidates(findings []engine.Finding) []Candidate {
	out := make([]Candidate, 0, len(findings))
	for _, finding := range findings {
		out = append(out, Candidate{
			VulnID:       strings.TrimSpace(finding.VulnID),
			PackagePURL:  strings.ToLower(strings.TrimSpace(finding.PackagePURL)),
			Severity:     normalizeSeverity(finding.Severity),
			Reachable:    isReachable(finding),
			FixedVersion: strings.TrimSpace(finding.FixedVersion),
			Locations:    locationsFromFinding(finding),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VulnID != out[j].VulnID {
			return out[i].VulnID < out[j].VulnID
		}
		return out[i].PackagePURL < out[j].PackagePURL
	})
	return out
}

func diffCandidateSets(before []Candidate, after []Candidate) (unresolved []Candidate, newCritical []Candidate) {
	beforeSet := map[string]Candidate{}
	afterSet := map[string]Candidate{}
	for _, c := range before {
		beforeSet[candidateKey(c)] = c
	}
	for _, c := range after {
		afterSet[candidateKey(c)] = c
	}

	for key, c := range beforeSet {
		if _, ok := afterSet[key]; ok {
			unresolved = append(unresolved, c)
		}
	}
	for key, c := range afterSet {
		if normalizeSeverity(c.Severity) != "critical" {
			continue
		}
		if _, ok := beforeSet[key]; !ok {
			newCritical = append(newCritical, c)
		}
	}

	sort.Slice(unresolved, func(i, j int) bool {
		if unresolved[i].VulnID != unresolved[j].VulnID {
			return unresolved[i].VulnID < unresolved[j].VulnID
		}
		return unresolved[i].PackagePURL < unresolved[j].PackagePURL
	})
	sort.Slice(newCritical, func(i, j int) bool {
		if newCritical[i].VulnID != newCritical[j].VulnID {
			return newCritical[i].VulnID < newCritical[j].VulnID
		}
		return newCritical[i].PackagePURL < newCritical[j].PackagePURL
	})
	return unresolved, newCritical
}
