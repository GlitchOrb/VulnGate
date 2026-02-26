package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

func TestPolicyEvaluationTableDriven(t *testing.T) {
	now := time.Date(2026, 2, 26, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		cfg        Config
		findings   []engine.Finding
		wantFail   bool
		wantViols  int
		wantIgnore int
	}{
		{
			name:      "high reachable fails by default",
			cfg:       DefaultConfig(),
			findings:  []engine.Finding{finding("OSV-1", "high", "required", true, "src/main.go")},
			wantFail:  true,
			wantViols: 1,
		},
		{
			name:      "high unreachable passes when reachability required",
			cfg:       DefaultConfig(),
			findings:  []engine.Finding{finding("OSV-2", "high", "required", false, "src/main.go")},
			wantFail:  false,
			wantViols: 0,
		},
		{
			name: "high unreachable fails when reachability not required",
			cfg: Config{
				FailOnSeverities: []string{"high"},
				Scope: ScopeRules{
					ProductionMode:         false,
					IgnoreDevDependencies:  true,
					IgnoreTestDependencies: true,
				},
				Reachability: ReachabilityRules{RequireReachableForSeverities: []string{}},
				Ignore:       []IgnoreRule{},
			},
			findings:  []engine.Finding{finding("OSV-3", "high", "required", false, "src/main.go")},
			wantFail:  true,
			wantViols: 1,
		},
		{
			name: "dev dependency ignored in production mode",
			cfg: Config{
				FailOnSeverities: []string{"high"},
				Scope: ScopeRules{
					ProductionMode:         true,
					IgnoreDevDependencies:  true,
					IgnoreTestDependencies: true,
				},
				Reachability: ReachabilityRules{RequireReachableForSeverities: []string{"high"}},
				Ignore:       []IgnoreRule{},
			},
			findings:   []engine.Finding{finding("OSV-4", "high", "dev", true, "package-lock.json")},
			wantFail:   false,
			wantViols:  0,
			wantIgnore: 1,
		},
		{
			name: "ignore by vuln id",
			cfg: Config{
				FailOnSeverities: []string{"high"},
				Scope: ScopeRules{
					ProductionMode:         false,
					IgnoreDevDependencies:  true,
					IgnoreTestDependencies: true,
				},
				Reachability: ReachabilityRules{RequireReachableForSeverities: []string{"high"}},
				Ignore: []IgnoreRule{{
					VulnID:  "OSV-5",
					Expires: "2030-01-01",
				}},
			},
			findings:   []engine.Finding{finding("OSV-5", "high", "required", true, "src/main.go")},
			wantFail:   false,
			wantViols:  0,
			wantIgnore: 1,
		},
		{
			name: "ignore by path expired no longer applies",
			cfg: Config{
				FailOnSeverities: []string{"high"},
				Scope: ScopeRules{
					ProductionMode:         false,
					IgnoreDevDependencies:  true,
					IgnoreTestDependencies: true,
				},
				Reachability: ReachabilityRules{RequireReachableForSeverities: []string{"high"}},
				Ignore: []IgnoreRule{{
					Path:    "vendor/**",
					Expires: "2020-01-01",
				}},
			},
			findings:  []engine.Finding{finding("OSV-6", "high", "required", true, "vendor/lib/a.go")},
			wantFail:  true,
			wantViols: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyEngine, err := NewEngine(tt.cfg)
			if err != nil {
				t.Fatalf("NewEngine returned error: %v", err)
			}
			policyEngine.SetNowFn(func() time.Time { return now })

			decision, err := policyEngine.Decide(context.Background(), engine.ScanContext{}, tt.findings)
			if err != nil {
				t.Fatalf("Decide returned error: %v", err)
			}
			if decision.Fail != tt.wantFail {
				t.Fatalf("expected fail=%v, got %v", tt.wantFail, decision.Fail)
			}
			if decision.Violations != tt.wantViols {
				t.Fatalf("expected violations=%d, got %d", tt.wantViols, decision.Violations)
			}

			report := policyEngine.LastReport()
			if report.IgnoredFindings != tt.wantIgnore {
				t.Fatalf("expected ignored=%d, got %d", tt.wantIgnore, report.IgnoredFindings)
			}
		})
	}
}

func TestSummaryLinesIncludeSeverityBreakdown(t *testing.T) {
	cfg := DefaultConfig()
	policyEngine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}

	_, err = policyEngine.Decide(context.Background(), engine.ScanContext{}, []engine.Finding{
		finding("OSV-1", "high", "required", true, "src/main.go"),
		finding("OSV-2", "medium", "required", false, "src/main.go"),
	})
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	lines := SummaryLines(policyEngine.LastReport())
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "severity=high reachable=1 unreachable=0 total=1") {
		t.Fatalf("expected high severity summary, got: %s", joined)
	}
	if !strings.Contains(joined, "severity=medium reachable=0 unreachable=1 total=1") {
		t.Fatalf("expected medium severity summary, got: %s", joined)
	}
}

func TestSampleRepoConfigsPassFailDeterministically(t *testing.T) {
	tests := []struct {
		name     string
		repoPath string
		wantFail bool
	}{
		{
			name:     "repo-pass",
			repoPath: filepath.Join("testdata", "repo-pass"),
			wantFail: false,
		},
		{
			name:     "repo-fail",
			repoPath: filepath.Join("testdata", "repo-fail"),
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _, err := Load(LoadOptions{Path: filepath.Join(tt.repoPath, ".vulngate.yml"), Required: true})
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}

			findings := fixtureFindings(t, tt.repoPath)
			policyEngine, err := NewEngine(cfg)
			if err != nil {
				t.Fatalf("NewEngine returned error: %v", err)
			}
			policyEngine.SetNowFn(func() time.Time {
				return time.Date(2026, 2, 26, 0, 0, 0, 0, time.UTC)
			})

			decision, err := policyEngine.Decide(context.Background(), engine.ScanContext{}, findings)
			if err != nil {
				t.Fatalf("Decide returned error: %v", err)
			}
			if decision.Fail != tt.wantFail {
				t.Fatalf("expected fail=%v, got %v", tt.wantFail, decision.Fail)
			}
		})
	}
}

func fixtureFindings(t *testing.T, repoPath string) []engine.Finding {
	t.Helper()
	findings := []engine.Finding{}

	insecurePath := filepath.Join(repoPath, ".vulngate-insecure")
	if _, err := os.Stat(insecurePath); err == nil {
		findings = append(findings, finding("OSV-PLACEHOLDER-0001", "high", "required", true, insecurePath))
	}

	devPath := filepath.Join(repoPath, ".vulngate-insecure-dev")
	if _, err := os.Stat(devPath); err == nil {
		findings = append(findings, finding("OSV-PLACEHOLDER-0001", "high", "dev", true, devPath))
	}

	return findings
}

func finding(vulnID, severity, scope string, reachable bool, path string) engine.Finding {
	f := engine.Finding{
		VulnID:           vulnID,
		PackagePURL:      "pkg:generic/vulngate/insecure@0.0.0",
		InstalledVersion: "0.0.0",
		Severity:         severity,
		Scope:            scope,
		Locations:        []engine.Location{{Path: path, Line: 1, Column: 1}},
	}
	if reachable {
		f.Reachability.Tier1 = true
	}
	return f
}
