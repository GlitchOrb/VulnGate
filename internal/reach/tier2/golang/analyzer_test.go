package golang

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

func TestReachableSampleMarkedTrueWithEvidence(t *testing.T) {
	analyzer := NewAnalyzer()
	target := filepath.Join("testdata", "reachable")

	findings := []engine.Finding{
		{
			VulnID:           "OSV-T2-0001",
			PackagePURL:      "pkg:golang/example.com/reacht2/vulnlib@1.0.0",
			InstalledVersion: "1.0.0",
			Severity:         "high",
			Scope:            "required",
		},
	}

	out, err := analyzer.Analyze(context.Background(), scanCtx(target), findings)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}

	got := out[0]
	if got.Reachability.Tier2Status != "true" {
		t.Fatalf("expected tier2 status true, got %q", got.Reachability.Tier2Status)
	}
	if !got.Reachability.Tier2 {
		t.Fatalf("expected tier2 bool true")
	}
	if !strings.Contains(strings.ToLower(got.Reachability.Tier2Reason), "reachable from entrypoint") {
		t.Fatalf("expected reason to mention entrypoint, got %q", got.Reachability.Tier2Reason)
	}
	if !strings.Contains(got.Reachability.Tier2Evidence, "vulnlib") {
		t.Fatalf("expected evidence to mention vulnlib, got %q", got.Reachability.Tier2Evidence)
	}
}

func TestUnreachableSampleMarkedFalseOrUnknownWithReason(t *testing.T) {
	analyzer := NewAnalyzer()
	target := filepath.Join("testdata", "unreachable")

	findings := []engine.Finding{
		{
			VulnID:           "OSV-T2-0002",
			PackagePURL:      "pkg:golang/example.com/unreacht2/vulnlib@1.0.0",
			InstalledVersion: "1.0.0",
			Severity:         "high",
			Scope:            "required",
		},
	}

	out, err := analyzer.Analyze(context.Background(), scanCtx(target), findings)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}

	got := out[0]
	if got.Reachability.Tier2Status != "false" && got.Reachability.Tier2Status != "unknown" {
		t.Fatalf("expected tier2 status false or unknown, got %q", got.Reachability.Tier2Status)
	}
	if got.Reachability.Tier2 {
		t.Fatalf("expected tier2 bool false")
	}
	if strings.TrimSpace(got.Reachability.Tier2Reason) == "" {
		t.Fatalf("expected non-empty reason")
	}
}

func TestNonGoPURLReturnsUnknown(t *testing.T) {
	analyzer := NewAnalyzer()
	target := filepath.Join("testdata", "reachable")

	findings := []engine.Finding{
		{
			VulnID:           "OSV-T2-0003",
			PackagePURL:      "pkg:npm/lodash@4.17.21",
			InstalledVersion: "4.17.21",
			Severity:         "high",
		},
	}

	out, err := analyzer.Analyze(context.Background(), scanCtx(target), findings)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if out[0].Reachability.Tier2Status != "unknown" {
		t.Fatalf("expected unknown status, got %q", out[0].Reachability.Tier2Status)
	}
}

func scanCtx(target string) engine.ScanContext {
	return engine.ScanContext{
		Target:      engine.TargetDescriptor{Type: engine.TargetTypeFS, Path: target},
		RequestedAt: time.Now().UTC(),
	}
}
