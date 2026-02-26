package tier1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

const samplePackageLock = `{
  "name": "sample",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "sample",
      "version": "1.0.0",
      "dependencies": {
        "prod-lib": "1.0.0"
      },
      "devDependencies": {
        "dev-only": "1.0.0"
      }
    },
    "node_modules/prod-lib": {
      "version": "1.0.0",
      "dependencies": {
        "transitive-lib": "1.0.0"
      }
    },
    "node_modules/transitive-lib": {
      "version": "1.0.0"
    },
    "node_modules/dev-only": {
      "version": "1.0.0",
      "dev": true
    }
  }
}`

func TestTier1ProfileToggleForDevDependency(t *testing.T) {
	target := writeSampleLockfile(t)
	finding := baseFinding("pkg:npm/dev-only@1.0.0", "dev")

	prod := NewAnalyzer(Options{Profile: ProfileProd})
	dev := NewAnalyzer(Options{Profile: ProfileDev})

	prodOut, err := prod.Analyze(context.Background(), scanCtx(target), []engine.Finding{finding})
	if err != nil {
		t.Fatalf("prod analyze returned error: %v", err)
	}
	devOut, err := dev.Analyze(context.Background(), scanCtx(target), []engine.Finding{finding})
	if err != nil {
		t.Fatalf("dev analyze returned error: %v", err)
	}

	if got := prodOut[0].Reachability.Tier1Status; got != string(ReachableFalse) {
		t.Fatalf("expected prod status false, got %s", got)
	}
	if !strings.Contains(prodOut[0].Reachability.Tier1Reason, "devDependency") {
		t.Fatalf("expected prod reason to mention devDependency, got %q", prodOut[0].Reachability.Tier1Reason)
	}

	if got := devOut[0].Reachability.Tier1Status; got != string(ReachableTrue) {
		t.Fatalf("expected dev status true, got %s", got)
	}
	if !strings.Contains(devOut[0].Reachability.Tier1Reason, "dev dependency closure") {
		t.Fatalf("expected dev reason to mention dev closure, got %q", devOut[0].Reachability.Tier1Reason)
	}
}

func TestTier1RuntimeClosureFromPackageLock(t *testing.T) {
	target := writeSampleLockfile(t)
	analyzer := NewAnalyzer(Options{Profile: ProfileProd})

	findings := []engine.Finding{
		baseFinding("pkg:npm/prod-lib@1.0.0", "required"),
		baseFinding("pkg:npm/transitive-lib@1.0.0", "transitive"),
		baseFinding("pkg:npm/dev-only@1.0.0", "dev"),
		baseFinding("pkg:npm/unknown-lib@9.9.9", "required"),
	}

	out, err := analyzer.Analyze(context.Background(), scanCtx(target), findings)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	got := map[string]engine.Finding{}
	for _, finding := range out {
		got[finding.PackagePURL] = finding
	}

	assertStatus(t, got["pkg:npm/prod-lib@1.0.0"], string(ReachableTrue), "runtime dependency closure")
	assertStatus(t, got["pkg:npm/transitive-lib@1.0.0"], string(ReachableTrue), "runtime dependency closure")
	assertStatus(t, got["pkg:npm/dev-only@1.0.0"], string(ReachableFalse), "devDependency")
	assertStatus(t, got["pkg:npm/unknown-lib@9.9.9"], string(ReachableUnknown), "not present in dependency graph")
}

func TestTier1NonFilesystemTargetIsUnknown(t *testing.T) {
	analyzer := NewAnalyzer(Options{Profile: ProfileProd})
	findings := []engine.Finding{baseFinding("pkg:npm/prod-lib@1.0.0", "required")}

	ctx := scanCtx(t.TempDir())
	ctx.Target.Type = engine.TargetTypeImage

	out, err := analyzer.Analyze(context.Background(), ctx, findings)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	assertStatus(t, out[0], string(ReachableUnknown), "non-filesystem")
}

func TestTier1NoGraphFallsBackToScope(t *testing.T) {
	analyzer := NewAnalyzer(Options{Profile: ProfileProd})
	out, err := analyzer.Analyze(context.Background(), scanCtx(t.TempDir()), []engine.Finding{
		baseFinding("pkg:pypi/requests@2.31.0", "required"),
		baseFinding("pkg:pypi/pytest@8.0.0", "test"),
	})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	assertStatus(t, out[0], string(ReachableTrue), "direct runtime dependency")
	assertStatus(t, out[1], string(ReachableFalse), "test dependency")
}

func scanCtx(target string) engine.ScanContext {
	return engine.ScanContext{
		Target:      engine.TargetDescriptor{Type: engine.TargetTypeFS, Path: target},
		RequestedAt: time.Now().UTC(),
	}
}

func writeSampleLockfile(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(samplePackageLock), 0o600); err != nil {
		t.Fatalf("write sample package-lock: %v", err)
	}
	return target
}

func baseFinding(purl string, scope string) engine.Finding {
	return engine.Finding{
		VulnID:           "OSV-TEST-0001",
		PackagePURL:      purl,
		InstalledVersion: "1.0.0",
		Severity:         "high",
		Scope:            scope,
		Locations:        []engine.Location{{Path: "package-lock.json", Line: 1, Column: 1}},
	}
}

func assertStatus(t *testing.T, finding engine.Finding, wantStatus string, reasonContains string) {
	t.Helper()
	if finding.Reachability.Tier1Status != wantStatus {
		t.Fatalf("expected status=%s got=%s for %s", wantStatus, finding.Reachability.Tier1Status, finding.PackagePURL)
	}
	if wantStatus == string(ReachableTrue) && !finding.Reachability.Tier1 {
		t.Fatalf("expected tier1 boolean true for %s", finding.PackagePURL)
	}
	if wantStatus != string(ReachableTrue) && finding.Reachability.Tier1 {
		t.Fatalf("expected tier1 boolean false for %s", finding.PackagePURL)
	}
	if !strings.Contains(strings.ToLower(finding.Reachability.Tier1Reason), strings.ToLower(reasonContains)) {
		t.Fatalf("expected reason to contain %q got %q", reasonContains, finding.Reachability.Tier1Reason)
	}
}
