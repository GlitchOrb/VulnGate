package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsWhenConfigMissing(t *testing.T) {
	target := t.TempDir()
	cfgPath := filepath.Join(target, ".vulngate.yml")

	cfg, loadedPath, err := Load(LoadOptions{Path: cfgPath, Required: false})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loadedPath != cfgPath {
		t.Fatalf("expected loaded path %q, got %q", cfgPath, loadedPath)
	}

	if len(cfg.FailOnSeverities) != 2 || cfg.FailOnSeverities[0] != "critical" || cfg.FailOnSeverities[1] != "high" {
		t.Fatalf("unexpected default fail severities: %#v", cfg.FailOnSeverities)
	}
}

func TestLoadWithPolicyKey(t *testing.T) {
	target := t.TempDir()
	cfgPath := filepath.Join(target, ".vulngate.yml")
	content := `policy:
  fail_on_severity: [HIGH]
  reachability:
    require_reachable_for_severities: [high]
  scope:
    production_mode: true
    ignore_dev_dependencies: true
    ignore_test_dependencies: true
  ignore:
    - vuln_id: OSV-2026-1000
      expires: 2030-01-01
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, _, err := Load(LoadOptions{Path: cfgPath, Required: true})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if len(cfg.FailOnSeverities) != 1 || cfg.FailOnSeverities[0] != "high" {
		t.Fatalf("unexpected fail severities: %#v", cfg.FailOnSeverities)
	}
	if !cfg.Scope.ProductionMode {
		t.Fatalf("expected production mode true")
	}
	if len(cfg.Ignore) != 1 || cfg.Ignore[0].VulnID != "OSV-2026-1000" {
		t.Fatalf("unexpected ignore rules: %#v", cfg.Ignore)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "invalid severity",
			content: `policy:
  fail_on_severity: [SEV0]
`,
			wantErr: "unsupported severity",
		},
		{
			name: "invalid ignore date",
			content: `policy:
  ignore:
    - vuln_id: OSV-1
      expires: 2099/01/01
`,
			wantErr: "unsupported date format",
		},
		{
			name: "empty ignore selector",
			content: `policy:
  ignore:
    - reason: temp
`,
			wantErr: "at least one selector is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := t.TempDir()
			cfgPath := filepath.Join(target, ".vulngate.yml")
			if err := os.WriteFile(cfgPath, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, _, err := Load(LoadOptions{Path: cfgPath, Required: true})
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestResolveDefaultPath(t *testing.T) {
	target := t.TempDir()
	path := ResolveDefaultPath(target)
	if path != filepath.Join(target, ".vulngate.yml") {
		t.Fatalf("unexpected default path for dir: %s", path)
	}

	fileTarget := filepath.Join(target, "manifest.sbom")
	if err := os.WriteFile(fileTarget, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file target: %v", err)
	}
	path = ResolveDefaultPath(fileTarget)
	if path != filepath.Join(target, ".vulngate.yml") {
		t.Fatalf("unexpected default path for file: %s", path)
	}
}
