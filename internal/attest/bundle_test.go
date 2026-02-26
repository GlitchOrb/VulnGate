package attest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbpkg "github.com/GlitchOrb/vulngate/internal/db"
)

func TestBuildBundleNoSigner(t *testing.T) {
	prov := Provenance{
		Tool: ToolMetadata{Name: "VulnGate", Version: "test"},
	}

	bundle, err := BuildBundle(context.Background(), BundleOptions{
		Provenance: prov,
		Signing:    SignConfig{Mode: "none"},
		Artifacts: []ArtifactInput{
			{
				Name:    "scan.sarif",
				Kind:    "sarif",
				Content: []byte(`{"version":"2.1.0"}`),
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildBundle returned error: %v", err)
	}
	if bundle.Schema != BundleSchema {
		t.Fatalf("unexpected bundle schema: %s", bundle.Schema)
	}
	if len(bundle.Artifacts) != 1 {
		t.Fatalf("expected one artifact, got %d", len(bundle.Artifacts))
	}
	if bundle.Artifacts[0].SHA256 == "" {
		t.Fatalf("expected artifact digest")
	}
	if bundle.Artifacts[0].Signed {
		t.Fatalf("artifact should not be signed in none mode")
	}
}

func TestBuildBundleWithMockSigner(t *testing.T) {
	bundle, err := BuildBundle(context.Background(), BundleOptions{
		Provenance: Provenance{Tool: ToolMetadata{Name: "VulnGate", Version: "test"}},
		Signing:    SignConfig{Mode: "cosign"},
		Signer: mockSigner{
			result: SignResult{Signature: "sig", Certificate: "cert", Bundle: "{}"},
		},
		Artifacts: []ArtifactInput{
			{Name: "sbom.json", Kind: "sbom", Content: []byte(`{"schema":"v1"}`)},
		},
	})
	if err != nil {
		t.Fatalf("BuildBundle returned error: %v", err)
	}
	if !bundle.Artifacts[0].Signed {
		t.Fatalf("expected signed artifact")
	}
	if bundle.Artifacts[0].Signer != "mock" {
		t.Fatalf("unexpected signer name: %s", bundle.Artifacts[0].Signer)
	}
	if bundle.Artifacts[0].Signature.Signature != "sig" {
		t.Fatalf("unexpected signature value")
	}
}

func TestProbeDatabaseReportsSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	store, err := dbpkg.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("init db: %v", err)
	}

	meta := ProbeDatabase(context.Background(), dbPath)
	if meta.Status != "present" {
		t.Fatalf("expected present database status, got %s (err=%s)", meta.Status, meta.Error)
	}
	if meta.SchemaVersion <= 0 {
		t.Fatalf("expected positive schema version, got %d", meta.SchemaVersion)
	}
}

func TestWriteBundleProducesJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "attest.json")
	bundle := Bundle{
		Schema:      BundleSchema,
		GeneratedAt: mustTime(t, "2026-02-26T00:00:00Z"),
		Provenance: Provenance{
			Tool: ToolMetadata{Name: "VulnGate", Version: "test"},
		},
		Artifacts: []ArtifactRecord{{Name: "artifact", Kind: "generic", SHA256: "abc", Size: 3}},
	}
	if err := WriteBundle(out, bundle); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle file: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("bundle is not valid json: %s", string(raw))
	}
	if !strings.Contains(string(raw), BundleSchema) {
		t.Fatalf("missing schema marker in bundle json")
	}
}

type mockSigner struct {
	result SignResult
	err    error
}

func (m mockSigner) Name() string {
	return "mock"
}

func (m mockSigner) Sign(_ context.Context, _ string, _ SignConfig) (SignResult, error) {
	return m.result, m.err
}

func mustTime(t *testing.T, raw string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return v
}
