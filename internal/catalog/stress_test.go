package catalog

import (
	"context"
	"path/filepath"
	"testing"
)

func TestBuildStressFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "stress", "large-repo")
	report, err := Build(context.Background(), BuildOptions{
		TargetPath: fixture,
		CacheDir:   filepath.Join(t.TempDir(), "catalog-cache"),
	})
	if err != nil {
		t.Fatalf("Build failed for stress fixture: %v", err)
	}
	if report.Summary.TotalComponents < 500 {
		t.Fatalf("expected large component set, got %d", report.Summary.TotalComponents)
	}
}
