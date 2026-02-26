package catalog

import (
	"context"
	"path/filepath"
	"testing"
)

func BenchmarkBuildStressFixture(b *testing.B) {
	fixture := filepath.Join("..", "..", "tests", "stress", "large-repo")

	b.Run("no-cache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			report, err := Build(context.Background(), BuildOptions{
				TargetPath:   fixture,
				DisableCache: true,
			})
			if err != nil {
				b.Fatalf("Build failed: %v", err)
			}
			if report.Summary.TotalComponents == 0 {
				b.Fatalf("expected components in stress fixture")
			}
		}
	})

	b.Run("cache-hit", func(b *testing.B) {
		cacheDir := filepath.Join(b.TempDir(), "catalog-cache")
		if _, err := Build(context.Background(), BuildOptions{
			TargetPath: fixture,
			CacheDir:   cacheDir,
		}); err != nil {
			b.Fatalf("warm cache build failed: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			report, err := Build(context.Background(), BuildOptions{
				TargetPath: fixture,
				CacheDir:   cacheDir,
			})
			if err != nil {
				b.Fatalf("cached Build failed: %v", err)
			}
			if report.Cache == nil || !report.Cache.Hit {
				b.Fatalf("expected cache hit")
			}
		}
	})
}
