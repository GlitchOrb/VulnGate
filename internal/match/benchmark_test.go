package match

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	dbpkg "github.com/GlitchOrb/vulngate/internal/db"
)

func BenchmarkMatch10kComponents(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "vulngate.db")
	store, err := dbpkg.Open(dbPath)
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	defer store.Close()

	osvDir := filepath.Join("..", "db", "testdata", "osv")
	if _, err := store.ImportOSVDir(context.Background(), osvDir); err != nil {
		b.Fatalf("import osv: %v", err)
	}

	components := buildBenchmarkComponents(10000)

	cases := []struct {
		name string
		opts EngineOptions
	}{
		{
			name: "sequential-no-cache",
			opts: EngineOptions{WorkerCount: 1, EnableCache: false},
		},
		{
			name: "parallel-with-cache",
			opts: EngineOptions{
				WorkerCount: min(runtime.NumCPU(), 8),
				EnableCache: true,
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			engine, err := NewEngineWithOptions(store.DB(), tc.opts)
			if err != nil {
				b.Fatalf("new engine: %v", err)
			}
			defer engine.Close()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				findings, err := engine.MatchComponents(context.Background(), components)
				if err != nil {
					b.Fatalf("MatchComponents failed: %v", err)
				}
				if len(findings) == 0 {
					b.Fatalf("expected findings for benchmark dataset")
				}
			}
			b.ReportMetric(float64(len(components)*b.N)/b.Elapsed().Seconds(), "components/s")
		})
	}
}

func buildBenchmarkComponents(n int) []Component {
	components := make([]Component, 0, n)
	for i := 0; i < n; i++ {
		switch i % 5 {
		case 0:
			components = append(components, Component{PURL: "pkg:npm/left-pad@1.3.0", Version: "1.3.0"})
		case 1:
			components = append(components, Component{PURL: "pkg:pypi/requests@2.31.0", Version: "2.31.0"})
		case 2:
			components = append(components, Component{PURL: "pkg:golang/github.com/google/uuid@1.6.0", Version: "1.6.0"})
		default:
			components = append(components, Component{PURL: fmt.Sprintf("pkg:npm/nonmatch-%d@1.0.0", i), Version: "1.0.0"})
		}
	}
	return components
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
