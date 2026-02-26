package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

func TestAnalyzerTableDriven(t *testing.T) {
	profile := Profile{Events: []Event{
		{
			PURL:      "pkg:generic/vulngate/insecure@0.0.0",
			Symbol:    "main.main",
			Count:     5,
			FirstSeen: time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, 1, 2, 10, 10, 0, 0, time.UTC),
		},
		{
			PURL:      "pkg:generic/vulngate/insecure@0.1.0",
			Symbol:    "handler.process",
			Count:     3,
			FirstSeen: time.Date(2026, 1, 2, 10, 2, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, 1, 2, 10, 12, 0, 0, time.UTC),
		},
	}}
	analyzer := NewAnalyzer(Options{Profile: profile, Source: "imported-runtime-profile"})

	tests := []struct {
		name       string
		finding    engine.Finding
		wantStatus string
		wantReach  bool
		wantCount  uint64
	}{
		{
			name: "exact version match",
			finding: engine.Finding{
				PackagePURL: "pkg:generic/vulngate/insecure@0.0.0",
			},
			wantStatus: "true",
			wantReach:  true,
			wantCount:  5,
		},
		{
			name: "package coordinate fallback",
			finding: engine.Finding{
				PackagePURL: "pkg:generic/vulngate/insecure@9.9.9",
			},
			wantStatus: "true",
			wantReach:  true,
			wantCount:  8,
		},
		{
			name: "no runtime evidence",
			finding: engine.Finding{
				PackagePURL: "pkg:generic/vulngate/other@1.0.0",
			},
			wantStatus: "unknown",
			wantReach:  false,
			wantCount:  0,
		},
		{
			name: "invalid finding purl",
			finding: engine.Finding{
				PackagePURL: "bad-purl",
			},
			wantStatus: "unknown",
			wantReach:  false,
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := analyzer.Analyze(context.Background(), engine.ScanContext{}, []engine.Finding{tt.finding})
			if err != nil {
				t.Fatalf("Analyze returned error: %v", err)
			}
			if len(out) != 1 {
				t.Fatalf("expected one finding, got %d", len(out))
			}

			got := out[0]
			if got.Reachability.RuntimeStatus != tt.wantStatus {
				t.Fatalf("expected runtime status %q, got %q", tt.wantStatus, got.Reachability.RuntimeStatus)
			}
			if got.Reachability.Tier2Runtime != tt.wantReach {
				t.Fatalf("expected tier2Runtime=%t, got %t", tt.wantReach, got.Reachability.Tier2Runtime)
			}
			if got.Reachability.RuntimeCallCount != tt.wantCount {
				t.Fatalf("expected runtime call count %d, got %d", tt.wantCount, got.Reachability.RuntimeCallCount)
			}
		})
	}
}

func TestAnalyzerWithNoEvents(t *testing.T) {
	analyzer := NewAnalyzer(Options{Profile: Profile{Events: []Event{}}})
	out, err := analyzer.Analyze(context.Background(), engine.ScanContext{}, []engine.Finding{{PackagePURL: "pkg:npm/a@1.0.0"}})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if out[0].Reachability.RuntimeStatus != "unknown" {
		t.Fatalf("expected unknown status, got %q", out[0].Reachability.RuntimeStatus)
	}
	if out[0].Reachability.Tier2Runtime {
		t.Fatalf("expected tier2Runtime=false")
	}
}
