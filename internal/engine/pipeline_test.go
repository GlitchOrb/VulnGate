package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type stubIngestor struct {
	out IngestedTarget
	err error
}

func (s stubIngestor) Ingest(_ context.Context, _ ScanContext) (IngestedTarget, error) {
	if s.err != nil {
		return IngestedTarget{}, s.err
	}
	return s.out, nil
}

type stubCataloger struct {
	out []PackageRef
	err error
}

func (s stubCataloger) Catalog(_ context.Context, _ ScanContext, _ IngestedTarget) ([]PackageRef, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

type stubMatcher struct {
	out []Finding
	err error
}

func (s stubMatcher) Match(_ context.Context, _ ScanContext, _ []PackageRef) ([]Finding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

type stubAnalyzer struct {
	name string
	err  error
}

func (s stubAnalyzer) Name() string {
	if s.name == "" {
		return "stub"
	}
	return s.name
}

func (s stubAnalyzer) Analyze(_ context.Context, _ ScanContext, findings []Finding) ([]Finding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return findings, nil
}

type stubDeduper struct {
	err error
}

func (s stubDeduper) DeduplicateAndFingerprint(_ context.Context, _ ScanContext, findings []Finding) ([]Finding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return findings, nil
}

type stubRenderer struct {
	err error
}

func (s stubRenderer) RenderSARIF(_ context.Context, _ ScanContext, _ []Finding, _ GateDecision) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []byte(`{"version":"2.1.0","runs":[]}`), nil
}

type stubPolicy struct {
	err error
}

func (s stubPolicy) Decide(_ context.Context, _ ScanContext, _ []Finding) (GateDecision, error) {
	if s.err != nil {
		return GateDecision{}, s.err
	}
	return GateDecision{Fail: false, Reason: "ok", Violations: 0}, nil
}

func baseConfig() PipelineConfig {
	return PipelineConfig{
		TargetIngestor: stubIngestor{out: IngestedTarget{Type: TargetTypeFS, Path: "/tmp"}},
		SBOMCataloger: stubCataloger{out: []PackageRef{{
			PURL:             "pkg:generic/example@1.0.0",
			InstalledVersion: "1.0.0",
		}}},
		Matcher: stubMatcher{out: []Finding{{
			VulnID:           "OSV-123",
			PackagePURL:      "pkg:generic/example@1.0.0",
			InstalledVersion: "1.0.0",
			Severity:         "low",
		}}},
		ReachabilityAnalyzers: []ReachabilityAnalyzer{stubAnalyzer{name: "tier1"}},
		Deduplicator:          stubDeduper{},
		Renderer:              stubRenderer{},
		PolicyEngine:          stubPolicy{},
	}
}

func TestNewPipelineContracts(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PipelineConfig)
		wantErr string
	}{
		{
			name: "missing target ingestor",
			mutate: func(cfg *PipelineConfig) {
				cfg.TargetIngestor = nil
			},
			wantErr: "target ingestor is required",
		},
		{
			name: "missing sbom cataloger",
			mutate: func(cfg *PipelineConfig) {
				cfg.SBOMCataloger = nil
			},
			wantErr: "sbom cataloger is required",
		},
		{
			name: "missing matcher",
			mutate: func(cfg *PipelineConfig) {
				cfg.Matcher = nil
			},
			wantErr: "matcher is required",
		},
		{
			name: "missing reachability analyzer",
			mutate: func(cfg *PipelineConfig) {
				cfg.ReachabilityAnalyzers = nil
			},
			wantErr: "at least one reachability analyzer is required",
		},
		{
			name: "missing deduplicator",
			mutate: func(cfg *PipelineConfig) {
				cfg.Deduplicator = nil
			},
			wantErr: "deduplicator/fingerprinter is required",
		},
		{
			name: "missing renderer",
			mutate: func(cfg *PipelineConfig) {
				cfg.Renderer = nil
			},
			wantErr: "renderer is required",
		},
		{
			name: "missing policy engine",
			mutate: func(cfg *PipelineConfig) {
				cfg.PolicyEngine = nil
			},
			wantErr: "policy engine is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			tt.mutate(&cfg)

			_, err := NewPipeline(cfg)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestRunStageErrorBoundaries(t *testing.T) {
	sentinel := errors.New("boom")

	tests := []struct {
		name      string
		mutate    func(*PipelineConfig)
		wantStage string
	}{
		{
			name: "target ingest failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.TargetIngestor = stubIngestor{err: sentinel}
			},
			wantStage: stageTargetIngest,
		},
		{
			name: "sbom catalog failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.SBOMCataloger = stubCataloger{err: sentinel}
			},
			wantStage: stageSBOMCatalog,
		},
		{
			name: "matcher failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.Matcher = stubMatcher{err: sentinel}
			},
			wantStage: stageMatcher,
		},
		{
			name: "reachability failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.ReachabilityAnalyzers = []ReachabilityAnalyzer{stubAnalyzer{name: "tier1", err: sentinel}}
			},
			wantStage: "reachability_tier1",
		},
		{
			name: "dedupe failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.Deduplicator = stubDeduper{err: sentinel}
			},
			wantStage: stageDeduplicate,
		},
		{
			name: "policy failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.PolicyEngine = stubPolicy{err: sentinel}
			},
			wantStage: stagePolicy,
		},
		{
			name: "renderer failure",
			mutate: func(cfg *PipelineConfig) {
				cfg.Renderer = stubRenderer{err: sentinel}
			},
			wantStage: stageRenderer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			tt.mutate(&cfg)

			pipeline, err := NewPipeline(cfg)
			if err != nil {
				t.Fatalf("unexpected config error: %v", err)
			}

			_, err = pipeline.Run(context.Background(), ScanContext{
				Target:      TargetDescriptor{Type: TargetTypeFS, Path: "/tmp"},
				RequestedAt: time.Now().UTC(),
			})
			if err == nil {
				t.Fatalf("expected stage error")
			}

			var stageErr StageError
			if !errors.As(err, &stageErr) {
				t.Fatalf("expected StageError, got %T", err)
			}
			if stageErr.Stage != tt.wantStage {
				t.Fatalf("expected stage %q, got %q", tt.wantStage, stageErr.Stage)
			}
		})
	}
}

func TestDummyPipelineRunProducesValidSARIF(t *testing.T) {
	stderr := bytes.Buffer{}
	SetLogOutput(&stderr)
	SetDebugLogging(true)
	defer SetLogOutput(nil)
	defer SetDebugLogging(false)

	pipeline, err := NewDefaultPipeline()
	if err != nil {
		t.Fatalf("NewDefaultPipeline returned error: %v", err)
	}

	targetPath := t.TempDir()
	result, err := pipeline.Run(context.Background(), ScanContext{
		Repo: RepoMetadata{Commit: "abc123", Branch: "main"},
		Target: TargetDescriptor{
			Type: TargetTypeFS,
			Path: targetPath,
		},
		RequestedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !json.Valid(result.SARIF) {
		t.Fatalf("result SARIF is not valid JSON: %s", string(result.SARIF))
	}

	var payload map[string]any
	if err := json.Unmarshal(result.SARIF, &payload); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}
	if payload["version"] != "2.1.0" {
		t.Fatalf("unexpected sarif version: %v", payload["version"])
	}

	if !strings.Contains(stderr.String(), "DEBUG") {
		t.Fatalf("expected debug logs on stderr, got: %q", stderr.String())
	}
}
