package engine

import (
	"context"
	"errors"
	"fmt"
)

const (
	stageTargetIngest = "target_ingest"
	stageSBOMCatalog  = "sbom_catalog"
	stageMatcher      = "matcher"
	stageDeduplicate  = "deduplicate_fingerprint"
	stagePolicy       = "policy_engine"
	stageRenderer     = "renderer_sarif"
)

type StageError struct {
	Stage string
	Err   error
}

func (e StageError) Error() string {
	return fmt.Sprintf("%s stage failed: %v", e.Stage, e.Err)
}

func (e StageError) Unwrap() error {
	return e.Err
}

type PipelineConfig struct {
	TargetIngestor        TargetIngestor
	SBOMCataloger         SBOMCataloger
	Matcher               Matcher
	ReachabilityAnalyzers []ReachabilityAnalyzer
	Deduplicator          DeduplicatorFingerprinter
	Renderer              Renderer
	PolicyEngine          PolicyEngine
}

type Pipeline struct {
	targetIngestor        TargetIngestor
	sbomCataloger         SBOMCataloger
	matcher               Matcher
	reachabilityAnalyzers []ReachabilityAnalyzer
	deduplicator          DeduplicatorFingerprinter
	renderer              Renderer
	policyEngine          PolicyEngine
}

func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	p := &Pipeline{
		targetIngestor:        cfg.TargetIngestor,
		sbomCataloger:         cfg.SBOMCataloger,
		matcher:               cfg.Matcher,
		reachabilityAnalyzers: cfg.ReachabilityAnalyzers,
		deduplicator:          cfg.Deduplicator,
		renderer:              cfg.Renderer,
		policyEngine:          cfg.PolicyEngine,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pipeline) Validate() error {
	switch {
	case p.targetIngestor == nil:
		return errors.New("target ingestor is required")
	case p.sbomCataloger == nil:
		return errors.New("sbom cataloger is required")
	case p.matcher == nil:
		return errors.New("matcher is required")
	case len(p.reachabilityAnalyzers) == 0:
		return errors.New("at least one reachability analyzer is required")
	case p.deduplicator == nil:
		return errors.New("deduplicator/fingerprinter is required")
	case p.renderer == nil:
		return errors.New("renderer is required")
	case p.policyEngine == nil:
		return errors.New("policy engine is required")
	default:
		return nil
	}
}

func (p *Pipeline) Run(ctx context.Context, scanCtx ScanContext) (RunResult, error) {
	if err := p.Validate(); err != nil {
		return RunResult{}, err
	}

	Debugf("pipeline start target=%s type=%s branch=%s commit=%s", scanCtx.Target.Path, scanCtx.Target.Type, scanCtx.Repo.Branch, scanCtx.Repo.Commit)

	ingestedTarget, err := p.targetIngestor.Ingest(ctx, scanCtx)
	if err != nil {
		return RunResult{}, StageError{Stage: stageTargetIngest, Err: err}
	}

	packages, err := p.sbomCataloger.Catalog(ctx, scanCtx, ingestedTarget)
	if err != nil {
		return RunResult{}, StageError{Stage: stageSBOMCatalog, Err: err}
	}

	findings, err := p.matcher.Match(ctx, scanCtx, packages)
	if err != nil {
		return RunResult{}, StageError{Stage: stageMatcher, Err: err}
	}

	for _, analyzer := range p.reachabilityAnalyzers {
		stage := "reachability_" + analyzer.Name()
		findings, err = analyzer.Analyze(ctx, scanCtx, findings)
		if err != nil {
			return RunResult{}, StageError{Stage: stage, Err: err}
		}
	}

	findings, err = p.deduplicator.DeduplicateAndFingerprint(ctx, scanCtx, findings)
	if err != nil {
		return RunResult{}, StageError{Stage: stageDeduplicate, Err: err}
	}

	decision, err := p.policyEngine.Decide(ctx, scanCtx, findings)
	if err != nil {
		return RunResult{}, StageError{Stage: stagePolicy, Err: err}
	}

	sarifBytes, err := p.renderer.RenderSARIF(ctx, scanCtx, findings, decision)
	if err != nil {
		return RunResult{}, StageError{Stage: stageRenderer, Err: err}
	}

	Debugf("pipeline complete findings=%d gate_fail=%t", len(findings), decision.Fail)

	return RunResult{
		Context:  scanCtx,
		Findings: findings,
		Decision: decision,
		SARIF:    sarifBytes,
	}, nil
}
