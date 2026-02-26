package engine

import "context"

type TargetIngestor interface {
	Ingest(context.Context, ScanContext) (IngestedTarget, error)
}

type SBOMCataloger interface {
	Catalog(context.Context, ScanContext, IngestedTarget) ([]PackageRef, error)
}

type Matcher interface {
	Match(context.Context, ScanContext, []PackageRef) ([]Finding, error)
}

type ReachabilityAnalyzer interface {
	Name() string
	Analyze(context.Context, ScanContext, []Finding) ([]Finding, error)
}

type DeduplicatorFingerprinter interface {
	DeduplicateAndFingerprint(context.Context, ScanContext, []Finding) ([]Finding, error)
}

type Renderer interface {
	RenderSARIF(context.Context, ScanContext, []Finding, GateDecision) ([]byte, error)
}

type PolicyEngine interface {
	Decide(context.Context, ScanContext, []Finding) (GateDecision, error)
}
