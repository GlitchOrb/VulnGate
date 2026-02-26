package engine

import (
	"context"
	"fmt"
	"io"
	"log"
	"sort"
	"time"

	"github.com/GlitchOrb/vulngate/internal/buildinfo"
	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Scanner interface {
	Name() string
	Scan(context.Context, model.ScanRequest) ([]model.Finding, error)
}

type ReachabilityAnalyzer interface {
	Name() string
	Annotate(context.Context, model.ScanRequest, []model.Finding) ([]model.Finding, error)
}

type Renderer interface {
	Name() string
	Render(io.Writer, model.Report) error
}

type Engine struct {
	logger    *log.Logger
	policy    model.PolicyConfig
	scanners  map[string]Scanner
	renderers map[string]Renderer
	analyzers []ReachabilityAnalyzer
}

func New(logger *log.Logger, policy model.PolicyConfig) *Engine {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Engine{
		logger:    logger,
		policy:    policy,
		scanners:  map[string]Scanner{},
		renderers: map[string]Renderer{},
		analyzers: []ReachabilityAnalyzer{},
	}
}

func (e *Engine) RegisterScanner(s Scanner) error {
	if s == nil {
		return fmt.Errorf("scanner is nil")
	}
	name := s.Name()
	if name == "" {
		return fmt.Errorf("scanner name is empty")
	}
	if _, exists := e.scanners[name]; exists {
		return fmt.Errorf("scanner %q already registered", name)
	}
	e.scanners[name] = s
	return nil
}

func (e *Engine) RegisterReachabilityAnalyzer(a ReachabilityAnalyzer) error {
	if a == nil {
		return fmt.Errorf("reachability analyzer is nil")
	}
	name := a.Name()
	if name == "" {
		return fmt.Errorf("reachability analyzer name is empty")
	}
	for _, existing := range e.analyzers {
		if existing.Name() == name {
			return fmt.Errorf("reachability analyzer %q already registered", name)
		}
	}
	e.analyzers = append(e.analyzers, a)
	return nil
}

func (e *Engine) RegisterRenderer(r Renderer) error {
	if r == nil {
		return fmt.Errorf("renderer is nil")
	}
	name := r.Name()
	if name == "" {
		return fmt.Errorf("renderer name is empty")
	}
	if _, exists := e.renderers[name]; exists {
		return fmt.Errorf("renderer %q already registered", name)
	}
	e.renderers[name] = r
	return nil
}

func (e *Engine) Scan(ctx context.Context, req model.ScanRequest) (model.Report, error) {
	if len(e.scanners) == 0 {
		return model.Report{}, fmt.Errorf("no scanners registered")
	}

	names := make([]string, 0, len(e.scanners))
	for name := range e.scanners {
		names = append(names, name)
	}
	sort.Strings(names)

	allFindings := make([]model.Finding, 0)
	for _, name := range names {
		scanner := e.scanners[name]
		findings, err := scanner.Scan(ctx, req)
		if err != nil {
			return model.Report{}, fmt.Errorf("scanner %s failed: %w", name, err)
		}
		allFindings = append(allFindings, findings...)
	}

	for _, analyzer := range e.analyzers {
		annotated, err := analyzer.Annotate(ctx, req, allFindings)
		if err != nil {
			return model.Report{}, fmt.Errorf("reachability analyzer %s failed: %w", analyzer.Name(), err)
		}
		allFindings = annotated
	}

	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Vulnerability.ID != allFindings[j].Vulnerability.ID {
			return allFindings[i].Vulnerability.ID < allFindings[j].Vulnerability.ID
		}
		return allFindings[i].Dependency.PURL < allFindings[j].Dependency.PURL
	})

	report := model.Report{
		ToolVersion: buildinfo.Version,
		Project:     req.Project,
		GeneratedAt: time.Now().UTC(),
		Findings:    allFindings,
	}
	report.PolicyDecision = EvaluatePolicy(e.policy, report.Findings)
	return report, nil
}

func (e *Engine) Render(w io.Writer, format string, report model.Report) error {
	renderer, ok := e.renderers[format]
	if !ok {
		return fmt.Errorf("renderer %q is not registered", format)
	}
	return renderer.Render(w, report)
}
