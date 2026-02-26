package dependency

import (
	"context"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return "tier1-dependency"
}

func (a *Analyzer) Annotate(_ context.Context, _ model.ScanRequest, findings []model.Finding) ([]model.Finding, error) {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if !model.ReachabilityAtLeast(out[i].Reachability, model.Tier1Dependency) {
			out[i].Reachability = model.Tier1Dependency
		}
	}
	return out, nil
}
