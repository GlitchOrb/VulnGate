package runtimeebpf

import (
	"context"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return "tier2r-runtime-ebpf"
}

func (a *Analyzer) Annotate(_ context.Context, _ model.ScanRequest, findings []model.Finding) ([]model.Finding, error) {
	return findings, nil
}
