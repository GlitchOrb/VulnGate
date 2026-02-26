package localllm

import (
	"context"
	"fmt"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type CandidatePatch struct {
	FilePath string
	Diff     string
	Reason   string
}

type Module struct {
	ModelPath string
}

func New(modelPath string) *Module {
	return &Module{ModelPath: modelPath}
}

func (m *Module) DetectRepairValidate(_ context.Context, findings []model.Finding) ([]CandidatePatch, error) {
	if len(findings) == 0 {
		return []CandidatePatch{}, nil
	}

	patches := make([]CandidatePatch, 0, len(findings))
	for _, f := range findings {
		patches = append(patches, CandidatePatch{
			FilePath: "",
			Diff:     "",
			Reason:   fmt.Sprintf("candidate fix for %s (%s)", f.Vulnerability.ID, f.Dependency.PURL),
		})
	}
	return patches, nil
}
