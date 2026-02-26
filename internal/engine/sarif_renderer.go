package engine

import (
	"context"
	"runtime"
	"strings"

	"github.com/GlitchOrb/vulngate/internal/buildinfo"
	rendersarif "github.com/GlitchOrb/vulngate/internal/render/sarif"
)

type SARIFRenderer struct {
	core *rendersarif.Renderer
}

func NewSARIFRenderer(toolName string) SARIFRenderer {
	name := strings.TrimSpace(toolName)
	if name == "" {
		name = "VulnGate"
	}
	return SARIFRenderer{core: rendersarif.New(name, buildinfo.Version)}
}

func (r SARIFRenderer) RenderSARIF(_ context.Context, scanCtx ScanContext, findings []Finding, decision GateDecision) ([]byte, error) {
	mapped := make([]rendersarif.Finding, 0, len(findings))
	for _, f := range findings {
		locations := make([]rendersarif.Location, 0, len(f.Locations))
		for _, loc := range f.Locations {
			locations = append(locations, rendersarif.Location{
				Path:   loc.Path,
				Line:   loc.Line,
				Column: loc.Column,
			})
		}
		mapped = append(mapped, rendersarif.Finding{
			VulnID:           f.VulnID,
			PackagePURL:      f.PackagePURL,
			InstalledVersion: f.InstalledVersion,
			FixedVersion:     f.FixedVersion,
			Severity:         f.Severity,
			Tier1Status:      f.Reachability.Tier1Status,
			Tier1Reason:      f.Reachability.Tier1Reason,
			Tier2Status:      f.Reachability.Tier2Status,
			Tier2Reason:      f.Reachability.Tier2Reason,
			Tier2Evidence:    f.Reachability.Tier2Evidence,
			RuntimeStatus:    f.Reachability.RuntimeStatus,
			RuntimeReason:    f.Reachability.RuntimeReason,
			RuntimeSymbols:   append([]string{}, f.Reachability.RuntimeSymbols...),
			RuntimeCallCount: f.Reachability.RuntimeCallCount,
			RuntimeFirstSeen: f.Reachability.RuntimeFirstSeen,
			RuntimeLastSeen:  f.Reachability.RuntimeLastSeen,
			References:       append([]string{}, f.References...),
			Locations:        locations,
		})
	}

	return r.core.Render(
		rendersarif.Context{
			TargetPath:    scanCtx.Target.Path,
			RunProperties: buildRunProperties(scanCtx),
		},
		mapped,
		rendersarif.Decision{Fail: decision.Fail, Reason: decision.Reason, Violations: decision.Violations},
	)
}

func buildRunProperties(scanCtx ScanContext) map[string]any {
	props := map[string]any{
		"toolVersion": buildinfo.Version,
		"toolCommit":  buildinfo.Commit,
		"toolDate":    buildinfo.Date,
		"goos":        runtime.GOOS,
		"goarch":      runtime.GOARCH,
		"gitCommit":   strings.TrimSpace(scanCtx.Repo.Commit),
		"gitBranch":   strings.TrimSpace(scanCtx.Repo.Branch),
		"ciProvider":  strings.TrimSpace(scanCtx.CI.Provider),
		"pipelineID":  strings.TrimSpace(scanCtx.CI.PipelineID),
		"jobID":       strings.TrimSpace(scanCtx.CI.JobID),
	}
	for k, v := range scanCtx.Provenance {
		if strings.TrimSpace(k) == "" {
			continue
		}
		props[k] = v
	}
	return props
}
