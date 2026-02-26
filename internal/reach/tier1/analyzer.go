package tier1

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

type Options struct {
	Profile Profile
}

type Analyzer struct {
	profile Profile
}

func NewAnalyzer(opts Options) Analyzer {
	profile := opts.Profile
	if profile != ProfileProd && profile != ProfileDev {
		profile = ProfileProd
	}
	return Analyzer{profile: profile}
}

func (a Analyzer) Name() string {
	return "tier1"
}

func (a Analyzer) Analyze(ctx context.Context, scanCtx engine.ScanContext, findings []engine.Finding) ([]engine.Finding, error) {
	if len(findings) == 0 {
		return []engine.Finding{}, nil
	}

	out := make([]engine.Finding, len(findings))
	copy(out, findings)

	if scanCtx.Target.Type != engine.TargetTypeFS {
		for i := range out {
			applyTier1(&out[i], Result{Reachable: ReachableUnknown, Reason: "dependency graph unavailable for non-filesystem target"})
		}
		return out, nil
	}

	absTarget, err := filepath.Abs(scanCtx.Target.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve target path: %w", err)
	}

	index := newGraphIndex()
	if err := index.load(ctx, absTarget, a.profile); err != nil {
		return nil, err
	}

	for i := range out {
		result := classifyFinding(out[i], index, a.profile)
		applyTier1(&out[i], result)
	}
	return out, nil
}

func classifyFinding(finding engine.Finding, index graphIndex, profile Profile) Result {
	scope := strings.ToLower(strings.TrimSpace(finding.Scope))
	switch scope {
	case "dev":
		if profile == ProfileProd {
			return Result{Reachable: ReachableFalse, Reason: "only devDependency"}
		}
	case "test":
		if profile == ProfileProd {
			return Result{Reachable: ReachableFalse, Reason: "only test dependency"}
		}
	}

	coord, err := parsePURL(finding.PackagePURL)
	if err != nil {
		if profile == ProfileDev && (scope == "dev" || scope == "test") {
			return Result{Reachable: ReachableTrue, Reason: "included in dev dependency closure"}
		}
		return Result{Reachable: ReachableUnknown, Reason: "unable to parse package PURL"}
	}

	if index.hasEcosystem(coord.Ecosystem) {
		if index.runtimeContains(coord) {
			reason := "included in runtime dependency closure"
			if profile == ProfileDev && (scope == "dev" || scope == "test") {
				reason = "included in dev dependency closure"
			}
			return Result{Reachable: ReachableTrue, Reason: reason}
		}
		if index.allContains(coord) {
			if scope == "dev" && profile == ProfileProd {
				return Result{Reachable: ReachableFalse, Reason: "only devDependency"}
			}
			return Result{Reachable: ReachableFalse, Reason: "not in runtime dependency closure"}
		}
		return Result{Reachable: ReachableUnknown, Reason: "package not present in dependency graph"}
	}

	if profile == ProfileDev && (scope == "dev" || scope == "test") {
		return Result{Reachable: ReachableTrue, Reason: "included in dev dependency closure"}
	}

	if scope == "required" {
		return Result{Reachable: ReachableTrue, Reason: "direct runtime dependency (graph unavailable for ecosystem)"}
	}
	if scope == "transitive" || scope == "optional" {
		return Result{Reachable: ReachableUnknown, Reason: "dependency graph unavailable for ecosystem"}
	}

	return Result{Reachable: ReachableUnknown, Reason: "dependency graph unavailable"}
}

func applyTier1(finding *engine.Finding, result Result) {
	if finding == nil {
		return
	}
	status := string(result.Reachable)
	if status == "" {
		status = string(ReachableUnknown)
	}

	finding.Reachability.Tier1Status = status
	finding.Reachability.Tier1Reason = strings.TrimSpace(result.Reason)
	finding.Reachability.Tier1 = status == string(ReachableTrue)
}
