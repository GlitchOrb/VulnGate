package engine

import (
	"fmt"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

func EvaluatePolicy(cfg model.PolicyConfig, findings []model.Finding) model.PolicyDecision {
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = model.SeverityHigh
	}
	if cfg.ReachabilityMode == "" {
		cfg.ReachabilityMode = model.ReachabilityReachable
	}
	if cfg.MinReachabilityTier == "" {
		cfg.MinReachabilityTier = model.Tier1Dependency
	}

	violations := make([]model.Finding, 0)
	for _, finding := range findings {
		if !model.SeverityAtLeast(finding.Vulnerability.Severity, cfg.MinSeverity) {
			continue
		}

		switch cfg.ReachabilityMode {
		case model.ReachabilityAny:
			violations = append(violations, finding)
		case model.ReachabilityReachable:
			if model.ReachabilityAtLeast(finding.Reachability, cfg.MinReachabilityTier) {
				violations = append(violations, finding)
			}
		}
	}

	if len(violations) == 0 {
		return model.PolicyDecision{Fail: false, Reason: "policy passed"}
	}

	reason := fmt.Sprintf(
		"policy failed: %d violation(s) at severity >= %s with reachability mode %s",
		len(violations),
		cfg.MinSeverity,
		cfg.ReachabilityMode,
	)
	return model.PolicyDecision{Fail: true, Reason: reason, Violations: violations}
}
