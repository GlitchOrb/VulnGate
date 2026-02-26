package engine

import (
	"testing"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

func TestEvaluatePolicyReachableMode(t *testing.T) {
	cfg := model.PolicyConfig{
		MinSeverity:         model.SeverityHigh,
		ReachabilityMode:    model.ReachabilityReachable,
		MinReachabilityTier: model.Tier1Dependency,
	}

	findings := []model.Finding{
		{
			Vulnerability: model.Vulnerability{ID: "V1", Severity: model.SeverityHigh},
			Reachability:  model.Tier0None,
		},
		{
			Vulnerability: model.Vulnerability{ID: "V2", Severity: model.SeverityHigh},
			Reachability:  model.Tier2Static,
		},
	}

	decision := EvaluatePolicy(cfg, findings)
	if !decision.Fail {
		t.Fatalf("expected policy to fail")
	}
	if len(decision.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(decision.Violations))
	}
	if decision.Violations[0].Vulnerability.ID != "V2" {
		t.Fatalf("unexpected violating vulnerability: %s", decision.Violations[0].Vulnerability.ID)
	}
}
