package sarif

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

func TestRendererOutputsSarif210(t *testing.T) {
	r := New()
	buf := bytes.Buffer{}
	err := r.Render(&buf, model.Report{
		ToolVersion: "test",
		Project:     "example",
		GeneratedAt: time.Now(),
		Findings: []model.Finding{{
			Vulnerability: model.Vulnerability{ID: "OSV-1", Summary: "demo", Severity: model.SeverityHigh},
			Dependency:    model.Dependency{PURL: "pkg:golang/github.com/foo/bar@1.0.0"},
			Reachability:  model.Tier1Dependency,
			Scanner:       "localdb-sca",
			Message:       "demo message",
		}},
		PolicyDecision: model.PolicyDecision{Fail: false, Reason: "policy passed"},
	})
	if err != nil {
		t.Fatalf("render returned error: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}
	if out["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", out["version"])
	}
}
