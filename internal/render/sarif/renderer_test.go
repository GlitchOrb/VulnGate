package sarif

import (
	"encoding/json"
	"testing"
)

func TestRendererSchemaShapeAndMappings(t *testing.T) {
	renderer := New("VulnGate", "test")

	findings := []Finding{
		{
			VulnID:           "OSV-2026-1000",
			PackagePURL:      "pkg:npm/left-pad@1.3.0",
			InstalledVersion: "1.3.0",
			Severity:         "high",
			Tier1Status:      "true",
			Tier1Reason:      "included in runtime dependency closure",
			Tier2Status:      "false",
			Tier2Reason:      "not reachable from discovered entrypoints",
			Tier2Evidence:    "main.main",
			RuntimeStatus:    "true",
			RuntimeReason:    "runtime profile observed runtime calls (exact package version match)",
			RuntimeSymbols:   []string{"main.main:11"},
			RuntimeCallCount: 11,
			RuntimeFirstSeen: "2026-02-20T10:00:00Z",
			RuntimeLastSeen:  "2026-02-20T10:05:00Z",
			References:       []string{"https://example.com/advisory"},
			Locations: []Location{
				{Path: "src/main.go", Line: 12, Column: 2},
				{Path: "package-lock.json", Line: 5, Column: 1},
			},
		},
		{
			VulnID:           "OSV-2026-1000",
			PackagePURL:      "pkg:npm/left-pad@1.3.0",
			InstalledVersion: "1.3.0",
			Severity:         "high",
			Locations: []Location{
				{Path: "lib/feature.go", Line: 20, Column: 4},
			},
		},
	}

	payload, err := renderer.Render(Context{
		TargetPath: ".",
		RunProperties: map[string]any{
			"toolCommit":      "abc123",
			"dbSchemaVersion": 1,
		},
	}, findings, Decision{Fail: true, Reason: "policy", Violations: 1})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}

	if doc["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", doc["version"])
	}
	if doc["$schema"] != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Fatalf("unexpected schema URL: %v", doc["$schema"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one SARIF run")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid run object")
	}
	runProps, ok := run["properties"].(map[string]any)
	if !ok {
		t.Fatalf("run properties missing")
	}
	if runProps["toolCommit"] != "abc123" {
		t.Fatalf("unexpected run property toolCommit: %v", runProps["toolCommit"])
	}

	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results missing or invalid")
	}
	if len(results) != 1 {
		t.Fatalf("expected deduplicated single result, got %d", len(results))
	}

	result := results[0].(map[string]any)
	if result["ruleId"] != "OSV-2026-1000" {
		t.Fatalf("unexpected ruleId: %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Fatalf("expected severity high -> error level, got %v", result["level"])
	}

	locations, ok := result["locations"].([]any)
	if !ok || len(locations) != 3 {
		t.Fatalf("expected 3 merged locations, got %v", len(locations))
	}

	foundRegion := false
	for _, item := range locations {
		loc := item.(map[string]any)
		pl := loc["physicalLocation"].(map[string]any)
		if _, ok := pl["region"]; ok {
			foundRegion = true
			break
		}
	}
	if !foundRegion {
		t.Fatalf("expected region mapping in at least one location")
	}

	pf, ok := result["partialFingerprints"].(map[string]any)
	if !ok {
		t.Fatalf("missing partialFingerprints")
	}
	contextHash, ok := pf["contextHash"].(string)
	if !ok || len(contextHash) != 64 {
		t.Fatalf("expected 64-char context hash, got %v", pf["contextHash"])
	}

	props, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("missing properties object")
	}
	if props["tier2Reachable"] != "false" {
		t.Fatalf("expected tier2Reachable property false, got %v", props["tier2Reachable"])
	}
	if props["tier2Reason"] != "not reachable from discovered entrypoints" {
		t.Fatalf("unexpected tier2Reason: %v", props["tier2Reason"])
	}
	if props["reachable_runtime"] != true {
		t.Fatalf("expected reachable_runtime true, got %v", props["reachable_runtime"])
	}
	if props["runtimeCallCount"] != float64(11) {
		t.Fatalf("expected runtimeCallCount 11, got %v", props["runtimeCallCount"])
	}
}

func TestFingerprintsStableAcrossRuns(t *testing.T) {
	renderer := New("VulnGate", "test")
	ctx := Context{TargetPath: "."}
	decision := Decision{Fail: false, Reason: "ok", Violations: 0}

	findingsA := []Finding{{
		VulnID:           "OSV-2026-2000",
		PackagePURL:      "pkg:pypi/requests@2.31.0",
		InstalledVersion: "2.31.0",
		Severity:         "medium",
		Locations: []Location{
			{Path: "poetry.lock", Line: 10, Column: 1},
			{Path: "src/app.py", Line: 44, Column: 2},
		},
	}}
	findingsB := []Finding{{
		VulnID:           "OSV-2026-2000",
		PackagePURL:      "pkg:pypi/requests@2.31.0",
		InstalledVersion: "2.31.0",
		Severity:         "medium",
		Locations: []Location{
			{Path: "src/app.py", Line: 44, Column: 2},
			{Path: "poetry.lock", Line: 10, Column: 1},
		},
	}}

	payloadA, err := renderer.Render(ctx, findingsA, decision)
	if err != nil {
		t.Fatalf("Render A failed: %v", err)
	}
	payloadB, err := renderer.Render(ctx, findingsB, decision)
	if err != nil {
		t.Fatalf("Render B failed: %v", err)
	}

	hashA := extractContextHash(t, payloadA)
	hashB := extractContextHash(t, payloadB)
	if hashA != hashB {
		t.Fatalf("expected identical context hash across runs, got %s vs %s", hashA, hashB)
	}
}

func extractContextHash(t *testing.T, payload []byte) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	result := results[0].(map[string]any)
	pf := result["partialFingerprints"].(map[string]any)
	return pf["contextHash"].(string)
}
