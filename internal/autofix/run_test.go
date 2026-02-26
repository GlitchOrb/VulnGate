package autofix

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSuccessOnSyntheticFixture(t *testing.T) {
	repoPath := prepareFixtureRepo(t)
	report, err := Run(context.Background(), Options{
		RepoPath:      repoPath,
		Model:         "local",
		AutoFix:       true,
		TestCommand:   "go test ./...",
		MaxCandidates: 3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if report.Status != StatusSuccess {
		t.Fatalf("expected success status, got=%s reason=%s", report.Status, report.Reason)
	}
	if !report.Validation.Passed {
		t.Fatalf("expected validation pass, reasons=%v", report.Validation.Reasons)
	}
	if !report.Validation.TestsRan || !report.Validation.TestsPassed {
		t.Fatalf("expected tests to run and pass, got ran=%t passed=%t", report.Validation.TestsRan, report.Validation.TestsPassed)
	}
	if len(report.Validation.UnresolvedFindings) != 0 {
		t.Fatalf("expected no unresolved findings, got=%d", len(report.Validation.UnresolvedFindings))
	}
	if report.Audit.ReportPath == "" || report.Audit.PatchPath == "" {
		t.Fatalf("expected audit artifact paths to be set")
	}

	patch, err := os.ReadFile(report.Audit.PatchPath)
	if err != nil {
		t.Fatalf("read patch artifact: %v", err)
	}
	if !strings.Contains(string(patch), "diff --git") {
		t.Fatalf("expected git diff patch, got: %s", string(patch))
	}

	rawReport, err := os.ReadFile(report.Audit.ReportPath)
	if err != nil {
		t.Fatalf("read report artifact: %v", err)
	}
	if !json.Valid(rawReport) {
		t.Fatalf("audit report is not valid json: %s", string(rawReport))
	}
}

func TestRunAbortsWhenValidationTestsFail(t *testing.T) {
	repoPath := prepareFixtureRepo(t)
	report, err := Run(context.Background(), Options{
		RepoPath:      repoPath,
		Model:         "local",
		AutoFix:       true,
		TestCommand:   "go test ./... && false",
		MaxCandidates: 3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if report.Status != StatusAborted {
		t.Fatalf("expected aborted status, got=%s reason=%s", report.Status, report.Reason)
	}
	if !report.Validation.TestsRan || report.Validation.TestsPassed {
		t.Fatalf("expected tests to run and fail")
	}
	if report.Validation.Passed {
		t.Fatalf("expected validation failure")
	}
	if !containsReason(report.Validation.Reasons, "tests failed") {
		t.Fatalf("expected tests failure reason, got=%v", report.Validation.Reasons)
	}
}

func TestEvaluatePatchSafetyTable(t *testing.T) {
	tests := []struct {
		name       string
		patch      string
		shouldPass bool
	}{
		{
			name: "safe delete marker",
			patch: `diff --git a/.vulngate-insecure b/.vulngate-insecure
deleted file mode 100644
--- a/.vulngate-insecure
+++ /dev/null
@@ -1,1 +0,0 @@
-marker
`,
			shouldPass: true,
		},
		{
			name: "network call added",
			patch: `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,1 +1,2 @@
 package main
+resp, _ := http.Get("https://example.com")
`,
			shouldPass: false,
		},
		{
			name: "secret added",
			patch: `diff --git a/config.txt b/config.txt
--- a/config.txt
+++ b/config.txt
@@ -1,1 +1,2 @@
 mode=dev
+api_key=super-secret
`,
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := evaluatePatchSafety(tt.patch)
			if report.Passed != tt.shouldPass {
				t.Fatalf("unexpected safety result: passed=%t violations=%v", report.Passed, report.Violations)
			}
		})
	}
}

func prepareFixtureRepo(t *testing.T) string {
	t.Helper()
	requireBinary(t, "git")
	requireBinary(t, "go")

	src := filepath.Join("testdata", "repo")
	dst := filepath.Join(t.TempDir(), "repo")
	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}

	runOrFail(t, dst, "git", "init")
	runOrFail(t, dst, "git", "config", "user.email", "vulngate-tests@example.com")
	runOrFail(t, dst, "git", "config", "user.name", "VulnGate Tests")
	runOrFail(t, dst, "git", "add", ".")
	runOrFail(t, dst, "git", "commit", "-m", "fixture baseline")
	return dst
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is required for this test: %v", name, err)
	}
}

func runOrFail(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s: %v\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func copyDir(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode())
	})
}

func containsReason(reasons []string, pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), p) {
			return true
		}
	}
	return false
}
