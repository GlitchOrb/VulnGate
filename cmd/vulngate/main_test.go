package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanOutputsSARIFToStdoutAndLogsToStderr(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	exitCode := runCLI(context.Background(), []string{"scan", "--debug", targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}

	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid json: %s", stdout.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse SARIF stdout: %v", err)
	}
	if payload["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", payload["version"])
	}

	if stderr.Len() == 0 {
		t.Fatalf("expected debug logs on stderr")
	}
	if strings.Contains(stderr.String(), `"version": "2.1.0"`) {
		t.Fatalf("SARIF payload leaked to stderr: %s", stderr.String())
	}
}

func TestScanRequiresTargetPath(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	exitCode := runCLI(context.Background(), []string{"scan"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for missing target path, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "requires exactly one target path") {
		t.Fatalf("expected usage error on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "error[parse]") {
		t.Fatalf("expected parse taxonomy marker, got: %s", stderr.String())
	}
}

func TestScanPolicyFailExitCodeOne(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "policy", "testdata", "repo-fail")

	exitCode := runCLI(context.Background(), []string{"scan", targetPath}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for policy violation, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid SARIF json: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy summary:") {
		t.Fatalf("expected policy summary on stderr, got: %s", stderr.String())
	}
}

func TestScanPolicyPassWithDevIgnored(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "policy", "testdata", "repo-pass")

	exitCode := runCLI(context.Background(), []string{"scan", targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for pass policy, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid SARIF json: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "ignored=1") {
		t.Fatalf("expected ignored count in policy summary, got: %s", stderr.String())
	}
}

func TestScanInvalidPolicyConfigReturnsToolError(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()
	configPath := filepath.Join(targetPath, ".vulngate.yml")
	if err := os.WriteFile(configPath, []byte("policy:\n  fail_on_severity: [SEV0]\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	exitCode := runCLI(context.Background(), []string{"scan", targetPath}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for invalid policy config, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "load policy config") {
		t.Fatalf("expected policy config error on stderr, got: %s", stderr.String())
	}
}

func TestScanTier2GoIsFailOpenOnAnalysisIssues(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "policy", "testdata", "repo-fail")

	exitCode := runCLI(context.Background(), []string{"scan", "--enable-tier2-go", targetPath}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("expected policy exit code 1 (not tool error) when tier2-go is enabled, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid SARIF json: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy summary:") {
		t.Fatalf("expected policy summary on stderr, got: %s", stderr.String())
	}
}

func TestSBOMOutputsJSONToStdoutAndWarningsToStderr(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "catalog", "testdata", "repo")

	exitCode := runCLI(context.Background(), []string{"sbom", targetPath, "--format", "json"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}

	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid json: %s", stdout.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse SBOM json: %v", err)
	}
	if payload["schema"] != "vulngate-internal-sbom-v1" {
		t.Fatalf("unexpected schema value: %v", payload["schema"])
	}

	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary object missing from sbom output")
	}
	if _, ok := summary["byEcosystem"]; !ok {
		t.Fatalf("summary.byEcosystem missing")
	}
	if _, ok := summary["byScope"]; !ok {
		t.Fatalf("summary.byScope missing")
	}

	if !strings.Contains(stderr.String(), "catalog warning") {
		t.Fatalf("expected parser warning on stderr for malformed fixture: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "\"schema\": \"vulngate-internal-sbom-v1\"") {
		t.Fatalf("SBOM payload leaked to stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "sbom summary:") {
		t.Fatalf("expected sbom summary line on stderr, got: %s", stderr.String())
	}
}

func TestSBOMFormatValidation(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "catalog", "testdata", "repo")

	exitCode := runCLI(context.Background(), []string{"sbom", "--format", "sarif", targetPath}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for invalid format, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "unsupported --format") {
		t.Fatalf("expected format error on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "error[parse]") {
		t.Fatalf("expected parse taxonomy marker, got: %s", stderr.String())
	}
}

func TestDBInitAndImportCommands(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	osvDir := filepath.Join("..", "..", "internal", "db", "testdata", "osv")

	initCode := runCLI(context.Background(), []string{"db", "init", "--db", dbPath}, &stdout, &stderr)
	if initCode != 0 {
		t.Fatalf("db init failed code=%d stderr=%s", initCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "initialized vuln db") {
		t.Fatalf("expected init message on stderr, got: %s", stderr.String())
	}

	stderr.Reset()
	importCode := runCLI(context.Background(), []string{"db", "import", "--db", dbPath, "--source", osvDir}, &stdout, &stderr)
	if importCode != 0 {
		t.Fatalf("db import failed code=%d stderr=%s", importCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "imported vulnerabilities: files=") {
		t.Fatalf("expected import summary on stderr, got: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected db commands to keep stdout empty, got: %s", stdout.String())
	}
}

func TestScanDetectsRealOSVVulnerabilityFromImportedDB(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	osvDir := filepath.Join("..", "..", "examples", "vulndb", "osv-real")
	targetPath := filepath.Join("..", "..", "examples", "repos", "real-vuln-npm-lodash")

	initCode := runCLI(context.Background(), []string{"db", "init", "--db", dbPath}, &stdout, &stderr)
	if initCode != 0 {
		t.Fatalf("db init failed code=%d stderr=%s", initCode, stderr.String())
	}

	stderr.Reset()
	importCode := runCLI(context.Background(), []string{"db", "import", "--db", dbPath, "--source", osvDir}, &stdout, &stderr)
	if importCode != 0 {
		t.Fatalf("db import failed code=%d stderr=%s", importCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	scanCode := runCLI(context.Background(), []string{"scan", "--db", dbPath, targetPath}, &stdout, &stderr)
	if scanCode != 1 {
		t.Fatalf("expected policy fail exit code 1, got %d stderr=%s", scanCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("scan stdout is not valid SARIF: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "GHSA-35jh-r3h4-6jhm") {
		t.Fatalf("expected GHSA-35jh-r3h4-6jhm in SARIF output, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "severity=high reachable=1") {
		t.Fatalf("expected reachable high severity in policy summary, got: %s", stderr.String())
	}
}

func TestReachImportAndScanAnnotatesRuntimeReachability(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	if err := os.WriteFile(filepath.Join(targetPath, ".vulngate-insecure"), []byte("marker"), 0o600); err != nil {
		t.Fatalf("write insecure marker: %v", err)
	}

	profileIn := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(profileIn, []byte(`[
  {
    "purl": "pkg:generic/vulngate/insecure@0.0.0",
    "symbol": "main.main",
    "count": 17,
    "firstSeen": "2026-02-20T10:00:00Z",
    "lastSeen": "2026-02-20T10:05:00Z"
  }
]`), 0o600); err != nil {
		t.Fatalf("write profile input: %v", err)
	}

	profileOut := filepath.Join(targetPath, ".vulngate-runtime-profile.json")
	importCode := runCLI(context.Background(), []string{"reach", "import", "--profile", profileIn, "--out", profileOut}, &stdout, &stderr)
	if importCode != 0 {
		t.Fatalf("reach import failed code=%d stderr=%s", importCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty stdout for reach import, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "runtime profile imported: events=1") {
		t.Fatalf("expected import summary on stderr, got: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()

	scanCode := runCLI(context.Background(), []string{"scan", targetPath}, &stdout, &stderr)
	if scanCode != 1 {
		t.Fatalf("expected policy fail exit code 1, got %d stderr=%s", scanCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("scan stdout is not valid SARIF: %s", stdout.String())
	}

	props := firstResultProperties(t, stdout.Bytes())
	if got, ok := props["reachable_runtime"].(bool); !ok || !got {
		t.Fatalf("expected reachable_runtime=true, got %v", props["reachable_runtime"])
	}
	if got, ok := props["runtimeCallCount"].(float64); !ok || int(got) != 17 {
		t.Fatalf("expected runtimeCallCount=17, got %v", props["runtimeCallCount"])
	}
}

func TestScanInvalidExplicitRuntimeProfileReturnsToolError(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	exitCode := runCLI(context.Background(), []string{"scan", "--runtime-profile", filepath.Join(targetPath, "missing.json"), targetPath}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for missing explicit runtime profile, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "load runtime profile") {
		t.Fatalf("expected runtime profile error on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "error[tool]") {
		t.Fatalf("expected tool taxonomy marker, got: %s", stderr.String())
	}
}

func TestScanAttestationBundleWithoutSigner(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "scan-attest.json")

	exitCode := runCLI(context.Background(), []string{"scan", "--attest-bundle", bundlePath, targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("scan stdout is not valid sarif json: %s", stdout.String())
	}
	rawBundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle file: %v", err)
	}
	if !json.Valid(rawBundle) {
		t.Fatalf("bundle is not valid json: %s", string(rawBundle))
	}
	var bundle map[string]any
	if err := json.Unmarshal(rawBundle, &bundle); err != nil {
		t.Fatalf("parse bundle json: %v", err)
	}
	if bundle["schema"] != "vulngate-attestation-bundle-v1" {
		t.Fatalf("unexpected bundle schema: %v", bundle["schema"])
	}
	artifacts, ok := bundle["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		t.Fatalf("expected one artifact in bundle, got %v", bundle["artifacts"])
	}
	artifact := artifacts[0].(map[string]any)
	if artifact["signed"] != false {
		t.Fatalf("expected unsigned artifact, got %v", artifact["signed"])
	}
}

func TestScanIncludesProvenanceRunProperties(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	exitCode := runCLI(context.Background(), []string{"scan", targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}

	props := firstRunProperties(t, stdout.Bytes())
	if _, ok := props["toolVersion"]; !ok {
		t.Fatalf("expected toolVersion in run properties")
	}
	if _, ok := props["dbStatus"]; !ok {
		t.Fatalf("expected dbStatus in run properties")
	}
	if _, ok := props["goos"]; !ok {
		t.Fatalf("expected goos in run properties")
	}
}

func TestSBOMAttestationBundleWithoutSigner(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "catalog", "testdata", "repo")
	bundlePath := filepath.Join(t.TempDir(), "sbom-attest.json")

	exitCode := runCLI(context.Background(), []string{"sbom", "--attest-bundle", bundlePath, "--format", "json", targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("sbom stdout is not valid json: %s", stdout.String())
	}
	rawBundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle file: %v", err)
	}
	if !json.Valid(rawBundle) {
		t.Fatalf("bundle is not valid json: %s", string(rawBundle))
	}
}

func TestSBOMCacheHitSummary(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := filepath.Join("..", "..", "internal", "catalog", "testdata", "repo")
	cacheDir := filepath.Join(t.TempDir(), "catalog-cache")

	first := runCLI(context.Background(), []string{"sbom", "--cache-dir", cacheDir, "--format", "json", targetPath}, &stdout, &stderr)
	if first != 0 {
		t.Fatalf("first sbom run failed: %d stderr=%s", first, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cache=miss") {
		t.Fatalf("expected cache miss on first run, got: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()

	second := runCLI(context.Background(), []string{"sbom", "--cache-dir", cacheDir, "--format", "json", targetPath}, &stdout, &stderr)
	if second != 0 {
		t.Fatalf("second sbom run failed: %d stderr=%s", second, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cache=hit") {
		t.Fatalf("expected cache hit on second run, got: %s", stderr.String())
	}
}

func TestScanProgressIndicators(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	exitCode := runCLI(context.Background(), []string{"scan", "--progress", targetPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "progress stage=") {
		t.Fatalf("expected progress lines on stderr, got: %s", stderr.String())
	}
}

func TestFixRequiresAutoFixFlag(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	targetPath := t.TempDir()

	exitCode := runCLI(context.Background(), []string{"fix", targetPath}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 when --auto-fix is missing, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "requires explicit --auto-fix") {
		t.Fatalf("expected explicit --auto-fix error, got: %s", stderr.String())
	}
}

func TestFixSuccessOutputsReportJSON(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "go")

	repoPath := prepareCLIFixRepo(t)
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	exitCode := runCLI(context.Background(), []string{"fix", "--auto-fix", "--model", "local", "--test-cmd", "go test ./...", repoPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("expected valid JSON report on stdout, got: %s", stdout.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if payload["status"] != "success" {
		t.Fatalf("expected status=success, got %v", payload["status"])
	}
	if !strings.Contains(stderr.String(), "auto-fix success") {
		t.Fatalf("expected success summary on stderr, got: %s", stderr.String())
	}
}

func TestFixValidationFailureReturnsExitOne(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "go")

	repoPath := prepareCLIFixRepo(t)
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	exitCode := runCLI(context.Background(), []string{"fix", "--auto-fix", "--model", "local", "--test-cmd", "go test ./... && false", repoPath}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for validation failure, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("expected valid JSON report on stdout, got: %s", stdout.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("parse report json: %v", err)
	}
	if payload["status"] != "aborted" {
		t.Fatalf("expected status=aborted, got %v", payload["status"])
	}
	if !strings.Contains(stderr.String(), "auto-fix aborted") {
		t.Fatalf("expected abort summary on stderr, got: %s", stderr.String())
	}
}

func TestFixAcceptsPathBeforeFlags(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "go")

	repoPath := prepareCLIFixRepo(t)
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	exitCode := runCLI(context.Background(), []string{"fix", repoPath, "--auto-fix", "--policy", ".vulngate.yml", "--model", "local", "--test-cmd", "go test ./..."}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 with path-first arguments, got %d stderr=%s", exitCode, stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("expected valid JSON report on stdout, got: %s", stdout.String())
	}
}

func firstResultProperties(t *testing.T, sarif []byte) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal(sarif, &payload); err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	runs, ok := payload["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("missing runs array")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid run object")
	}
	results, ok := run["results"].([]any)
	if !ok || len(results) == 0 {
		t.Fatalf("missing results array")
	}
	result, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid result object")
	}
	props, ok := result["properties"].(map[string]any)
	if !ok {
		t.Fatalf("missing result properties")
	}
	return props
}

func firstRunProperties(t *testing.T, sarif []byte) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal(sarif, &payload); err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	runs, ok := payload["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("missing runs array")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid run object")
	}
	props, ok := run["properties"].(map[string]any)
	if !ok {
		t.Fatalf("missing run properties")
	}
	return props
}

func prepareCLIFixRepo(t *testing.T) string {
	t.Helper()

	src := filepath.Join("..", "..", "internal", "autofix", "testdata", "repo")
	dst := filepath.Join(t.TempDir(), "repo")
	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copy fixture repo: %v", err)
	}

	runOrFail(t, dst, "git", "init")
	runOrFail(t, dst, "git", "config", "user.email", "vulngate-tests@example.com")
	runOrFail(t, dst, "git", "config", "user.name", "VulnGate Tests")
	runOrFail(t, dst, "git", "add", ".")
	runOrFail(t, dst, "git", "commit", "-m", "fixture baseline")
	return dst
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

func runOrFail(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s: %v\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}
}
