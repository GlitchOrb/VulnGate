package autofix

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrAutoFixNotEnabled = errors.New("auto-fix is disabled; pass --auto-fix to enable patch generation")

const (
	defaultMaxCandidates = 3
	maxChangedFiles      = 10
	maxAddedLines        = 500
	maxRemovedLines      = 1200
)

func Run(ctx context.Context, opts Options) (report Report, err error) {
	started := time.Now().UTC()
	report = Report{
		StartedAt:   started,
		CompletedAt: started,
		RepoPath:    strings.TrimSpace(opts.RepoPath),
		PolicyPath:  strings.TrimSpace(opts.PolicyPath),
		Model:       normalizeModel(opts.Model),
		AutoFix:     opts.AutoFix,
		Status:      StatusError,
		Detect: DetectReport{
			Candidates: []Candidate{},
		},
		Safety: SafetyReport{
			Violations: []string{},
		},
		Validation: ValidationReport{
			Reasons:             []string{},
			UnresolvedFindings:  []Candidate{},
			NewCriticalFindings: []Candidate{},
		},
		NeverPushed: true,
	}

	defer func() {
		report.CompletedAt = time.Now().UTC()
		if report.Reason == "" && err != nil {
			report.Reason = err.Error()
		}
		if report.Audit.ReportPath != "" {
			if writeErr := writeJSONFile(report.Audit.ReportPath, report); writeErr != nil && err == nil {
				err = fmt.Errorf("write audit report: %w", writeErr)
			}
		}
	}()

	repoPath, err := validateAndResolveRepoPath(opts.RepoPath)
	if err != nil {
		return report, err
	}
	report.RepoPath = repoPath

	if !opts.AutoFix {
		return report, ErrAutoFixNotEnabled
	}

	report.PolicyPath = resolvePolicyPathForReport(repoPath, opts.PolicyPath)
	report.Model = normalizeModel(opts.Model)

	auditDir, err := resolveAuditDir(repoPath, opts.AuditDir)
	if err != nil {
		return report, err
	}
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return report, fmt.Errorf("create audit directory %q: %w", auditDir, err)
	}
	report.Audit = AuditArtifacts{
		Directory:       auditDir,
		PromptPath:      filepath.Join(auditDir, "prompt.txt"),
		ModelOutputPath: filepath.Join(auditDir, "model-output.txt"),
		PatchPath:       filepath.Join(auditDir, "patch.diff"),
		ReportPath:      filepath.Join(auditDir, "report.json"),
	}

	scanBefore, err := runScanSnapshot(ctx, repoPath, opts.PolicyPath)
	if err != nil {
		return report, fmt.Errorf("detect stage scan failed: %w", err)
	}

	maxCandidates := opts.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = defaultMaxCandidates
	}
	report.Detect = detectCandidates(scanBefore.Result.Findings, maxCandidates)
	if len(report.Detect.Candidates) == 0 {
		report.Status = StatusAborted
		report.Reason = "no reachable high/critical findings available for auto-remediation"
		return report, nil
	}

	adapter, err := resolveAdapter(opts)
	if err != nil {
		return report, err
	}

	prompt := buildPrompt(report.RepoPath, report.PolicyPath, report.Detect.Candidates)
	if err := os.WriteFile(report.Audit.PromptPath, []byte(prompt), 0o600); err != nil {
		return report, fmt.Errorf("write prompt audit artifact: %w", err)
	}

	gen, genErr := adapter.GeneratePatch(ctx, GenerateRequest{
		RepoPath:   repoPath,
		Prompt:     prompt,
		Candidates: report.Detect.Candidates,
	})
	if genErr != nil {
		report.Status = StatusAborted
		report.Reason = fmt.Sprintf("repair stage failed: %v", genErr)
		_ = os.WriteFile(report.Audit.ModelOutputPath, []byte(genErr.Error()+"\n"), 0o600)
		return report, nil
	}
	if err := os.WriteFile(report.Audit.ModelOutputPath, []byte(ensureTrailingNewline(gen.RawOutput)), 0o600); err != nil {
		return report, fmt.Errorf("write model output audit artifact: %w", err)
	}

	patch := ensureTrailingNewline(gen.Patch)
	if strings.TrimSpace(patch) == "" {
		report.Status = StatusAborted
		report.Reason = "repair stage returned an empty patch"
		return report, nil
	}

	if err := os.WriteFile(report.Audit.PatchPath, []byte(patch), 0o600); err != nil {
		return report, fmt.Errorf("write patch audit artifact: %w", err)
	}
	report.PatchPreview = patchPreview(patch, 120)

	safety := evaluatePatchSafety(patch)
	report.Safety = safety
	if !safety.Passed {
		report.Status = StatusAborted
		report.Reason = "generated patch violates safety constraints"
		return report, nil
	}

	validation, validateErr := validatePatch(ctx, validationInput{
		RepoPath:           repoPath,
		PolicyPath:         opts.PolicyPath,
		PatchPath:          report.Audit.PatchPath,
		TestCommand:        strings.TrimSpace(opts.TestCommand),
		AuditDir:           report.Audit.Directory,
		BeforeScan:         scanBefore,
		TargetedCandidates: report.Detect.Candidates,
	})
	if validateErr != nil {
		return report, fmt.Errorf("validate stage failed: %w", validateErr)
	}
	report.Validation = validation
	if !validation.Passed {
		report.Status = StatusAborted
		report.Reason = firstNonEmpty(validation.Reasons...)
		if report.Reason == "" {
			report.Reason = "validation failed"
		}
		return report, nil
	}

	report.Status = StatusSuccess
	report.Reason = "auto-remediation validated successfully"
	return report, nil
}

func resolveAdapter(opts Options) (Adapter, error) {
	if opts.Adapter != nil {
		return opts.Adapter, nil
	}

	switch normalizeModel(opts.Model) {
	case "local":
		return LocalAdapter{Command: strings.TrimSpace(opts.LocalLLMCmd)}, nil
	default:
		return nil, fmt.Errorf("unsupported model %q (supported: local)", opts.Model)
	}
}

func normalizeModel(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return "local"
	}
	return m
}

func validateAndResolveRepoPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("repo path is required")
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("read repo path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repo path must be a directory: %s", abs)
	}
	return abs, nil
}

func resolvePolicyPathForReport(repoPath string, policyPath string) string {
	resolved, _ := resolvePolicyPath(repoPath, policyPath)
	return resolved
}

func resolveAuditDir(repoPath string, requested string) (string, error) {
	trimmed := strings.TrimSpace(requested)
	if trimmed == "" {
		now := time.Now().UTC()
		stamp := fmt.Sprintf("%s-%09d", now.Format("20060102T150405Z"), now.Nanosecond())
		return filepath.Join(repoPath, ".vulngate", "autofix", stamp), nil
	}
	if filepath.IsAbs(trimmed) {
		return trimmed, nil
	}
	return filepath.Join(repoPath, trimmed), nil
}

func buildPrompt(repoPath string, policyPath string, candidates []Candidate) string {
	if len(candidates) == 0 {
		return ""
	}

	payload, err := json.MarshalIndent(candidates, "", "  ")
	if err != nil {
		payload = []byte("[]")
	}

	return fmt.Sprintf(`You are generating a remediation patch for VulnGate.
Repository: %s
Policy file: %s

Primary objective:
- remove or mitigate the listed vulnerabilities with the smallest safe diff.

Strict constraints:
1) Output only a valid git unified diff beginning with "diff --git".
2) Keep changes minimal and focused on the vulnerable dependency or marker only.
3) Preserve existing tests; do not disable, delete, skip, or weaken tests.
4) Never introduce network calls, telemetry, remote fetches, or external APIs.
5) Never introduce credentials, secrets, tokens, or private keys.
6) Avoid refactors and unrelated formatting changes.

Target findings (JSON):
%s
`, repoPath, policyPath, string(payload))
}

func patchPreview(patch string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 120
	}
	scanner := bufio.NewScanner(strings.NewReader(patch))
	lines := make([]string, 0, maxLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= maxLines {
			break
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return ensureTrailingNewline(strings.Join(lines, "\n"))
}

func evaluatePatchSafety(patch string) SafetyReport {
	report := SafetyReport{
		Passed:     true,
		Violations: []string{},
	}

	if strings.TrimSpace(patch) == "" {
		report.Passed = false
		report.Violations = append(report.Violations, "patch is empty")
		return report
	}

	type fileChange struct {
		path    string
		deleted bool
	}
	changes := map[string]*fileChange{}
	currentPath := ""

	scanner := bufio.NewScanner(strings.NewReader(patch))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "diff --git ") {
			path := diffPathFromHeader(line)
			currentPath = path
			if path != "" {
				if _, ok := changes[path]; !ok {
					changes[path] = &fileChange{path: path}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "deleted file mode ") && currentPath != "" {
			if item, ok := changes[currentPath]; ok {
				item.deleted = true
			}
			continue
		}
		if strings.HasPrefix(line, "+++ /dev/null") && currentPath != "" {
			if item, ok := changes[currentPath]; ok {
				item.deleted = true
			}
			continue
		}

		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			report.AddedLines++
			content := strings.TrimSpace(line[1:])
			if looksLikeNetworkCall(content) {
				report.Violations = append(report.Violations, fmt.Sprintf("network-related change detected in %s", firstNonEmpty(currentPath, "<unknown>")))
			}
			if looksLikeSecret(content) {
				report.Violations = append(report.Violations, fmt.Sprintf("possible secret material added in %s", firstNonEmpty(currentPath, "<unknown>")))
			}
			if looksLikeTestBypass(content) {
				report.Violations = append(report.Violations, fmt.Sprintf("test bypass pattern detected in %s", firstNonEmpty(currentPath, "<unknown>")))
			}
			continue
		}

		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			report.RemovedLines++
		}
	}

	changedPaths := make([]string, 0, len(changes))
	for path, item := range changes {
		changedPaths = append(changedPaths, path)
		if item.deleted && looksLikeTestPath(path) {
			report.Violations = append(report.Violations, fmt.Sprintf("deleting test file is not allowed: %s", path))
		}
	}
	sort.Strings(changedPaths)
	report.ChangedFiles = len(changedPaths)

	if report.ChangedFiles > maxChangedFiles {
		report.Violations = append(report.Violations, fmt.Sprintf("too many changed files: %d (limit=%d)", report.ChangedFiles, maxChangedFiles))
	}
	if report.AddedLines > maxAddedLines {
		report.Violations = append(report.Violations, fmt.Sprintf("too many added lines: %d (limit=%d)", report.AddedLines, maxAddedLines))
	}
	if report.RemovedLines > maxRemovedLines {
		report.Violations = append(report.Violations, fmt.Sprintf("too many removed lines: %d (limit=%d)", report.RemovedLines, maxRemovedLines))
	}

	if len(report.Violations) > 0 {
		report.Passed = false
	}
	return report
}

func diffPathFromHeader(line string) string {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 4 {
		return ""
	}
	aPath := strings.TrimPrefix(parts[2], "a/")
	bPath := strings.TrimPrefix(parts[3], "b/")
	switch {
	case bPath != "" && bPath != "/dev/null":
		return filepath.ToSlash(bPath)
	case aPath != "":
		return filepath.ToSlash(aPath)
	default:
		return ""
	}
}

func looksLikeNetworkCall(line string) bool {
	lower := strings.ToLower(line)
	patterns := []string{
		"http://",
		"https://",
		"net/http",
		"http.get(",
		"http.post(",
		"fetch(",
		"axios.",
		"requests.",
		"urllib.",
		"socket.",
		"grpc.dial(",
		"curl ",
		"wget ",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func looksLikeSecret(line string) bool {
	lower := strings.ToLower(line)
	patterns := []string{
		"begin private key",
		"api_key",
		"apikey",
		"secret_key",
		"password=",
		"token=",
		"ghp_",
		"aws_secret_access_key",
		"akia",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func looksLikeTestBypass(line string) bool {
	lower := strings.ToLower(line)
	patterns := []string{
		"t.skip(",
		"t.skipnow(",
		"pytest.skip(",
		"@unittest.skip",
		".skip(",
		"xit(",
		"xdescribe(",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func looksLikeTestPath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
	switch {
	case p == "":
		return false
	case strings.Contains(p, "/test/"):
		return true
	case strings.Contains(p, "/tests/"):
		return true
	case strings.HasPrefix(p, "test/"):
		return true
	case strings.HasPrefix(p, "tests/"):
		return true
	case strings.HasSuffix(p, "_test.go"):
		return true
	case strings.HasSuffix(p, "_test.py"):
		return true
	case strings.HasSuffix(p, ".spec.js"), strings.HasSuffix(p, ".spec.ts"), strings.HasSuffix(p, ".spec.tsx"), strings.HasSuffix(p, ".spec.jsx"):
		return true
	case strings.HasSuffix(p, ".test.js"), strings.HasSuffix(p, ".test.ts"), strings.HasSuffix(p, ".test.tsx"), strings.HasSuffix(p, ".test.jsx"):
		return true
	default:
		return false
	}
}

type validationInput struct {
	RepoPath           string
	PolicyPath         string
	PatchPath          string
	TestCommand        string
	AuditDir           string
	BeforeScan         scanSnapshot
	TargetedCandidates []Candidate
}

func validatePatch(ctx context.Context, in validationInput) (ValidationReport, error) {
	report := ValidationReport{
		Reasons:             []string{},
		UnresolvedFindings:  []Candidate{},
		NewCriticalFindings: []Candidate{},
	}

	if _, err := exec.LookPath("git"); err != nil {
		return report, fmt.Errorf("git binary not found in PATH")
	}

	if _, err := runCommand(ctx, "", "git", "-C", in.RepoPath, "rev-parse", "--is-inside-work-tree"); err != nil {
		return report, fmt.Errorf("repo is not a git worktree: %w", err)
	}

	worktreePath, err := os.MkdirTemp("", "vulngate-autofix-worktree-")
	if err != nil {
		return report, fmt.Errorf("create temp worktree path: %w", err)
	}
	branch := fmt.Sprintf("vulngate/autofix-%d", time.Now().UTC().UnixNano())
	report.WorktreePath = worktreePath
	report.Branch = branch

	added := false
	defer func() {
		if added {
			_, _ = runCommand(context.Background(), "", "git", "-C", in.RepoPath, "worktree", "remove", "--force", worktreePath)
		}
		_, _ = runCommand(context.Background(), "", "git", "-C", in.RepoPath, "branch", "-D", branch)
		_ = os.RemoveAll(worktreePath)
	}()

	if _, err := runCommand(ctx, "", "git", "-C", in.RepoPath, "worktree", "add", "-b", branch, worktreePath, "HEAD"); err != nil {
		return report, fmt.Errorf("create temp worktree branch: %w", err)
	}
	added = true

	if _, err := runCommand(ctx, "", "git", "-C", worktreePath, "apply", "--whitespace=nowarn", in.PatchPath); err != nil {
		report.Reasons = append(report.Reasons, fmt.Sprintf("patch apply failed: %v", err))
		report.Passed = false
		return report, nil
	}
	report.PatchApplied = true

	if in.TestCommand != "" {
		report.TestsRan = true
		testOutput, testErr := runShellCommand(ctx, worktreePath, in.TestCommand)
		testOutputPath := filepath.Join(in.AuditDir, "validation-tests.log")
		if writeErr := os.WriteFile(testOutputPath, []byte(ensureTrailingNewline(testOutput)), 0o600); writeErr == nil {
			report.TestOutputPath = testOutputPath
		}
		if testErr != nil {
			report.TestsPassed = false
			report.Reasons = append(report.Reasons, fmt.Sprintf("tests failed: %v", testErr))
			report.Passed = false
			return report, nil
		}
		report.TestsPassed = true
	} else {
		report.TestsRan = false
		report.TestsPassed = true
	}

	afterScan, scanErr := runScanSnapshot(ctx, worktreePath, in.PolicyPath)
	if scanErr != nil {
		report.Reasons = append(report.Reasons, fmt.Sprintf("rescan failed: %v", scanErr))
		report.RescanPassed = false
		report.Passed = false
		return report, nil
	}

	afterCandidates := findingsToCandidates(afterScan.Result.Findings)
	report.UnresolvedFindings = unresolvedTargets(in.TargetedCandidates, afterCandidates)

	beforeAll := findingsToCandidates(in.BeforeScan.Result.Findings)
	_, report.NewCriticalFindings = diffCandidateSets(beforeAll, afterCandidates)

	report.RescanPassed = len(report.UnresolvedFindings) == 0 && len(report.NewCriticalFindings) == 0
	if !report.RescanPassed {
		if len(report.UnresolvedFindings) > 0 {
			report.Reasons = append(report.Reasons, fmt.Sprintf("targeted findings unresolved after rescan: %d", len(report.UnresolvedFindings)))
		}
		if len(report.NewCriticalFindings) > 0 {
			report.Reasons = append(report.Reasons, fmt.Sprintf("new critical findings introduced: %d", len(report.NewCriticalFindings)))
		}
	}

	report.Passed = report.PatchApplied && report.TestsPassed && report.RescanPassed
	return report, nil
}

func unresolvedTargets(targets []Candidate, after []Candidate) []Candidate {
	if len(targets) == 0 || len(after) == 0 {
		return []Candidate{}
	}

	afterSet := map[string]bool{}
	for _, candidate := range after {
		afterSet[candidateKey(candidate)] = true
	}

	unresolved := make([]Candidate, 0)
	for _, candidate := range targets {
		if afterSet[candidateKey(candidate)] {
			unresolved = append(unresolved, candidate)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool {
		if unresolved[i].VulnID != unresolved[j].VulnID {
			return unresolved[i].VulnID < unresolved[j].VulnID
		}
		return unresolved[i].PackagePURL < unresolved[j].PackagePURL
	})
	return unresolved
}

func runCommand(ctx context.Context, dir string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	buf := bytes.Buffer{}
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		if out == "" {
			return "", err
		}
		return out, fmt.Errorf("%w: %s", err, out)
	}
	return out, nil
}

func runShellCommand(ctx context.Context, dir string, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	cmd.Dir = dir
	out := bytes.Buffer{}
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func writeJSONFile(path string, v any) error {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o600)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
