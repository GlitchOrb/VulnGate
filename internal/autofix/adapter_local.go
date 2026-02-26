package autofix

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type LocalAdapter struct {
	Command string
}

func (a LocalAdapter) Name() string {
	return "local"
}

func (a LocalAdapter) GeneratePatch(ctx context.Context, req GenerateRequest) (GenerateResult, error) {
	cmd := strings.TrimSpace(a.Command)
	if cmd != "" {
		generated, err := runLocalModelCommand(ctx, cmd, req.RepoPath, req.Prompt)
		if err != nil {
			return GenerateResult{}, err
		}
		patch := extractGitDiff(generated)
		if patch != "" {
			return GenerateResult{Patch: patch, RawOutput: generated, ModelInfo: "local-llm-cmd"}, nil
		}
	}

	patch, note, err := buildHeuristicPatch(req)
	if err != nil {
		return GenerateResult{}, err
	}
	if strings.TrimSpace(patch) == "" {
		return GenerateResult{}, fmt.Errorf("local adapter produced empty patch")
	}
	return GenerateResult{Patch: patch, RawOutput: note, ModelInfo: "local-heuristic"}, nil
}

func runLocalModelCommand(ctx context.Context, command string, repoPath string, prompt string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "bash", "-lc", command)
	cmd.Dir = repoPath
	cmd.Stdin = strings.NewReader(prompt)
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run local model command: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
	}

	combined := strings.TrimSpace(stdout.String())
	if strings.TrimSpace(stderr.String()) != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += "[stderr]\n" + strings.TrimSpace(stderr.String())
	}
	return combined, nil
}

func extractGitDiff(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if strings.Contains(trimmed, "```diff") {
		start := strings.Index(trimmed, "```diff")
		if start >= 0 {
			sub := trimmed[start+len("```diff"):]
			end := strings.Index(sub, "```")
			if end >= 0 {
				candidate := strings.TrimSpace(sub[:end])
				if strings.Contains(candidate, "diff --git") {
					return ensureTrailingNewline(candidate)
				}
			}
		}
	}

	idx := strings.Index(trimmed, "diff --git")
	if idx >= 0 {
		return ensureTrailingNewline(trimmed[idx:])
	}
	return ""
}

func ensureTrailingNewline(raw string) string {
	out := strings.ReplaceAll(raw, "\r\n", "\n")
	if strings.HasSuffix(out, "\n") {
		return out
	}
	return out + "\n"
}

func buildHeuristicPatch(req GenerateRequest) (string, string, error) {
	if strings.TrimSpace(req.RepoPath) == "" {
		return "", "", fmt.Errorf("repo path is empty")
	}

	deleteCandidates := map[string]bool{}
	for _, candidate := range req.Candidates {
		for _, location := range candidate.Locations {
			raw := strings.TrimSpace(location)
			if raw == "" {
				continue
			}
			rel := normalizeRelativePath(req.RepoPath, raw)
			if rel == "" {
				continue
			}
			base := strings.ToLower(filepath.Base(rel))
			if base == ".vulngate-insecure" || base == ".vulngate-insecure-dev" || strings.Contains(base, "vulnerable") {
				deleteCandidates[rel] = true
			}
		}
	}

	for _, marker := range []string{".vulngate-insecure", ".vulngate-insecure-dev"} {
		abs := filepath.Join(req.RepoPath, marker)
		if _, err := os.Stat(abs); err == nil {
			deleteCandidates[marker] = true
		}
	}

	files := make([]string, 0, len(deleteCandidates))
	for rel := range deleteCandidates {
		files = append(files, rel)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", "no heuristic fix candidates found", fmt.Errorf("no heuristic auto-fix candidates")
	}

	patch, err := buildDeletePatch(req.RepoPath, files)
	if err != nil {
		return "", "", err
	}
	note := fmt.Sprintf("heuristic patch generated: delete %d marker file(s)", len(files))
	return patch, note, nil
}

func buildDeletePatch(repoPath string, relativePaths []string) (string, error) {
	builder := strings.Builder{}

	for _, rel := range relativePaths {
		cleanRel := normalizeRelativePath(repoPath, rel)
		if cleanRel == "" {
			continue
		}
		abs := filepath.Join(repoPath, filepath.FromSlash(cleanRel))
		raw, err := os.ReadFile(abs)
		if err != nil {
			return "", fmt.Errorf("read file for delete patch %s: %w", cleanRel, err)
		}

		content := strings.ReplaceAll(string(raw), "\r\n", "\n")
		content = strings.TrimSuffix(content, "\n")
		lines := []string{}
		if content != "" {
			lines = strings.Split(content, "\n")
		}

		builder.WriteString("diff --git a/")
		builder.WriteString(cleanRel)
		builder.WriteString(" b/")
		builder.WriteString(cleanRel)
		builder.WriteString("\n")
		builder.WriteString("deleted file mode 100644\n")
		builder.WriteString("--- a/")
		builder.WriteString(cleanRel)
		builder.WriteString("\n")
		builder.WriteString("+++ /dev/null\n")

		if len(lines) == 0 {
			builder.WriteString("@@ -0,0 +0,0 @@\n")
		} else {
			builder.WriteString(fmt.Sprintf("@@ -1,%d +0,0 @@\n", len(lines)))
			for _, line := range lines {
				builder.WriteString("-")
				builder.WriteString(line)
				builder.WriteString("\n")
			}
		}
	}

	patch := builder.String()
	if strings.TrimSpace(patch) == "" {
		return "", fmt.Errorf("generated delete patch is empty")
	}
	return patch, nil
}

func normalizeRelativePath(repoPath string, pathValue string) string {
	value := strings.TrimSpace(pathValue)
	if value == "" {
		return ""
	}

	asFS := filepath.FromSlash(value)
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return ""
	}

	if filepath.IsAbs(asFS) {
		absPath, err := filepath.Abs(asFS)
		if err != nil {
			return ""
		}
		rel, err := filepath.Rel(absRepo, absPath)
		if err != nil {
			return ""
		}
		normalized := filepath.ToSlash(rel)
		if strings.HasPrefix(normalized, "../") || normalized == ".." {
			return ""
		}
		return strings.TrimPrefix(normalized, "./")
	}

	clean := filepath.ToSlash(filepath.Clean(asFS))
	clean = strings.TrimPrefix(clean, "./")
	if clean == "." || clean == "" {
		return ""
	}
	if strings.HasPrefix(clean, "../") || clean == ".." {
		return ""
	}
	return clean
}
