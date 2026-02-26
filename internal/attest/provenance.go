package attest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/buildinfo"
	dbpkg "github.com/GlitchOrb/vulngate/internal/db"
)

type ProvenanceOptions struct {
	RepoPath   string
	DBPath     string
	GitCommit  string
	GitBranch  string
	CIProvider string
}

func BuildProvenance(ctx context.Context, opts ProvenanceOptions) Provenance {
	repoPath := strings.TrimSpace(opts.RepoPath)
	if repoPath != "" {
		if abs, err := filepath.Abs(repoPath); err == nil {
			repoPath = abs
		}
	}

	commit := strings.TrimSpace(opts.GitCommit)
	if commit == "" {
		commit = gitOutput(ctx, repoPath, "rev-parse", "HEAD")
	}
	branch := strings.TrimSpace(opts.GitBranch)
	if branch == "" {
		branch = gitOutput(ctx, repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	}

	ciProvider := strings.TrimSpace(opts.CIProvider)
	if ciProvider == "" {
		ciProvider = detectCIProvider()
	}

	dbMeta := ProbeDatabase(ctx, opts.DBPath)

	hints := map[string]string{}
	addHint(hints, "runner.os", os.Getenv("RUNNER_OS"))
	addHint(hints, "runner.arch", os.Getenv("RUNNER_ARCH"))
	addHint(hints, "github.workflow", os.Getenv("GITHUB_WORKFLOW"))
	addHint(hints, "github.run_id", os.Getenv("GITHUB_RUN_ID"))
	addHint(hints, "github.actor", os.Getenv("GITHUB_ACTOR"))
	addHint(hints, "build.id", os.Getenv("BUILD_ID"))
	addHint(hints, "ci.pipeline_id", os.Getenv("CI_PIPELINE_ID"))
	addHint(hints, "ci.job_id", os.Getenv("CI_JOB_ID"))

	return Provenance{
		GeneratedAt: time.Now().UTC(),
		Tool: ToolMetadata{
			Name:    "VulnGate",
			Version: buildinfo.Version,
			Commit:  buildinfo.Commit,
			Date:    buildinfo.Date,
		},
		Database: dbMeta,
		Source: SourceMetadata{
			RepoPath:  repoPath,
			GitCommit: commit,
			GitBranch: branch,
		},
		BuildEnv: BuildEnvironment{
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
			GoVersion:  runtime.Version(),
			CI:         ciProvider != "",
			CIProvider: ciProvider,
			Hints:      hints,
		},
	}
}

func ProbeDatabase(ctx context.Context, dbPath string) DatabaseMetadata {
	path := strings.TrimSpace(dbPath)
	if path == "" {
		path = "vulngate.db"
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DatabaseMetadata{
				Path:   absPath,
				Status: "missing",
			}
		}
		return DatabaseMetadata{
			Path:   absPath,
			Status: "error",
			Error:  err.Error(),
		}
	}
	if info.IsDir() {
		return DatabaseMetadata{
			Path:   absPath,
			Status: "error",
			Error:  "database path is a directory",
		}
	}

	store, err := dbpkg.Open(absPath)
	if err != nil {
		return DatabaseMetadata{
			Path:   absPath,
			Status: "error",
			Error:  err.Error(),
		}
	}
	defer store.Close()

	version, err := store.SchemaVersion(ctx)
	if err != nil {
		return DatabaseMetadata{
			Path:   absPath,
			Status: "error",
			Error:  err.Error(),
		}
	}
	if version <= 0 {
		return DatabaseMetadata{
			Path:   absPath,
			Status: "uninitialized",
		}
	}
	return DatabaseMetadata{
		Path:          absPath,
		SchemaVersion: version,
		Status:        "present",
	}
}

func (p Provenance) AsRunProperties() map[string]any {
	return map[string]any{
		"toolVersion":     p.Tool.Version,
		"toolCommit":      p.Tool.Commit,
		"toolBuildDate":   p.Tool.Date,
		"dbPath":          p.Database.Path,
		"dbSchemaVersion": p.Database.SchemaVersion,
		"dbStatus":        p.Database.Status,
		"gitCommit":       p.Source.GitCommit,
		"gitBranch":       p.Source.GitBranch,
		"ciProvider":      p.BuildEnv.CIProvider,
		"goos":            p.BuildEnv.GOOS,
		"goarch":          p.BuildEnv.GOARCH,
		"goVersion":       p.BuildEnv.GoVersion,
		"generatedAt":     p.GeneratedAt.Format(time.RFC3339),
	}
}

func addHint(hints map[string]string, key string, value string) {
	k := strings.TrimSpace(key)
	v := strings.TrimSpace(value)
	if k == "" || v == "" {
		return
	}
	hints[k] = v
}

func detectCIProvider() string {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return "github-actions"
	case strings.TrimSpace(os.Getenv("CI")) != "":
		return "generic-ci"
	default:
		return ""
	}
}

func gitOutput(ctx context.Context, repoPath string, args ...string) string {
	if repoPath == "" {
		return ""
	}
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoPath}, args...)...)
	raw, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func ResolveBundlePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" {
		return trimmed
	}
	return "vulngate-attestation.json"
}

func shouldSign(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "cosign")
}

func ValidateSignConfig(cfg SignConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "", "none", "cosign":
		return nil
	default:
		return fmt.Errorf("unsupported signer %q (expected none|cosign)", cfg.Mode)
	}
}
