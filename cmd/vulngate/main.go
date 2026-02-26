package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/attest"
	"github.com/GlitchOrb/vulngate/internal/autofix"
	"github.com/GlitchOrb/vulngate/internal/buildinfo"
	"github.com/GlitchOrb/vulngate/internal/catalog"
	dbpkg "github.com/GlitchOrb/vulngate/internal/db"
	"github.com/GlitchOrb/vulngate/internal/engine"
	matchpkg "github.com/GlitchOrb/vulngate/internal/match"
	"github.com/GlitchOrb/vulngate/internal/policy"
	reachruntime "github.com/GlitchOrb/vulngate/internal/reach/runtime"
	reachtier1 "github.com/GlitchOrb/vulngate/internal/reach/tier1"
	reachtier2go "github.com/GlitchOrb/vulngate/internal/reach/tier2/golang"
)

func main() {
	os.Exit(runCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		printRootHelp(stdout)
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "fix":
		return runFix(ctx, args[1:], stdout, stderr)
	case "sbom":
		return runSBOM(ctx, args[1:], stdout, stderr)
	case "db":
		return runDB(ctx, args[1:], stdout, stderr)
	case "reach":
		return runReach(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "vulngate version %s (commit=%s, date=%s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "help":
		printRootHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printRootHelp(stderr)
		return 2
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var debug bool
	var targetTypeRaw string
	var configPath string
	var enableTier2Go bool
	var runtimeProfilePath string
	var dbPath string
	var attestBundlePath string
	var signerMode string
	var signerKey string
	var cosignBin string
	var signIdentityTokenEnv string
	var progress bool
	fs.BoolVar(&debug, "debug", false, "Enable debug logging to stderr")
	fs.StringVar(&targetTypeRaw, "target-type", string(engine.TargetTypeFS), "Target type: fs|image|sbom")
	fs.StringVar(&configPath, "config", "", "Path to policy config file (default: <target>/.vulngate.yml)")
	fs.BoolVar(&enableTier2Go, "enable-tier2-go", false, "Enable Tier-2 static call-graph reachability for Go (best-effort)")
	fs.StringVar(&runtimeProfilePath, "runtime-profile", "", "Path to Tier-2R runtime profile JSON (default: <target>/.vulngate-runtime-profile.json if present)")
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to local vulnerability DB (used for provenance metadata)")
	fs.StringVar(&attestBundlePath, "attest-bundle", "", "Optional output path for attestation bundle JSON")
	fs.StringVar(&signerMode, "signer", "none", "Optional artifact signer: none|cosign")
	fs.StringVar(&signerKey, "sign-key", "", "Optional signer key reference (cosign key, KMS URI, etc)")
	fs.StringVar(&cosignBin, "cosign-bin", "cosign", "Cosign binary path for --signer cosign")
	fs.StringVar(&signIdentityTokenEnv, "sign-identity-token-env", "COSIGN_ID_TOKEN", "Environment variable containing cosign identity token")
	fs.BoolVar(&progress, "progress", false, "Show progress indicators on stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printScanHelp(stdout)
			return 0
		}
		printClassifiedError(stderr, errorKindParse, "scan argument parse error: %v", err)
		return 2
	}

	if fs.NArg() != 1 {
		printClassifiedError(stderr, errorKindParse, "scan requires exactly one target path argument")
		printScanHelp(stderr)
		return 2
	}

	targetType, err := engine.ParseTargetType(targetTypeRaw)
	if err != nil {
		printClassifiedError(stderr, errorKindParse, "invalid --target-type: %v", err)
		return 2
	}

	progressStage(stderr, progress, 1, 6, "preparing scan configuration")

	targetPath := fs.Arg(0)
	scanCtx := buildScanContext(targetPath, targetType)

	signCfg := attest.SignConfig{
		Mode:         signerMode,
		CosignBinary: cosignBin,
		KeyRef:       signerKey,
	}
	if tokenEnv := strings.TrimSpace(signIdentityTokenEnv); tokenEnv != "" {
		signCfg.IdentityToken = strings.TrimSpace(os.Getenv(tokenEnv))
	}
	if err := attest.ValidateSignConfig(signCfg); err != nil {
		printClassifiedError(stderr, errorKindParse, "invalid signing config: %v", err)
		return 2
	}

	resolvedConfigPath := strings.TrimSpace(configPath)
	configRequired := resolvedConfigPath != ""
	if resolvedConfigPath == "" {
		resolvedConfigPath = policy.ResolveDefaultPath(targetPath)
	}

	policyConfig, _, err := policy.Load(policy.LoadOptions{
		Path:     resolvedConfigPath,
		Required: configRequired,
	})
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "load policy config: %v", err)
		return 2
	}
	progressStage(stderr, progress, 2, 6, "policy loaded")

	policyEngine, err := policy.NewEngine(policyConfig)
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "build policy engine: %v", err)
		return 2
	}

	provenance := attest.BuildProvenance(ctx, attest.ProvenanceOptions{
		RepoPath:   targetPath,
		DBPath:     dbPath,
		GitCommit:  scanCtx.Repo.Commit,
		GitBranch:  scanCtx.Repo.Branch,
		CIProvider: scanCtx.CI.Provider,
	})
	scanCtx.Provenance = provenance.AsRunProperties()

	tier1Analyzer := reachtier1.NewAnalyzer(reachtier1.Options{
		Profile: reachtier1.ProfileFromProductionMode(policyConfig.Scope.ProductionMode),
	})
	reachabilityAnalyzers := []engine.ReachabilityAnalyzer{tier1Analyzer}
	if enableTier2Go {
		reachabilityAnalyzers = append(reachabilityAnalyzers, reachtier2go.NewAnalyzer())
	}

	runtimeProfile, warnings, err := loadRuntimeProfile(targetPath, runtimeProfilePath)
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "load runtime profile: %v", err)
		return 2
	}
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "runtime profile warning: %s\n", warning)
	}
	if runtimeProfile != nil {
		reachabilityAnalyzers = append(reachabilityAnalyzers, reachruntime.NewAnalyzer(reachruntime.Options{
			Profile: *runtimeProfile,
			Source:  "runtime-profile-import",
		}))
	}

	engine.SetLogOutput(stderr)
	engine.SetDebugLogging(debug)

	sbomCataloger := engine.SBOMCataloger(engine.PlaceholderSBOMCataloger{})
	matcherStage := engine.Matcher(engine.PlaceholderMatcher{})

	if targetType == engine.TargetTypeFS {
		store, err := dbpkg.Open(dbPath)
		if err != nil {
			printClassifiedError(stderr, errorKindTool, "open vulnerability db: %v", err)
			return 2
		}
		defer store.Close()

		if err := store.Init(ctx); err != nil {
			printClassifiedError(stderr, errorKindTool, "initialize vulnerability db schema: %v", err)
			return 2
		}

		matchOpts := matchpkg.EngineOptions{
			EnableCache: true,
		}
		if progress {
			matchOpts.ProgressEvery = 200
			matchOpts.Progress = func(p matchpkg.Progress) {
				fmt.Fprintf(stderr, "progress[match] processed=%d total=%d matched=%d\n", p.Processed, p.Total, p.Matched)
			}
		}

		matchEngine, err := matchpkg.NewEngineWithOptions(store.DB(), matchOpts)
		if err != nil {
			printClassifiedError(stderr, errorKindTool, "initialize matcher engine: %v", err)
			return 2
		}
		defer matchEngine.Close()

		sbomCataloger = fsCatalogStage{
			cacheDir: filepath.Join(".vulngate", "cache", "catalog"),
			progress: progress,
			stderr:   stderr,
		}
		matcherStage = localDBMatcherStage{engine: matchEngine}
	} else {
		fmt.Fprintf(stderr, "warning: target type %s uses placeholder catalog/matcher in MVP\n", targetType)
	}

	pipeline, err := engine.NewPipeline(engine.PipelineConfig{
		TargetIngestor:        engine.PlaceholderTargetIngestor{},
		SBOMCataloger:         sbomCataloger,
		Matcher:               matcherStage,
		ReachabilityAnalyzers: reachabilityAnalyzers,
		Deduplicator:          engine.DefaultDeduplicatorFingerprinter{},
		Renderer:              engine.NewSARIFRenderer("VulnGate"),
		PolicyEngine:          policyEngine,
	})
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "build pipeline: %v", err)
		return 2
	}
	progressStage(stderr, progress, 3, 6, "pipeline constructed")

	result, err := pipeline.Run(ctx, scanCtx)
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "scan pipeline failed: %v", err)
		return 2
	}
	progressStage(stderr, progress, 4, 6, "scan pipeline completed")

	for _, line := range policy.SummaryLines(policyEngine.LastReport()) {
		fmt.Fprintln(stderr, line)
	}

	if _, err := stdout.Write(result.SARIF); err != nil {
		printClassifiedError(stderr, errorKindTool, "write sarif output: %v", err)
		return 2
	}
	progressStage(stderr, progress, 5, 6, "sarif emitted")

	if attest.ShouldEmitBundle(attestBundlePath, signerMode) {
		bundlePath := attest.ResolveBundlePath(attestBundlePath)
		bundle, err := attest.BuildBundle(ctx, attest.BundleOptions{
			Provenance: provenance,
			Signing:    signCfg,
			Artifacts: []attest.ArtifactInput{
				{
					Name:      "scan.sarif",
					Kind:      "scan-sarif",
					MediaType: "application/sarif+json",
					Content:   append([]byte{}, result.SARIF...),
				},
			},
		})
		if err != nil {
			printClassifiedError(stderr, errorKindTool, "build attestation bundle: %v", err)
			return 2
		}
		if err := attest.WriteBundle(bundlePath, bundle); err != nil {
			printClassifiedError(stderr, errorKindTool, "write attestation bundle: %v", err)
			return 2
		}
		fmt.Fprintf(stderr, "attestation bundle written: %s\n", bundlePath)
	}
	progressStage(stderr, progress, 6, 6, "scan finalized")
	fmt.Fprintf(stderr, "scan summary: findings=%d gate_fail=%t target=%s type=%s\n", len(result.Findings), result.Decision.Fail, targetPath, targetType)

	if result.Decision.Fail {
		printClassifiedError(stderr, errorKindPolicy, "policy gate failed: %s", result.Decision.Reason)
		return 1
	}
	return 0
}

func runSBOM(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	args = normalizePathFirstArgs(args)

	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var format string
	var debug bool
	var dbPath string
	var attestBundlePath string
	var signerMode string
	var signerKey string
	var cosignBin string
	var signIdentityTokenEnv string
	var cacheDir string
	var noCache bool
	var progress bool
	fs.StringVar(&format, "format", "json", "Output format (json)")
	fs.BoolVar(&debug, "debug", false, "Enable debug logging to stderr")
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to local vulnerability DB (used for provenance metadata)")
	fs.StringVar(&attestBundlePath, "attest-bundle", "", "Optional output path for attestation bundle JSON")
	fs.StringVar(&signerMode, "signer", "none", "Optional artifact signer: none|cosign")
	fs.StringVar(&signerKey, "sign-key", "", "Optional signer key reference (cosign key, KMS URI, etc)")
	fs.StringVar(&cosignBin, "cosign-bin", "cosign", "Cosign binary path for --signer cosign")
	fs.StringVar(&signIdentityTokenEnv, "sign-identity-token-env", "COSIGN_ID_TOKEN", "Environment variable containing cosign identity token")
	fs.StringVar(&cacheDir, "cache-dir", ".vulngate/cache/catalog", "Catalog cache directory")
	fs.BoolVar(&noCache, "no-cache", false, "Disable dependency catalog cache")
	fs.BoolVar(&progress, "progress", false, "Show progress indicators on stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSBOMHelp(stdout)
			return 0
		}
		printClassifiedError(stderr, errorKindParse, "sbom argument parse error: %v", err)
		return 2
	}

	if fs.NArg() != 1 {
		printClassifiedError(stderr, errorKindParse, "sbom requires exactly one target path argument")
		printSBOMHelp(stderr)
		return 2
	}

	if strings.ToLower(strings.TrimSpace(format)) != "json" {
		printClassifiedError(stderr, errorKindParse, "unsupported --format %q (expected json)", format)
		return 2
	}

	signCfg := attest.SignConfig{
		Mode:         signerMode,
		CosignBinary: cosignBin,
		KeyRef:       signerKey,
	}
	if tokenEnv := strings.TrimSpace(signIdentityTokenEnv); tokenEnv != "" {
		signCfg.IdentityToken = strings.TrimSpace(os.Getenv(tokenEnv))
	}
	if err := attest.ValidateSignConfig(signCfg); err != nil {
		printClassifiedError(stderr, errorKindParse, "invalid signing config: %v", err)
		return 2
	}

	engine.SetLogOutput(stderr)
	engine.SetDebugLogging(debug)

	targetPath := fs.Arg(0)
	progressStage(stderr, progress, 1, 3, "catalog build started")
	engine.Debugf("building sbom for target=%s", targetPath)
	report, err := catalog.Build(ctx, catalog.BuildOptions{
		TargetPath:   targetPath,
		CacheDir:     cacheDir,
		DisableCache: noCache,
		Progress: func(event catalog.Progress) {
			if !progress {
				return
			}
			fmt.Fprintf(stderr, "progress[sbom] stage=%s current=%d total=%d %s\n", event.Stage, event.Current, event.Total, strings.TrimSpace(event.Message))
		},
	})
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "sbom build failed: %v", err)
		return 2
	}
	progressStage(stderr, progress, 2, 3, "catalog build completed")

	for _, warning := range report.Warnings {
		engine.Errorf("catalog warning: %s", warning)
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		printClassifiedError(stderr, errorKindTool, "marshal sbom output: %v", err)
		return 2
	}
	payload = append(payload, '\n')
	if _, err := stdout.Write(payload); err != nil {
		printClassifiedError(stderr, errorKindTool, "write sbom output: %v", err)
		return 2
	}

	if attest.ShouldEmitBundle(attestBundlePath, signerMode) {
		provenance := attest.BuildProvenance(ctx, attest.ProvenanceOptions{
			RepoPath: targetPath,
			DBPath:   dbPath,
		})
		bundlePath := attest.ResolveBundlePath(attestBundlePath)
		bundle, err := attest.BuildBundle(ctx, attest.BundleOptions{
			Provenance: provenance,
			Signing:    signCfg,
			Artifacts: []attest.ArtifactInput{
				{
					Name:      "sbom.json",
					Kind:      "sbom",
					MediaType: "application/json",
					Content:   append([]byte{}, payload...),
				},
			},
		})
		if err != nil {
			printClassifiedError(stderr, errorKindTool, "build attestation bundle: %v", err)
			return 2
		}
		if err := attest.WriteBundle(bundlePath, bundle); err != nil {
			printClassifiedError(stderr, errorKindTool, "write attestation bundle: %v", err)
			return 2
		}
		fmt.Fprintf(stderr, "attestation bundle written: %s\n", bundlePath)
	}
	progressStage(stderr, progress, 3, 3, "sbom output finalized")
	cacheState := "disabled"
	if report.Cache != nil {
		if report.Cache.Hit {
			cacheState = "hit"
		} else {
			cacheState = "miss"
		}
	}
	fmt.Fprintf(
		stderr,
		"sbom summary: components=%d files_parsed=%d files_errored=%d cache=%s ecosystems=%s scopes=%s\n",
		report.Summary.TotalComponents,
		report.Summary.FilesParsed,
		report.Summary.FilesErrored,
		cacheState,
		formatCountMap(report.Summary.ByEcosystem),
		formatCountMap(report.Summary.ByScope),
	)
	return 0
}

func runFix(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	args = normalizePathFirstArgs(args)

	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var debug bool
	var policyPath string
	var model string
	var autoFix bool
	var testCommand string
	var localLLMCmd string
	var auditDir string
	var maxCandidates int

	fs.BoolVar(&debug, "debug", false, "Enable debug logging to stderr")
	fs.StringVar(&policyPath, "policy", "", "Path to policy config file (default: <target>/.vulngate.yml)")
	fs.StringVar(&model, "model", "local", "Auto-fix model adapter (supported: local)")
	fs.BoolVar(&autoFix, "auto-fix", false, "Required safety flag to enable patch generation")
	fs.StringVar(&testCommand, "test-cmd", "", "Optional test command to validate patch (for example: go test ./...)")
	fs.StringVar(&localLLMCmd, "llm-cmd", "", "Optional local LLM command (stdin prompt -> stdout diff)")
	fs.StringVar(&auditDir, "audit-dir", "", "Audit artifact output directory (default: <target>/.vulngate/autofix/<timestamp>)")
	fs.IntVar(&maxCandidates, "max-candidates", 3, "Maximum number of remediation candidates")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printFixHelp(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "fix argument parse error: %v\n", err)
		return 2
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "fix requires exactly one repository path argument")
		printFixHelp(stderr)
		return 2
	}

	if !autoFix {
		fmt.Fprintln(stderr, "fix requires explicit --auto-fix flag")
		printFixHelp(stderr)
		return 2
	}

	engine.SetLogOutput(stderr)
	engine.SetDebugLogging(debug)

	opts := autofix.Options{
		RepoPath:      fs.Arg(0),
		PolicyPath:    policyPath,
		Model:         model,
		AutoFix:       autoFix,
		TestCommand:   testCommand,
		AuditDir:      auditDir,
		MaxCandidates: maxCandidates,
		LocalLLMCmd:   localLLMCmd,
	}

	report, err := autofix.Run(ctx, opts)
	if err != nil {
		if report.Status == "" {
			report.Status = autofix.StatusError
		}
		if strings.TrimSpace(report.Reason) == "" {
			report.Reason = err.Error()
		}
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(stderr, "write fix report: %v\n", err)
		return 2
	}

	if err != nil {
		fmt.Fprintf(stderr, "auto-fix error: %v\n", err)
		return 2
	}

	switch report.Status {
	case autofix.StatusSuccess:
		fmt.Fprintf(stderr, "auto-fix success: candidates=%d audit=%s\n", len(report.Detect.Candidates), report.Audit.Directory)
		return 0
	case autofix.StatusAborted:
		fmt.Fprintf(stderr, "auto-fix aborted: %s\n", report.Reason)
		return 1
	default:
		fmt.Fprintf(stderr, "auto-fix error: %s\n", report.Reason)
		return 2
	}
}

func runDB(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		printDBHelp(stdout)
		return 0
	}

	switch args[0] {
	case "init":
		return runDBInit(ctx, args[1:], stderr)
	case "import":
		return runDBImport(ctx, args[1:], stderr)
	case "pull":
		return runDBPull(ctx, args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "unknown db subcommand %q\n\n", args[0])
		printDBHelp(stderr)
		return 2
	}
}

func runDBInit(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("db init", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var dbPath string
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to sqlite vulnerability database")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "db init parse error: %v\n", err)
		return 2
	}

	store, err := dbpkg.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "open db: %v\n", err)
		return 1
	}
	defer store.Close()

	if err := store.Init(ctx); err != nil {
		fmt.Fprintf(stderr, "init db schema: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "initialized vuln db at %s\n", dbPath)
	return 0
}

func runDBImport(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("db import", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var dbPath string
	var source string
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to sqlite vulnerability database")
	fs.StringVar(&source, "source", "", "Path to OSV JSON directory")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "db import parse error: %v\n", err)
		return 2
	}

	if strings.TrimSpace(source) == "" {
		fmt.Fprintln(stderr, "db import requires --source <osv-json-dir>")
		return 2
	}

	store, err := dbpkg.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "open db: %v\n", err)
		return 1
	}
	defer store.Close()

	result, err := store.ImportOSVDir(ctx, source)
	if err != nil {
		fmt.Fprintf(stderr, "import osv data: %v\n", err)
		return 1
	}

	fmt.Fprintf(stderr, "imported vulnerabilities: files=%d imported=%d errors=%d\n", result.FilesProcessed, result.VulnsImported, result.FilesErrored)
	for _, warning := range result.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	return 0
}

func runDBPull(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("db pull", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var dbPath string
	var ociRef string
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to sqlite vulnerability database")
	fs.StringVar(&ociRef, "oci", "", "OCI reference to vulnerability dataset")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "db pull parse error: %v\n", err)
		return 2
	}
	if strings.TrimSpace(ociRef) == "" {
		fmt.Fprintln(stderr, "db pull requires --oci <ref>")
		return 2
	}

	store, err := dbpkg.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "open db: %v\n", err)
		return 1
	}
	defer store.Close()

	if err := store.PullOCI(ctx, ociRef); err != nil {
		fmt.Fprintf(stderr, "db pull: %v\n", err)
		return 1
	}
	return 0
}

func runReach(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		printReachHelp(stdout)
		return 0
	}

	switch args[0] {
	case "import":
		return runReachImport(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "unknown reach subcommand %q\n\n", args[0])
		printReachHelp(stderr)
		return 2
	}
}

func runReachImport(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("reach import", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var profilePath string
	var outPath string
	fs.StringVar(&profilePath, "profile", "", "Path to runtime profile JSON")
	fs.StringVar(&outPath, "out", ".vulngate-runtime-profile.json", "Output path for normalized runtime profile")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "reach import parse error: %v\n", err)
		return 2
	}
	if strings.TrimSpace(profilePath) == "" {
		fmt.Fprintln(stderr, "reach import requires --profile <path>")
		return 2
	}

	profile, warnings, err := reachruntime.LoadProfileFile(profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "read runtime profile: %v\n", err)
		return 1
	}
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "runtime profile warning: %s\n", warning)
	}

	if err := reachruntime.WriteProfileFile(outPath, profile); err != nil {
		fmt.Fprintf(stderr, "write normalized runtime profile: %v\n", err)
		return 1
	}

	fmt.Fprintf(stderr, "runtime profile imported: events=%d out=%s\n", len(profile.Events), outPath)
	return 0
}

func loadRuntimeProfile(targetPath, explicitPath string) (*reachruntime.Profile, []string, error) {
	path, required, err := resolveRuntimeProfilePath(targetPath, explicitPath)
	if err != nil {
		return nil, nil, err
	}
	if path == "" {
		return nil, nil, nil
	}

	profile, warnings, err := reachruntime.LoadProfileFile(path)
	if err != nil {
		if required {
			return nil, nil, err
		}
		return nil, []string{fmt.Sprintf("skipping runtime profile %q: %v", path, err)}, nil
	}
	if len(profile.Events) == 0 {
		warnings = append(warnings, fmt.Sprintf("runtime profile %q contains zero events", path))
	}
	return &profile, warnings, nil
}

func resolveRuntimeProfilePath(targetPath, explicitPath string) (string, bool, error) {
	explicit := strings.TrimSpace(explicitPath)
	if explicit != "" {
		return explicit, true, nil
	}

	candidate := filepath.Join(strings.TrimSpace(targetPath), ".vulngate-runtime-profile.json")
	info, err := os.Stat(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("check default runtime profile path %q: %w", candidate, err)
	}
	if info.IsDir() {
		return "", false, fmt.Errorf("default runtime profile path is a directory: %s", candidate)
	}
	return candidate, false, nil
}

func normalizePathFirstArgs(args []string) []string {
	if len(args) < 2 {
		return args
	}
	if strings.HasPrefix(args[0], "-") {
		return args
	}
	normalized := append([]string{}, args[1:]...)
	normalized = append(normalized, args[0])
	return normalized
}

func buildScanContext(targetPath string, targetType engine.TargetType) engine.ScanContext {
	return engine.ScanContext{
		Repo: engine.RepoMetadata{
			Commit: firstNonEmpty(os.Getenv("GIT_COMMIT"), os.Getenv("GITHUB_SHA")),
			Branch: firstNonEmpty(os.Getenv("GIT_BRANCH"), os.Getenv("GITHUB_REF_NAME")),
			URL:    firstNonEmpty(os.Getenv("GIT_URL"), os.Getenv("GITHUB_SERVER_URL")),
		},
		CI: detectCIMetadata(),
		Target: engine.TargetDescriptor{
			Type: targetType,
			Path: targetPath,
		},
		RequestedAt: time.Now().UTC(),
	}
}

func detectCIMetadata() engine.CIMetadata {
	ci := engine.CIMetadata{}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		ci.Provider = "github-actions"
		ci.PipelineID = os.Getenv("GITHUB_RUN_ID")
		ci.JobID = os.Getenv("GITHUB_JOB")
		if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
			runID := os.Getenv("GITHUB_RUN_ID")
			if runID != "" {
				ci.RunURL = fmt.Sprintf("https://github.com/%s/actions/runs/%s", repo, runID)
			}
		}
		return ci
	}

	if os.Getenv("CI") != "" {
		ci.Provider = "generic-ci"
		ci.PipelineID = firstNonEmpty(os.Getenv("BUILD_ID"), os.Getenv("CI_PIPELINE_ID"))
		ci.JobID = firstNonEmpty(os.Getenv("JOB_ID"), os.Getenv("CI_JOB_ID"))
		ci.RunURL = firstNonEmpty(os.Getenv("BUILD_URL"), os.Getenv("CI_JOB_URL"))
	}
	return ci
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isHelp(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func printRootHelp(w io.Writer) {
	fmt.Fprint(w, `VulnGate - CI/CD vulnerability scanning skeleton

Usage:
  vulngate <command> [options]

Commands:
  scan       Run placeholder scan pipeline and emit SARIF 2.1.0 to stdout
  fix        Run optional Detect-Repair-Validate loop and emit fix report JSON to stdout
  sbom       Build internal SBOM-like component catalog and emit JSON to stdout
  db         Manage local vulnerability SQLite database
  reach      Import runtime reachability profiles (Tier-2R)
  version    Print version metadata
  help       Show this help

Run "vulngate <command> --help" for command details.
`)
}

func printScanHelp(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vulngate scan [--target-type fs|image|sbom] [--config path] [--db path] [--attest-bundle path] [--signer none|cosign] [--sign-key key] [--enable-tier2-go] [--runtime-profile path] [--progress] [--debug] <target-path>

Behavior:
  - stdout: final SARIF 2.1.0 JSON only
  - stderr: logs and errors
  - optional attestation bundle can be emitted and signed
  - if --signer cosign is set and --attest-bundle is omitted, default bundle path is ./vulngate-attestation.json
  - scan exit code: 0=pass, 1=policy fail, 2=tool error
`)
}

func printFixHelp(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vulngate fix [--policy path] [--model local] --auto-fix [--test-cmd "go test ./..."] [--llm-cmd "<cmd>"] [--audit-dir path] [--max-candidates N] [--debug] <repo-path>

Behavior:
  - Detect: selects top reachable high/critical findings
  - Repair: generates candidate git diff with local adapter
  - Validate: applies patch in temp git worktree, runs tests (optional), and rescans
  - stdout: auto-fix report JSON
  - stderr: logs and summary
  - fix exit code: 0=validated, 1=aborted/failed validation, 2=tool error
`)
}

func printSBOMHelp(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vulngate sbom [--format json] [--cache-dir path] [--no-cache] [--progress] [--db path] [--attest-bundle path] [--signer none|cosign] [--sign-key key] [--debug] <target-path>

Behavior:
  - stdout: internal SBOM JSON
  - stderr: logs and parser warnings
  - optional attestation bundle can be emitted and signed
  - if --signer cosign is set and --attest-bundle is omitted, default bundle path is ./vulngate-attestation.json
  - sbom exit code: 0=ok, 2=parse/tool error
`)
}

func printDBHelp(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vulngate db <command> [options]

Commands:
  init                     Initialize local vulnerability DB schema
  import --source <dir>    Import OSV JSON files from directory into local DB
  pull --oci <ref>         Pull vulnerability dataset from OCI reference (stub)

Common options:
  --db <path>              SQLite DB path (default: vulngate.db)
`)
}

func printReachHelp(w io.Writer) {
	fmt.Fprint(w, `Usage:
  vulngate reach import --profile <profile.json> [--out .vulngate-runtime-profile.json]

Behavior:
  - imports and normalizes runtime profile events for Tier-2R scan correlation
  - stdout: reserved (empty)
  - stderr: warnings and import summary
`)
}

type errorKind string

const (
	errorKindParse  errorKind = "parse"
	errorKindTool   errorKind = "tool"
	errorKindPolicy errorKind = "policy"
)

func printClassifiedError(w io.Writer, kind errorKind, format string, args ...any) {
	prefix := fmt.Sprintf("error[%s]: ", kind)
	fmt.Fprintf(w, prefix+format+"\n", args...)
}

func progressStage(w io.Writer, enabled bool, current int, total int, message string) {
	if !enabled {
		return
	}
	fmt.Fprintf(w, "progress stage=%d/%d %s\n", current, total, strings.TrimSpace(message))
}

func formatCountMap(values map[string]int) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]string, 0, len(keys))
	for _, key := range keys {
		items = append(items, fmt.Sprintf("%s=%d", key, values[key]))
	}
	return strings.Join(items, ",")
}
