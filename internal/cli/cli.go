package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/buildinfo"
	"github.com/GlitchOrb/vulngate/pkg/deps/gomod"
	"github.com/GlitchOrb/vulngate/pkg/engine"
	"github.com/GlitchOrb/vulngate/pkg/matcher"
	"github.com/GlitchOrb/vulngate/pkg/model"
	"github.com/GlitchOrb/vulngate/pkg/vulndb/sqlite"
	"github.com/GlitchOrb/vulngate/plugins/reachability/dependency"
	"github.com/GlitchOrb/vulngate/plugins/reachability/runtimeebpf"
	"github.com/GlitchOrb/vulngate/plugins/reachability/staticcallgraph"
	consolerenderer "github.com/GlitchOrb/vulngate/pkg/render/console"
	htmlrenderer "github.com/GlitchOrb/vulngate/pkg/render/html"
	sarifrenderer "github.com/GlitchOrb/vulngate/pkg/render/sarif"
	"github.com/GlitchOrb/vulngate/plugins/scanners/localdb"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
	logger *log.Logger
}

func New(stdout, stderr io.Writer) *App {
	return &App{
		stdout: stdout,
		stderr: stderr,
		logger: log.New(stderr, "vulngate: ", log.LstdFlags),
	}
}

func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		a.printRootHelp()
		return 0
	}

	switch args[0] {
	case "scan":
		return a.runScan(ctx, args[1:])
	case "db":
		return a.runDB(ctx, args[1:])
	case "version":
		fmt.Fprintf(a.stdout, "vulngate version %s (commit=%s, date=%s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "help":
		a.printRootHelp()
		return 0
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printRootHelp()
		return 2
	}
}

func (a *App) runScan(ctx context.Context, args []string) int {
	if hasHelp(args) {
		a.printScanHelp()
		return 0
	}

	var depInputs stringListFlag
	var format string
	var dbPath string
	var target string
	var project string
	var minSeverityRaw string
	var reachabilityModeRaw string
	var minTierRaw string
	var staticReachabilityFile string
	var enableRuntimeEBPF bool

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.StringVar(&format, "format", "html", "Output format (html, console, sarif).")
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to embedded SQLite vulnerability DB.")
	fs.StringVar(&target, "target", ".", "Project root path for dependency discovery.")
	fs.StringVar(&project, "project", "", "Logical project name in reports.")
	fs.Var(&depInputs, "dep", "Dependency PURL (repeatable). Example: pkg:golang/github.com/foo/bar@1.2.3")
	fs.StringVar(&minSeverityRaw, "policy-min-severity", string(model.SeverityHigh), "Policy fail threshold: low|medium|high|critical")
	fs.StringVar(&reachabilityModeRaw, "policy-reachability", string(model.ReachabilityReachable), "Policy mode: any|reachable")
	fs.StringVar(&minTierRaw, "policy-min-tier", string(model.Tier1Dependency), "Minimum reachability tier when mode=reachable: tier0|tier1|tier2|tier2r")
	fs.StringVar(&staticReachabilityFile, "static-reachability-file", "", "Optional file containing reachable vulnerability IDs for Tier-2 static upgrade.")
	fs.BoolVar(&enableRuntimeEBPF, "enable-runtime-ebpf", false, "Enable Tier-2R runtime reachability placeholder analyzer.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.printScanHelp()
			return 0
		}
		fmt.Fprintf(a.stderr, "scan flag parse error: %v\n", err)
		return 2
	}

	if format != "sarif" && format != "console" && format != "html" {
		fmt.Fprintf(a.stderr, "unsupported format %q: only html, sarif and console are supported\n", format)
		return 2
	}

	minSeverity, err := model.ParseSeverity(minSeverityRaw)
	if err != nil {
		fmt.Fprintf(a.stderr, "invalid --policy-min-severity: %v\n", err)
		return 2
	}

	reachabilityMode, err := model.ParseReachabilityMode(reachabilityModeRaw)
	if err != nil {
		fmt.Fprintf(a.stderr, "invalid --policy-reachability: %v\n", err)
		return 2
	}

	minTier, err := model.ParseReachabilityTier(minTierRaw)
	if err != nil {
		fmt.Fprintf(a.stderr, "invalid --policy-min-tier: %v\n", err)
		return 2
	}

	policy := model.PolicyConfig{
		MinSeverity:         minSeverity,
		ReachabilityMode:    reachabilityMode,
		MinReachabilityTier: minTier,
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "open vulnerability DB: %v\n", err)
		return 1
	}
	defer store.Close()

	if err := store.EnsureSchema(ctx); err != nil {
		fmt.Fprintf(a.stderr, "initialize vulnerability DB schema: %v\n", err)
		return 1
	}

	deps, err := parseDependencies(depInputs)
	if err != nil {
		fmt.Fprintf(a.stderr, "parse dependencies: %v\n", err)
		return 2
	}
	if len(deps) == 0 {
		discovered, err := gomod.Discover(target)
		if err != nil {
			fmt.Fprintf(a.stderr, "dependency discovery failed: %v\n", err)
			return 1
		}
		deps = discovered
	}

	if project == "" {
		project = filepath.Base(target)
	}

	e := engine.New(a.logger, policy)
	if err := e.RegisterScanner(localdb.New(store, a.logger)); err != nil {
		fmt.Fprintf(a.stderr, "register scanner: %v\n", err)
		return 1
	}
	if err := e.RegisterReachabilityAnalyzer(dependency.New()); err != nil {
		fmt.Fprintf(a.stderr, "register dependency reachability analyzer: %v\n", err)
		return 1
	}
	if staticReachabilityFile != "" {
		staticAnalyzer, err := staticcallgraph.NewFromFile(staticReachabilityFile)
		if err != nil {
			fmt.Fprintf(a.stderr, "load static reachability file: %v\n", err)
			return 1
		}
		if err := e.RegisterReachabilityAnalyzer(staticAnalyzer); err != nil {
			fmt.Fprintf(a.stderr, "register static reachability analyzer: %v\n", err)
			return 1
		}
	}
	if enableRuntimeEBPF {
		if err := e.RegisterReachabilityAnalyzer(runtimeebpf.New()); err != nil {
			fmt.Fprintf(a.stderr, "register runtime ebpf analyzer: %v\n", err)
			return 1
		}
	}
	if err := e.RegisterRenderer(sarifrenderer.New()); err != nil {
		fmt.Fprintf(a.stderr, "register sarif renderer: %v\n", err)
		return 1
	}
	if err := e.RegisterRenderer(consolerenderer.New()); err != nil {
		fmt.Fprintf(a.stderr, "register console renderer: %v\n", err)
		return 1
	}
	if err := e.RegisterRenderer(htmlrenderer.New()); err != nil {
		fmt.Fprintf(a.stderr, "register html renderer: %v\n", err)
		return 1
	}

	report, err := e.Scan(ctx, model.ScanRequest{
		Project:      project,
		TargetPath:   target,
		Dependencies: deps,
		GeneratedAt:  time.Now().Local(),
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "scan failed: %v\n", err)
		return 1
	}

	if err := e.Render(a.stdout, format, report); err != nil {
		fmt.Fprintf(a.stderr, "render %s output: %v\n", format, err)
		return 1
	}

	if report.PolicyDecision.Fail {
		a.logger.Printf("build gate failed: %s", report.PolicyDecision.Reason)
		return 3
	}
	return 0
}

func (a *App) runDB(ctx context.Context, args []string) int {
	if len(args) == 0 || hasHelp(args) {
		a.printDBHelp()
		return 0
	}

	switch args[0] {
	case "seed-example":
		return a.runDBSeedExample(ctx, args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown db subcommand %q\n\n", args[0])
		a.printDBHelp()
		return 2
	}
}

func (a *App) runDBSeedExample(ctx context.Context, args []string) int {
	var dbPath string
	fs := flag.NewFlagSet("db seed-example", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.StringVar(&dbPath, "db", "vulngate.db", "Path to embedded SQLite vulnerability DB.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(a.stdout, "usage: vulngate db seed-example [--db vulngate.db]")
			return 0
		}
		fmt.Fprintf(a.stderr, "seed-example flag parse error: %v\n", err)
		return 2
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "open vulnerability DB: %v\n", err)
		return 1
	}
	defer store.Close()

	if err := store.EnsureSchema(ctx); err != nil {
		fmt.Fprintf(a.stderr, "initialize vulnerability DB schema: %v\n", err)
		return 1
	}

	vuln := model.Vulnerability{
		ID:          "test_vulnerability",
		Summary:     "Example vulnerable range for demonstration and tests",
		Severity:    model.SeverityHigh,
		PackagePURL: "pkg:golang/github.com/example/insecure-lib",
		Ranges: []model.OSVRange{{
			Type: model.OSVRangeSemver,
			Events: []model.OSVRangeEvent{
				{Introduced: "0"},
				{Fixed: "1.2.4"},
			},
		}},
		Aliases:    []string{"CVE-2026-0001"},
		References: []string{"https://osv.dev/"},
	}
	if err := store.Upsert(ctx, vuln); err != nil {
		fmt.Fprintf(a.stderr, "seed vulnerability DB: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stderr, "seeded example vulnerability into %s\n", dbPath)
	return 0
}

func parseDependencies(depInputs []string) ([]model.Dependency, error) {
	deps := make([]model.Dependency, 0, len(depInputs))
	seen := map[string]bool{}
	for _, dep := range depInputs {
		p, err := matcher.ParsePURL(dep)
		if err != nil {
			return nil, err
		}
		if p.Version == "" {
			return nil, fmt.Errorf("dependency %q must include @version", dep)
		}
		clean := strings.TrimSpace(dep)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		deps = append(deps, model.Dependency{PURL: dep, Version: p.Version})
	}
	return deps, nil
}

type stringListFlag []string

func (s *stringListFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if isHelpArg(arg) {
			return true
		}
	}
	return false
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help"
}
