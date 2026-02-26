package golang

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GlitchOrb/vulngate/internal/engine"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type Reachability string

const (
	ReachableTrue    Reachability = "true"
	ReachableFalse   Reachability = "false"
	ReachableUnknown Reachability = "unknown"
)

type Result struct {
	Reachable Reachability
	Reason    string
	Evidence  string
}

type Analyzer struct{}

func NewAnalyzer() Analyzer {
	return Analyzer{}
}

func (a Analyzer) Name() string {
	return "tier2_go"
}

func (a Analyzer) Analyze(ctx context.Context, scanCtx engine.ScanContext, findings []engine.Finding) ([]engine.Finding, error) {
	if len(findings) == 0 {
		return []engine.Finding{}, nil
	}

	out := make([]engine.Finding, len(findings))
	copy(out, findings)

	if scanCtx.Target.Type != engine.TargetTypeFS {
		for i := range out {
			applyTier2(&out[i], Result{Reachable: ReachableUnknown, Reason: "tier2 go analyzer requires filesystem target"})
		}
		return out, nil
	}

	absTarget, err := filepath.Abs(scanCtx.Target.Path)
	if err != nil {
		reason := fmt.Sprintf("resolve target path: %v", err)
		for i := range out {
			applyTier2(&out[i], Result{Reachable: ReachableUnknown, Reason: reason})
		}
		return out, nil
	}

	model, err := buildModel(ctx, absTarget)
	if err != nil {
		engine.Debugf("tier2 go analysis unavailable: %v", err)
		reason := fmt.Sprintf("tier2 go analysis unavailable: %v", err)
		for i := range out {
			applyTier2(&out[i], Result{Reachable: ReachableUnknown, Reason: reason})
		}
		return out, nil
	}

	for i := range out {
		result := model.classify(out[i])
		applyTier2(&out[i], result)
	}
	return out, nil
}

func applyTier2(finding *engine.Finding, result Result) {
	if finding == nil {
		return
	}
	status := strings.ToLower(strings.TrimSpace(string(result.Reachable)))
	switch status {
	case string(ReachableTrue), string(ReachableFalse), string(ReachableUnknown):
	default:
		status = string(ReachableUnknown)
	}
	finding.Reachability.Tier2Status = status
	finding.Reachability.Tier2Reason = strings.TrimSpace(result.Reason)
	finding.Reachability.Tier2Evidence = strings.TrimSpace(result.Evidence)
	finding.Reachability.Tier2 = status == string(ReachableTrue)
}

type analysisModel struct {
	graph           *callgraph.Graph
	roots           []*callgraph.Node
	parentByNode    map[*callgraph.Node]*callgraph.Node
	reachableByNode map[*callgraph.Node]bool
	packagePaths    map[string]bool
	targetNodes     map[string][]*callgraph.Node
}

func buildModel(ctx context.Context, targetPath string) (*analysisModel, error) {
	cfg := &packages.Config{
		Context: ctx,
		Dir:     targetPath,
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedSyntax,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load go packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages discovered")
	}
	if errs := packagesErrors(pkgs); len(errs) > 0 {
		return nil, fmt.Errorf("package load errors: %s", strings.Join(errs, "; "))
	}

	packagePaths := collectPackagePaths(pkgs)

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.SanityCheckFunctions)
	prog.Build()

	roots := make([]*ssa.Function, 0)
	for _, ssaPkg := range ssaPkgs {
		if ssaPkg == nil || ssaPkg.Pkg == nil {
			continue
		}
		if ssaPkg.Pkg.Name() != "main" {
			continue
		}
		if mainFn := ssaPkg.Func("main"); mainFn != nil {
			roots = append(roots, mainFn)
		}
		if initFn := ssaPkg.Func("init"); initFn != nil {
			roots = append(roots, initFn)
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no main entrypoints found")
	}

	rtaResult, err := safeRTAAnalyze(roots)
	if err != nil {
		return nil, err
	}
	if rtaResult == nil || rtaResult.CallGraph == nil {
		return nil, fmt.Errorf("call graph construction failed")
	}

	rootNodes := make([]*callgraph.Node, 0, len(roots))
	for _, root := range roots {
		n := rtaResult.CallGraph.Nodes[root]
		if n != nil {
			rootNodes = append(rootNodes, n)
		}
	}
	if len(rootNodes) == 0 {
		return nil, fmt.Errorf("call graph contains no entrypoint nodes")
	}

	parent, reachable := buildReachabilityIndex(rootNodes)
	targetNodes := indexTargetNodes(rtaResult.CallGraph)

	return &analysisModel{
		graph:           rtaResult.CallGraph,
		roots:           rootNodes,
		parentByNode:    parent,
		reachableByNode: reachable,
		packagePaths:    packagePaths,
		targetNodes:     targetNodes,
	}, nil
}

func (m *analysisModel) classify(finding engine.Finding) Result {
	coord, err := parsePURL(finding.PackagePURL)
	if err != nil {
		return Result{Reachable: ReachableUnknown, Reason: "unable to parse package PURL for tier2 go"}
	}
	if coord.Ecosystem != "golang" {
		return Result{Reachable: ReachableUnknown, Reason: "tier2 go analyzer only supports golang PURLs"}
	}

	target := strings.ToLower(strings.TrimSpace(coord.Name))
	if target == "" {
		return Result{Reachable: ReachableUnknown, Reason: "empty go package target"}
	}

	nodes := m.nodesForTarget(target)
	if len(nodes) == 0 {
		if m.packageExists(target) {
			return Result{Reachable: ReachableFalse, Reason: "package present but no callable functions in analyzed graph"}
		}
		return Result{Reachable: ReachableFalse, Reason: "package not in runtime dependency closure"}
	}

	for _, node := range nodes {
		if !m.reachableByNode[node] {
			continue
		}
		chain := m.callChain(node)
		entry := "entrypoint"
		if len(chain) > 0 {
			entry = chain[0]
		}
		return Result{
			Reachable: ReachableTrue,
			Reason:    fmt.Sprintf("reachable from entrypoint %s", entry),
			Evidence:  strings.Join(chain, " -> "),
		}
	}

	return Result{Reachable: ReachableFalse, Reason: "not reachable from discovered entrypoints"}
}

func (m *analysisModel) nodesForTarget(target string) []*callgraph.Node {
	if nodes, ok := m.targetNodes[target]; ok {
		return nodes
	}
	out := []*callgraph.Node{}
	for pkgPath, nodes := range m.targetNodes {
		if strings.HasPrefix(pkgPath, target+"/") {
			out = append(out, nodes...)
		}
	}
	return out
}

func (m *analysisModel) packageExists(target string) bool {
	for pkgPath := range m.packagePaths {
		if pkgPath == target || strings.HasPrefix(pkgPath, target+"/") {
			return true
		}
	}
	return false
}

func (m *analysisModel) callChain(target *callgraph.Node) []string {
	chain := []string{}
	for n := target; n != nil; n = m.parentByNode[n] {
		chain = append(chain, functionLabel(n))
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	if len(chain) > 6 {
		chain = append(chain[:5], chain[len(chain)-1])
	}
	return chain
}

func buildReachabilityIndex(roots []*callgraph.Node) (map[*callgraph.Node]*callgraph.Node, map[*callgraph.Node]bool) {
	parent := map[*callgraph.Node]*callgraph.Node{}
	reachable := map[*callgraph.Node]bool{}
	queue := make([]*callgraph.Node, 0, len(roots))

	for _, root := range roots {
		if root == nil || reachable[root] {
			continue
		}
		reachable[root] = true
		parent[root] = nil
		queue = append(queue, root)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range current.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			next := edge.Callee
			if reachable[next] {
				continue
			}
			reachable[next] = true
			parent[next] = current
			queue = append(queue, next)
		}
	}
	return parent, reachable
}

func indexTargetNodes(graph *callgraph.Graph) map[string][]*callgraph.Node {
	index := map[string][]*callgraph.Node{}
	if graph == nil {
		return index
	}
	for fn, node := range graph.Nodes {
		if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil || node == nil {
			continue
		}
		pkgPath := strings.ToLower(strings.TrimSpace(fn.Pkg.Pkg.Path()))
		if pkgPath == "" {
			continue
		}
		index[pkgPath] = append(index[pkgPath], node)
	}
	for pkgPath := range index {
		sort.Slice(index[pkgPath], func(i, j int) bool {
			return functionLabel(index[pkgPath][i]) < functionLabel(index[pkgPath][j])
		})
	}
	return index
}

func collectPackagePaths(pkgs []*packages.Package) map[string]bool {
	seen := map[string]bool{}
	var walk func(*packages.Package)
	walk = func(pkg *packages.Package) {
		if pkg == nil {
			return
		}
		if pkg.PkgPath != "" {
			if seen[pkg.PkgPath] {
				return
			}
			seen[pkg.PkgPath] = true
		}
		for _, imp := range pkg.Imports {
			walk(imp)
		}
	}
	for _, pkg := range pkgs {
		walk(pkg)
	}
	return seen
}

func packagesErrors(pkgs []*packages.Package) []string {
	errSet := map[string]bool{}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		for _, e := range pkg.Errors {
			msg := strings.TrimSpace(e.Msg)
			if msg == "" {
				continue
			}
			errSet[msg] = true
		}
	}
	out := make([]string, 0, len(errSet))
	for msg := range errSet {
		out = append(out, msg)
	}
	sort.Strings(out)
	return out
}

func functionLabel(node *callgraph.Node) string {
	if node == nil || node.Func == nil {
		return "<unknown>"
	}
	fn := node.Func
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Path(), fn.Name())
	}
	return fn.String()
}

func safeRTAAnalyze(roots []*ssa.Function) (result *rta.Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("rta analyze panic: %v", recovered)
		}
	}()
	result = rta.Analyze(roots, true)
	return result, nil
}
