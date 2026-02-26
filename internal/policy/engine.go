package policy

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

type ReachabilityCount struct {
	Reachable   int
	Unreachable int
}

type EvaluationReport struct {
	TotalFindings      int
	ConsideredFindings int
	IgnoredFindings    int
	Violations         int
	CountsBySeverity   map[string]ReachabilityCount
}

type Engine struct {
	config Config
	nowFn  func() time.Time

	mu   sync.RWMutex
	last EvaluationReport
}

func NewEngine(cfg Config) (*Engine, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Engine{
		config: normalized,
		nowFn:  func() time.Time { return time.Now().UTC() },
		last: EvaluationReport{
			CountsBySeverity: map[string]ReachabilityCount{},
		},
	}, nil
}

func (e *Engine) SetNowFn(nowFn func() time.Time) {
	if nowFn == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nowFn = nowFn
}

func (e *Engine) LastReport() EvaluationReport {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return cloneReport(e.last)
}

func (e *Engine) Decide(_ context.Context, _ engine.ScanContext, findings []engine.Finding) (engine.GateDecision, error) {
	e.mu.RLock()
	nowFn := e.nowFn
	cfg := e.config
	e.mu.RUnlock()

	now := time.Now().UTC()
	if nowFn != nil {
		now = nowFn().UTC()
	}

	decision, report := evaluate(cfg, now, findings)

	e.mu.Lock()
	e.last = report
	e.mu.Unlock()

	return decision, nil
}

func evaluate(cfg Config, now time.Time, findings []engine.Finding) (engine.GateDecision, EvaluationReport) {
	failSeverities := setFromList(cfg.FailOnSeverities)
	reachabilityRequired := setFromList(cfg.Reachability.RequireReachableForSeverities)

	report := EvaluationReport{
		CountsBySeverity: map[string]ReachabilityCount{},
	}
	violations := 0

	for _, finding := range findings {
		reachable := isReachable(finding.Reachability)
		severity := normalizeSeverity(finding.Severity)
		report.TotalFindings++

		if shouldIgnoreByScope(cfg, finding) || matchesIgnoreRules(cfg.Ignore, now, finding) {
			report.IgnoredFindings++
			continue
		}

		report.ConsideredFindings++
		incrementSeverityCount(report.CountsBySeverity, severity, reachable)

		if !failSeverities[severity] {
			continue
		}
		if reachabilityRequired[severity] && !reachable {
			continue
		}
		violations++
	}

	report.Violations = violations
	if violations == 0 {
		return engine.GateDecision{Fail: false, Reason: "policy passed", Violations: 0}, report
	}

	return engine.GateDecision{
		Fail:       true,
		Reason:     fmt.Sprintf("policy failed with %d violation(s)", violations),
		Violations: violations,
	}, report
}

func cloneReport(in EvaluationReport) EvaluationReport {
	out := in
	out.CountsBySeverity = map[string]ReachabilityCount{}
	for severity, count := range in.CountsBySeverity {
		out.CountsBySeverity[severity] = count
	}
	return out
}

func setFromList(values []string) map[string]bool {
	set := map[string]bool{}
	for _, value := range values {
		set[normalizeSeverity(value)] = true
	}
	return set
}

func isReachable(flags engine.ReachabilityFlags) bool {
	return flags.Tier1 || flags.Tier2 || flags.Tier2Runtime
}

func shouldIgnoreByScope(cfg Config, finding engine.Finding) bool {
	if !cfg.Scope.ProductionMode {
		return false
	}

	scope := strings.ToLower(strings.TrimSpace(finding.Scope))
	switch scope {
	case "dev":
		return cfg.Scope.IgnoreDevDependencies
	case "test":
		return cfg.Scope.IgnoreTestDependencies
	default:
		return false
	}
}

func matchesIgnoreRules(rules []IgnoreRule, now time.Time, finding engine.Finding) bool {
	for _, rule := range rules {
		if ruleIsExpired(rule, now) {
			continue
		}

		if !ruleMatchesFinding(rule, finding) {
			continue
		}
		return true
	}
	return false
}

func ruleIsExpired(rule IgnoreRule, now time.Time) bool {
	if strings.TrimSpace(rule.Expires) == "" {
		return false
	}
	expiresAt, err := parseExpiry(rule.Expires)
	if err != nil {
		return false
	}

	if len(strings.TrimSpace(rule.Expires)) == len("2006-01-02") {
		expiresAt = expiresAt.Add(24*time.Hour - time.Nanosecond)
	}
	return now.UTC().After(expiresAt)
}

func ruleMatchesFinding(rule IgnoreRule, finding engine.Finding) bool {
	hasSelector := false

	if rule.VulnID != "" {
		hasSelector = true
		if !strings.EqualFold(strings.TrimSpace(rule.VulnID), strings.TrimSpace(finding.VulnID)) {
			return false
		}
	}

	if rule.PURL != "" {
		hasSelector = true
		if !strings.EqualFold(strings.TrimSpace(rule.PURL), strings.TrimSpace(finding.PackagePURL)) {
			return false
		}
	}

	if rule.Path != "" {
		hasSelector = true
		if !matchesFindingPath(rule.Path, finding.Locations) {
			return false
		}
	}

	return hasSelector
}

func matchesFindingPath(rulePath string, locations []engine.Location) bool {
	trimmedRule := filepath.ToSlash(strings.TrimSpace(rulePath))
	if trimmedRule == "" {
		return false
	}

	for _, location := range locations {
		candidate := filepath.ToSlash(strings.TrimSpace(location.Path))
		if candidate == "" {
			continue
		}
		if pathMatches(trimmedRule, candidate) {
			return true
		}
	}
	return false
}

func pathMatches(rulePath, findingPath string) bool {
	rule := strings.TrimPrefix(path.Clean(rulePath), "./")
	candidate := strings.TrimPrefix(path.Clean(findingPath), "./")

	if rule == candidate {
		return true
	}

	if strings.HasSuffix(rule, "/") {
		prefix := strings.TrimSuffix(rule, "/")
		if candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}

	if strings.HasSuffix(rule, "/**") {
		prefix := strings.TrimSuffix(rule, "/**")
		if candidate == prefix || strings.HasPrefix(candidate, prefix+"/") {
			return true
		}
	}

	if matched, err := path.Match(rule, candidate); err == nil && matched {
		return true
	}

	if strings.HasSuffix(candidate, "/"+rule) {
		return true
	}
	return false
}

func incrementSeverityCount(counts map[string]ReachabilityCount, severity string, reachable bool) {
	current := counts[severity]
	if reachable {
		current.Reachable++
	} else {
		current.Unreachable++
	}
	counts[severity] = current
}

func formatCounts(counts map[string]ReachabilityCount) []string {
	ordered := make([]string, 0)
	for _, severity := range severityOrder {
		if count, ok := counts[severity]; ok && (count.Reachable > 0 || count.Unreachable > 0) {
			ordered = append(ordered, severity)
		}
	}

	extra := make([]string, 0)
	for severity, count := range counts {
		if count.Reachable == 0 && count.Unreachable == 0 {
			continue
		}
		known := false
		for _, item := range ordered {
			if item == severity {
				known = true
				break
			}
		}
		if !known {
			extra = append(extra, severity)
		}
	}
	sort.Strings(extra)
	ordered = append(ordered, extra...)

	out := make([]string, 0, len(ordered))
	for _, severity := range ordered {
		count := counts[severity]
		total := count.Reachable + count.Unreachable
		out = append(out, fmt.Sprintf("severity=%s reachable=%d unreachable=%d total=%d", severity, count.Reachable, count.Unreachable, total))
	}
	return out
}
