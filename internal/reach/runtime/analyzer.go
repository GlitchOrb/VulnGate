package runtime

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/internal/engine"
)

const (
	reachabilityTrue    = "true"
	reachabilityFalse   = "false"
	reachabilityUnknown = "unknown"
)

type Options struct {
	Profile Profile
	Source  string
}

type Analyzer struct {
	source string
	index  evidenceIndex
}

func NewAnalyzer(opts Options) Analyzer {
	normalized := NormalizeProfile(opts.Profile)
	source := strings.TrimSpace(opts.Source)
	if source == "" {
		source = "runtime-profile"
	}
	return Analyzer{
		source: source,
		index:  buildEvidenceIndex(normalized),
	}
}

func (a Analyzer) Name() string {
	return "tier2_runtime"
}

func (a Analyzer) Analyze(_ context.Context, _ engine.ScanContext, findings []engine.Finding) ([]engine.Finding, error) {
	if len(findings) == 0 {
		return []engine.Finding{}, nil
	}

	out := make([]engine.Finding, len(findings))
	copy(out, findings)

	for i := range out {
		result := a.classify(out[i])
		applyRuntime(&out[i], result)
	}
	return out, nil
}

type classifyResult struct {
	Status    string
	Reason    string
	Count     uint64
	Symbols   []string
	FirstSeen string
	LastSeen  string
}

func (a Analyzer) classify(finding engine.Finding) classifyResult {
	if a.index.events == 0 {
		return classifyResult{Status: reachabilityUnknown, Reason: "no runtime profile events loaded"}
	}

	coord, err := parsePURL(finding.PackagePURL)
	if err != nil {
		return classifyResult{Status: reachabilityUnknown, Reason: "unable to parse finding package PURL for runtime correlation"}
	}

	if evidence, ok := a.index.exact[exactKey(coord)]; ok {
		if evidence.count == 0 {
			return classifyResult{Status: reachabilityFalse, Reason: fmt.Sprintf("%s observed package but no calls in runtime profile", a.source)}
		}
		return classifyResult{
			Status:    reachabilityTrue,
			Reason:    fmt.Sprintf("%s observed runtime calls (exact package version match)", a.source),
			Count:     evidence.count,
			Symbols:   evidence.symbolsWithCounts(),
			FirstSeen: formatTimestamp(evidence.firstSeen),
			LastSeen:  formatTimestamp(evidence.lastSeen),
		}
	}

	if evidence, ok := a.index.byPackage[packageKey(coord)]; ok {
		if evidence.count == 0 {
			return classifyResult{Status: reachabilityFalse, Reason: fmt.Sprintf("%s observed package coordinate but no calls", a.source)}
		}
		return classifyResult{
			Status:    reachabilityTrue,
			Reason:    fmt.Sprintf("%s observed runtime calls (package coordinate match)", a.source),
			Count:     evidence.count,
			Symbols:   evidence.symbolsWithCounts(),
			FirstSeen: formatTimestamp(evidence.firstSeen),
			LastSeen:  formatTimestamp(evidence.lastSeen),
		}
	}

	return classifyResult{Status: reachabilityUnknown, Reason: fmt.Sprintf("no runtime evidence for %s in %s", finding.PackagePURL, a.source)}
}

func applyRuntime(finding *engine.Finding, result classifyResult) {
	if finding == nil {
		return
	}

	status := normalizeStatus(result.Status)
	finding.Reachability.RuntimeStatus = status
	finding.Reachability.RuntimeReason = strings.TrimSpace(result.Reason)
	finding.Reachability.RuntimeCallCount = result.Count
	finding.Reachability.RuntimeSymbols = append([]string{}, result.Symbols...)
	finding.Reachability.RuntimeFirstSeen = strings.TrimSpace(result.FirstSeen)
	finding.Reachability.RuntimeLastSeen = strings.TrimSpace(result.LastSeen)
	finding.Reachability.Tier2Runtime = status == reachabilityTrue
}

func normalizeStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case reachabilityTrue, reachabilityFalse, reachabilityUnknown:
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return reachabilityUnknown
	}
}

type evidence struct {
	count      uint64
	firstSeen  time.Time
	lastSeen   time.Time
	symbolHits map[string]uint64
}

func (e evidence) withEvent(event Event) evidence {
	symbol := strings.TrimSpace(event.Symbol)
	if symbol == "" {
		symbol = "(package)"
	}

	if e.symbolHits == nil {
		e.symbolHits = map[string]uint64{}
	}
	e.count += event.Count
	e.symbolHits[symbol] += event.Count
	e.firstSeen = earlierTime(e.firstSeen, normalizeTime(event.FirstSeen))
	e.lastSeen = laterTime(e.lastSeen, normalizeTime(event.LastSeen))
	return e
}

func (e evidence) symbolsWithCounts() []string {
	type pair struct {
		symbol string
		count  uint64
	}
	pairs := make([]pair, 0, len(e.symbolHits))
	for symbol, count := range e.symbolHits {
		pairs = append(pairs, pair{symbol: symbol, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].symbol < pairs[j].symbol
	})

	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, fmt.Sprintf("%s:%d", p.symbol, p.count))
	}
	return out
}

type evidenceIndex struct {
	events    int
	exact     map[string]evidence
	byPackage map[string]evidence
}

func buildEvidenceIndex(profile Profile) evidenceIndex {
	index := evidenceIndex{
		events:    len(profile.Events),
		exact:     map[string]evidence{},
		byPackage: map[string]evidence{},
	}

	for _, event := range profile.Events {
		coord, err := parsePURL(event.PURL)
		if err != nil {
			continue
		}

		exact := index.exact[exactKey(coord)]
		exact = exact.withEvent(event)
		index.exact[exactKey(coord)] = exact

		pkg := index.byPackage[packageKey(coord)]
		pkg = pkg.withEvent(event)
		index.byPackage[packageKey(coord)] = pkg
	}

	return index
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}
