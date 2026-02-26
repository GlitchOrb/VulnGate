package staticcallgraph

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Analyzer struct {
	reachableVulnIDs map[string]bool
}

func NewFromFile(path string) (*Analyzer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open static reachability file: %w", err)
	}
	defer f.Close()

	reachable := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		reachable[line] = true
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan static reachability file: %w", err)
	}

	return &Analyzer{reachableVulnIDs: reachable}, nil
}

func (a *Analyzer) Name() string {
	return "tier2-static-callgraph"
}

func (a *Analyzer) Annotate(_ context.Context, _ model.ScanRequest, findings []model.Finding) ([]model.Finding, error) {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if a.reachableVulnIDs[out[i].Vulnerability.ID] {
			out[i].Reachability = model.Tier2Static
		}
	}
	return out, nil
}
