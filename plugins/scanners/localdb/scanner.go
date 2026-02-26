package localdb

import (
	"context"
	"fmt"
	"log"

	"github.com/GlitchOrb/vulngate/pkg/model"
	"github.com/GlitchOrb/vulngate/pkg/vulndb/sqlite"
)

type Scanner struct {
	store  *sqlite.Store
	logger *log.Logger
}

func New(store *sqlite.Store, logger *log.Logger) *Scanner {
	return &Scanner{store: store, logger: logger}
}

func (s *Scanner) Name() string {
	return "localdb-sca"
}

func (s *Scanner) Scan(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	if s.store == nil {
		return nil, fmt.Errorf("sqlite store is nil")
	}

	findings := make([]model.Finding, 0)
	for _, dep := range req.Dependencies {
		vulns, err := s.store.FindForDependency(ctx, dep)
		if err != nil {
			return nil, fmt.Errorf("find vulnerabilities for %s: %w", dep.PURL, err)
		}

		for _, vuln := range vulns {
			findings = append(findings, model.Finding{
				Vulnerability: vuln,
				Dependency:    dep,
				Reachability:  model.Tier0None,
				Scanner:       s.Name(),
				Message:       fmt.Sprintf("%s affects %s", vuln.ID, dep.PURL),
			})
		}
	}

	if s.logger != nil {
		s.logger.Printf("scanned %d dependencies, found %d vulnerabilities", len(req.Dependencies), len(findings))
	}
	return findings, nil
}
