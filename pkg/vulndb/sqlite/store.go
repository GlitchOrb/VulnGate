package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/GlitchOrb/vulngate/pkg/matcher"
	"github.com/GlitchOrb/vulngate/pkg/model"
)

type Store struct {
	db *sql.DB
}

type storedVulnerability struct {
	id          string
	summary     string
	severity    model.Severity
	packagePURL string
	aliases     []string
	references  []string
	ranges      []model.OSVRange
}

func Open(path string) (*Store, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		cleanPath = "vulngate.db"
	}

	db, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	const createTable = `
CREATE TABLE IF NOT EXISTS vulnerabilities (
	id TEXT NOT NULL,
	summary TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL,
	package_purl TEXT NOT NULL,
	package_key TEXT NOT NULL,
	range_type TEXT NOT NULL,
	events_json TEXT NOT NULL,
	aliases_json TEXT NOT NULL DEFAULT '[]',
	references_json TEXT NOT NULL DEFAULT '[]',
	PRIMARY KEY (id, package_key, range_type, events_json)
);
`
	const createIndex = `
CREATE INDEX IF NOT EXISTS idx_vuln_package_key ON vulnerabilities (package_key);
`

	_, err := s.db.ExecContext(ctx, createTable)
	if err != nil {
		return fmt.Errorf("ensure schema table: %w", err)
	}

	_, err = s.db.ExecContext(ctx, createIndex)
	if err != nil {
		return fmt.Errorf("ensure schema index: %w", err)
	}
	return nil
}

func (s *Store) Upsert(ctx context.Context, v model.Vulnerability) error {
	parsed, err := matcher.ParsePURL(v.PackagePURL)
	if err != nil {
		return fmt.Errorf("invalid vulnerability package purl %q: %w", v.PackagePURL, err)
	}
	packageKey := parsed.PackageKey()

	aliasesJSON, err := json.Marshal(v.Aliases)
	if err != nil {
		return fmt.Errorf("marshal aliases: %w", err)
	}
	referencesJSON, err := json.Marshal(v.References)
	if err != nil {
		return fmt.Errorf("marshal references: %w", err)
	}

	for _, r := range v.Ranges {
		eventsJSON, err := json.Marshal(r.Events)
		if err != nil {
			return fmt.Errorf("marshal range events: %w", err)
		}

		const q = `
INSERT INTO vulnerabilities (
	id, summary, severity, package_purl, package_key, range_type, events_json, aliases_json, references_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id, package_key, range_type, events_json)
DO UPDATE SET
	summary = excluded.summary,
	severity = excluded.severity,
	aliases_json = excluded.aliases_json,
	references_json = excluded.references_json
`
		_, err = s.db.ExecContext(
			ctx,
			q,
			v.ID,
			v.Summary,
			string(v.Severity),
			v.PackagePURL,
			packageKey,
			string(r.Type),
			string(eventsJSON),
			string(aliasesJSON),
			string(referencesJSON),
		)
		if err != nil {
			return fmt.Errorf("upsert vulnerability %s: %w", v.ID, err)
		}
	}

	return nil
}

func (s *Store) FindForDependency(ctx context.Context, dep model.Dependency) ([]model.Vulnerability, error) {
	parsedDep, err := matcher.ParsePURL(dep.PURL)
	if err != nil {
		return nil, fmt.Errorf("invalid dependency purl %q: %w", dep.PURL, err)
	}
	packageKey := parsedDep.PackageKey()

	const q = `
SELECT id, summary, severity, package_purl, range_type, events_json, aliases_json, references_json
FROM vulnerabilities
WHERE package_key = ?
ORDER BY id
`
	rows, err := s.db.QueryContext(ctx, q, packageKey)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities by package key: %w", err)
	}
	defer rows.Close()

	aggregated := map[string]*storedVulnerability{}
	for rows.Next() {
		var id string
		var summary string
		var severityRaw string
		var packagePURL string
		var rangeTypeRaw string
		var eventsJSON string
		var aliasesJSON string
		var referencesJSON string

		if err := rows.Scan(&id, &summary, &severityRaw, &packagePURL, &rangeTypeRaw, &eventsJSON, &aliasesJSON, &referencesJSON); err != nil {
			return nil, fmt.Errorf("scan vulnerability row: %w", err)
		}

		severity, err := model.ParseSeverity(severityRaw)
		if err != nil {
			severity = model.SeverityUnknown
		}

		var events []model.OSVRangeEvent
		if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
			return nil, fmt.Errorf("decode events_json for %s: %w", id, err)
		}

		entry, exists := aggregated[id]
		if !exists {
			entry = &storedVulnerability{
				id:          id,
				summary:     summary,
				severity:    severity,
				packagePURL: packagePURL,
				ranges:      []model.OSVRange{},
			}

			if aliasesJSON != "" {
				_ = json.Unmarshal([]byte(aliasesJSON), &entry.aliases)
			}
			if referencesJSON != "" {
				_ = json.Unmarshal([]byte(referencesJSON), &entry.references)
			}

			aggregated[id] = entry
		}

		entry.ranges = append(entry.ranges, model.OSVRange{
			Type:   model.OSVRangeType(rangeTypeRaw),
			Events: events,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vulnerability rows: %w", err)
	}

	version := dep.Version
	if version == "" {
		version = parsedDep.Version
	}

	out := []model.Vulnerability{}
	for _, v := range aggregated {
		if matcher.IsAffected(version, v.ranges) {
			out = append(out, model.Vulnerability{
				ID:          v.id,
				Summary:     v.summary,
				Severity:    v.severity,
				PackagePURL: v.packagePURL,
				Ranges:      v.ranges,
				Aliases:     v.aliases,
				References:  v.references,
			})
		}
	}

	return out, nil
}
