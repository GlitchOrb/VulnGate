package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ImportResult struct {
	FilesProcessed int      `json:"filesProcessed"`
	FilesErrored   int      `json:"filesErrored"`
	VulnsImported  int      `json:"vulnsImported"`
	Warnings       []string `json:"warnings,omitempty"`
}

func (s *Store) ImportOSVDir(ctx context.Context, sourceDir string) (ImportResult, error) {
	if s == nil || s.db == nil {
		return ImportResult{}, fmt.Errorf("store is not initialized")
	}
	if err := s.Init(ctx); err != nil {
		return ImportResult{}, err
	}

	root := strings.TrimSpace(sourceDir)
	if root == "" {
		return ImportResult{}, fmt.Errorf("source directory is required")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ImportResult{}, fmt.Errorf("resolve source directory: %w", err)
	}

	files := make([]string, 0)
	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return ImportResult{}, fmt.Errorf("scan source directory: %w", err)
	}
	sort.Strings(files)

	result := ImportResult{Warnings: []string{}}
	for _, filePath := range files {
		result.FilesProcessed++
		entry, err := readOSVEntry(filePath)
		if err != nil {
			result.FilesErrored++
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", relPath(absRoot, filePath), err))
			continue
		}

		if strings.TrimSpace(entry.ID) == "" {
			result.FilesErrored++
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: missing vulnerability id", relPath(absRoot, filePath)))
			continue
		}

		if err := upsertOSV(ctx, s.db, entry); err != nil {
			result.FilesErrored++
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", relPath(absRoot, filePath), err))
			continue
		}
		result.VulnsImported++
	}

	return result, nil
}

func readOSVEntry(path string) (osvEntry, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return osvEntry{}, fmt.Errorf("read file: %w", err)
	}

	var entry osvEntry
	if err := json.Unmarshal(content, &entry); err != nil {
		return osvEntry{}, fmt.Errorf("decode json: %w", err)
	}
	return entry, nil
}

func upsertOSV(ctx context.Context, db *sql.DB, entry osvEntry) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	severity := deriveSeverity(entry.Severity, entry.DatabaseSpecific.Severity)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO vulnerabilities(vuln_id, summary, details, severity, modified)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(vuln_id) DO UPDATE SET
  summary=excluded.summary,
  details=excluded.details,
  severity=excluded.severity,
  modified=excluded.modified`,
		entry.ID,
		entry.Summary,
		entry.Details,
		severity,
		entry.Modified,
	); err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM aliases WHERE vuln_id = ?`, entry.ID); err != nil {
		return fmt.Errorf("clear aliases: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM references_data WHERE vuln_id = ?`, entry.ID); err != nil {
		return fmt.Errorf("clear references: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM affected_packages WHERE vuln_id = ?`, entry.ID); err != nil {
		return fmt.Errorf("clear affected packages: %w", err)
	}

	aliasStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO aliases(vuln_id, alias) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare alias stmt: %w", err)
	}
	defer aliasStmt.Close()

	refStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO references_data(vuln_id, ref_type, url) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare reference stmt: %w", err)
	}
	defer refStmt.Close()

	affectedStmt, err := tx.PrepareContext(ctx, `INSERT INTO affected_packages(vuln_id, ecosystem, name, package_purl) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare affected package stmt: %w", err)
	}
	defer affectedStmt.Close()

	rangeStmt, err := tx.PrepareContext(ctx, `INSERT INTO affected_ranges(affected_id, range_type, repo) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare range stmt: %w", err)
	}
	defer rangeStmt.Close()

	eventStmt, err := tx.PrepareContext(ctx, `INSERT INTO range_events(range_id, event_order, introduced, fixed, last_affected, limit_value)
VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare range event stmt: %w", err)
	}
	defer eventStmt.Close()

	for _, alias := range entry.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		if _, err := aliasStmt.ExecContext(ctx, entry.ID, alias); err != nil {
			return fmt.Errorf("insert alias %q: %w", alias, err)
		}
	}

	for _, ref := range entry.References {
		url := strings.TrimSpace(ref.URL)
		if url == "" {
			continue
		}
		if _, err := refStmt.ExecContext(ctx, entry.ID, strings.TrimSpace(ref.Type), url); err != nil {
			return fmt.Errorf("insert reference %q: %w", url, err)
		}
	}

	for _, affected := range entry.Affected {
		ecosystem := normalizeEcosystem(affected.Package.Ecosystem)
		name := normalizePackageName(ecosystem, affected.Package.Name)
		if ecosystem == "" || name == "" {
			continue
		}

		purl := strings.TrimSpace(affected.Package.PURL)
		if purl == "" {
			purl = buildPackagePURL(ecosystem, name)
		}

		res, err := affectedStmt.ExecContext(ctx, entry.ID, ecosystem, name, purl)
		if err != nil {
			return fmt.Errorf("insert affected package %s/%s: %w", ecosystem, name, err)
		}
		affectedID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("get affected package id: %w", err)
		}

		for _, r := range affected.Ranges {
			rangeType := strings.ToUpper(strings.TrimSpace(r.Type))
			if rangeType == "" {
				continue
			}

			res, err := rangeStmt.ExecContext(ctx, affectedID, rangeType, strings.TrimSpace(r.Repo))
			if err != nil {
				return fmt.Errorf("insert range %s: %w", rangeType, err)
			}
			rangeID, err := res.LastInsertId()
			if err != nil {
				return fmt.Errorf("get range id: %w", err)
			}

			for idx, e := range r.Events {
				if _, err := eventStmt.ExecContext(
					ctx,
					rangeID,
					idx,
					strings.TrimSpace(e.Introduced),
					strings.TrimSpace(e.Fixed),
					strings.TrimSpace(e.LastAffected),
					strings.TrimSpace(e.Limit),
				); err != nil {
					return fmt.Errorf("insert range event: %w", err)
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	commit = true
	return nil
}

func buildPackagePURL(ecosystem, name string) string {
	switch normalizeEcosystem(ecosystem) {
	case "npm":
		return "pkg:npm/" + strings.ReplaceAll(name, "@", "%40")
	case "pypi":
		return "pkg:pypi/" + name
	case "golang":
		return "pkg:golang/" + name
	default:
		return "pkg:generic/" + name
	}
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
