package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type migration struct {
	version int
	name    string
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		name:    "initial_osv_schema",
		sql: `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  vuln_id TEXT PRIMARY KEY,
  summary TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'unknown',
  modified TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(vuln_id);

CREATE TABLE IF NOT EXISTS aliases (
  vuln_id TEXT NOT NULL,
  alias TEXT NOT NULL,
  PRIMARY KEY (vuln_id, alias),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alias ON aliases(alias);

CREATE TABLE IF NOT EXISTS references_data (
  vuln_id TEXT NOT NULL,
  ref_type TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  PRIMARY KEY (vuln_id, url),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS affected_packages (
  affected_id INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  package_purl TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_affected_ecosystem_name ON affected_packages(ecosystem, name);

CREATE TABLE IF NOT EXISTS affected_ranges (
  range_id INTEGER PRIMARY KEY AUTOINCREMENT,
  affected_id INTEGER NOT NULL,
  range_type TEXT NOT NULL,
  repo TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (affected_id) REFERENCES affected_packages(affected_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ranges_affected_id ON affected_ranges(affected_id);

CREATE TABLE IF NOT EXISTS range_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  range_id INTEGER NOT NULL,
  event_order INTEGER NOT NULL,
  introduced TEXT NOT NULL DEFAULT '',
  fixed TEXT NOT NULL DEFAULT '',
  last_affected TEXT NOT NULL DEFAULT '',
  limit_value TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (range_id) REFERENCES affected_ranges(range_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_range_events_range_id ON range_events(range_id, event_order);
`,
	},
}

func ApplyMigrations(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("nil db")
	}

	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	for _, m := range migrations {
		applied, err := migrationApplied(ctx, db, m.version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration tx: %w", err)
		}

		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.name, err)
		}

		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
			m.version,
			m.name,
			time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

func migrationApplied(ctx context.Context, db *sql.DB, version int) (bool, error) {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);`); err != nil {
		return false, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, version).Scan(&count); err != nil {
		return false, fmt.Errorf("query schema_migrations version=%d: %w", version, err)
	}
	return count > 0, nil
}
