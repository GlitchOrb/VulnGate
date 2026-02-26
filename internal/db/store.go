package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		cleanPath = "vulngate.db"
	}

	sqlDB, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return &Store{db: sqlDB}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *Store) Init(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store is not initialized")
	}
	return ApplyMigrations(ctx, s.db)
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("store is not initialized")
	}

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	var version sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	if version.Int64 < 0 {
		return 0, nil
	}
	return int(version.Int64), nil
}
