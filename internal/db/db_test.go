package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestInitCreatesVersionedSchemaAndIndexes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	var migrationCount int
	if err := store.DB().QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("query schema_migrations failed: %v", err)
	}
	if migrationCount == 0 {
		t.Fatalf("expected at least one migration row")
	}

	version, err := store.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion failed: %v", err)
	}
	if version <= 0 {
		t.Fatalf("expected positive schema version, got %d", version)
	}

	for _, indexName := range []string{
		"idx_affected_ecosystem_name",
		"idx_vuln_id",
		"idx_alias",
	} {
		var count int
		if err := store.DB().QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name=?`, indexName).Scan(&count); err != nil {
			t.Fatalf("query sqlite_master for %s failed: %v", indexName, err)
		}
		if count == 0 {
			t.Fatalf("missing index %s", indexName)
		}
	}
}

func TestImportOSVDir(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	source := filepath.Join("testdata", "osv")
	result, err := store.ImportOSVDir(context.Background(), source)
	if err != nil {
		t.Fatalf("ImportOSVDir failed: %v", err)
	}

	if result.VulnsImported != 3 {
		t.Fatalf("expected 3 imported vulnerabilities, got %d", result.VulnsImported)
	}
	if result.FilesErrored != 0 {
		t.Fatalf("expected 0 import errors, got %d (%v)", result.FilesErrored, result.Warnings)
	}

	var vulnCount int
	if err := store.DB().QueryRow(`SELECT COUNT(1) FROM vulnerabilities`).Scan(&vulnCount); err != nil {
		t.Fatalf("query vulnerabilities failed: %v", err)
	}
	if vulnCount != 3 {
		t.Fatalf("expected 3 vulnerability rows, got %d", vulnCount)
	}

	var aliasCount int
	if err := store.DB().QueryRow(`SELECT COUNT(1) FROM aliases WHERE alias='CVE-2026-1000'`).Scan(&aliasCount); err != nil {
		t.Fatalf("query aliases failed: %v", err)
	}
	if aliasCount != 1 {
		t.Fatalf("expected alias row for CVE-2026-1000")
	}
}
