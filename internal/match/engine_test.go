package match

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/GlitchOrb/vulngate/internal/catalog"
	dbpkg "github.com/GlitchOrb/vulngate/internal/db"
)

func TestMatchComponentsAgainstImportedOSVData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	store, err := dbpkg.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()

	osvDir := filepath.Join("..", "db", "testdata", "osv")
	result, err := store.ImportOSVDir(context.Background(), osvDir)
	if err != nil {
		t.Fatalf("ImportOSVDir failed: %v", err)
	}
	if result.VulnsImported != 3 {
		t.Fatalf("expected 3 imported vulnerabilities, got %d", result.VulnsImported)
	}

	repoPath := filepath.Join("..", "catalog", "testdata", "repo")
	sbomReport, err := catalog.Build(context.Background(), catalog.BuildOptions{TargetPath: repoPath})
	if err != nil {
		t.Fatalf("catalog.Build failed: %v", err)
	}

	components := make([]Component, 0, len(sbomReport.Components))
	for _, c := range sbomReport.Components {
		components = append(components, Component{PURL: c.PURL, Version: c.Version})
	}

	engine, err := NewEngine(store.DB())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	findings, err := engine.MatchComponents(context.Background(), components)
	if err != nil {
		t.Fatalf("MatchComponents failed: %v", err)
	}

	gotIDs := make([]string, 0, len(findings))
	for _, finding := range findings {
		gotIDs = append(gotIDs, finding.VulnID)
	}
	sort.Strings(gotIDs)

	wantIDs := []string{"OSV-2026-1000", "OSV-2026-2000", "OSV-2026-3000"}
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("expected %d findings, got %d (%v)", len(wantIDs), len(gotIDs), gotIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("unexpected finding ids: got=%v want=%v", gotIDs, wantIDs)
		}
	}
}

func TestSemverRangeEvaluation(t *testing.T) {
	events := []rangeEvent{{introduced: "0"}, {fixed: "1.3.1"}}
	affected, fixed := isAffected("SEMVER", "1.3.0", events)
	if !affected {
		t.Fatalf("expected version to be affected")
	}
	if fixed != "1.3.1" {
		t.Fatalf("expected fixed version 1.3.1, got %q", fixed)
	}

	affected, _ = isAffected("SEMVER", "1.3.1", events)
	if affected {
		t.Fatalf("expected fixed version to be unaffected")
	}
}

func TestGitRangeEvaluationStub(t *testing.T) {
	events := []rangeEvent{{introduced: "deadbeef"}, {fixed: "cafebabe"}}
	affected, _ := isAffected("GIT", "deadbeef", events)
	if !affected {
		t.Fatalf("introduced commit should match as affected")
	}

	affected, _ = isAffected("GIT", "cafebabe", events)
	if affected {
		t.Fatalf("fixed commit should be unaffected")
	}
}

func TestMatchComponentsParallelCacheProducesStableResults(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vulngate.db")
	store, err := dbpkg.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer store.Close()

	osvDir := filepath.Join("..", "db", "testdata", "osv")
	if _, err := store.ImportOSVDir(context.Background(), osvDir); err != nil {
		t.Fatalf("ImportOSVDir failed: %v", err)
	}

	components := []Component{
		{PURL: "pkg:npm/left-pad@1.3.0", Version: "1.3.0", Scope: "required"},
		{PURL: "pkg:pypi/requests@2.31.0", Version: "2.31.0", Scope: "required"},
		{PURL: "pkg:golang/github.com/google/uuid@1.6.0", Version: "1.6.0", Scope: "required"},
		{PURL: "pkg:npm/left-pad@1.3.0", Version: "1.3.0", Scope: "required"},
		{PURL: "pkg:invalid/nope", Version: "1.0.0", Scope: "required"},
	}

	sequential, err := NewEngineWithOptions(store.DB(), EngineOptions{
		WorkerCount:   1,
		EnableCache:   false,
		ProgressEvery: 1,
	})
	if err != nil {
		t.Fatalf("NewEngineWithOptions (sequential) failed: %v", err)
	}
	defer sequential.Close()

	parallelProgressCalls := 0
	var progressMu sync.Mutex
	parallel, err := NewEngineWithOptions(store.DB(), EngineOptions{
		WorkerCount:   4,
		EnableCache:   true,
		ProgressEvery: 1,
		Progress: func(_ Progress) {
			progressMu.Lock()
			parallelProgressCalls++
			progressMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("NewEngineWithOptions (parallel) failed: %v", err)
	}
	defer parallel.Close()

	wantFindings, err := sequential.MatchComponents(context.Background(), components)
	if err != nil {
		t.Fatalf("sequential MatchComponents failed: %v", err)
	}
	gotFindings, err := parallel.MatchComponents(context.Background(), components)
	if err != nil {
		t.Fatalf("parallel MatchComponents failed: %v", err)
	}

	if len(wantFindings) != len(gotFindings) {
		t.Fatalf("unexpected finding count: want=%d got=%d", len(wantFindings), len(gotFindings))
	}
	for i := range wantFindings {
		if wantFindings[i].VulnID != gotFindings[i].VulnID || wantFindings[i].PackagePURL != gotFindings[i].PackagePURL {
			t.Fatalf("unexpected finding at %d: want=%+v got=%+v", i, wantFindings[i], gotFindings[i])
		}
	}

	progressMu.Lock()
	defer progressMu.Unlock()
	if parallelProgressCalls == 0 {
		t.Fatalf("expected progress callback calls for parallel match")
	}
}
