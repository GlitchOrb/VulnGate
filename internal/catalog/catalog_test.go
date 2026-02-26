package catalog

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParsersStablePURLs(t *testing.T) {
	tests := []struct {
		name    string
		parse   func(string) ([]Component, error)
		fixture string
		want    []string
	}{
		{
			name:    "npm package-lock",
			parse:   parsePackageLock,
			fixture: "npm/package-lock.json",
			want: []string{
				"pkg:npm/%40types/node@20.11.30|dev",
				"pkg:npm/chalk@5.3.0|transitive",
				"pkg:npm/left-pad@1.3.0|required",
				"pkg:npm/mocha@10.2.0|dev",
			},
		},
		{
			name:    "pnpm lock",
			parse:   parsePNPMLock,
			fixture: "npm/pnpm-lock.yaml",
			want: []string{
				"pkg:npm/%40types/node@20.11.30|transitive",
				"pkg:npm/chalk@5.3.0|required",
				"pkg:npm/vitest@1.2.0|dev",
			},
		},
		{
			name:    "python poetry",
			parse:   parsePoetryLock,
			fixture: "python/poetry.lock",
			want: []string{
				"pkg:pypi/coverage@7.4.4|test",
				"pkg:pypi/pytest@8.1.1|dev",
				"pkg:pypi/requests@2.31.0|required",
			},
		},
		{
			name:    "python requirements",
			parse:   parseRequirements,
			fixture: "python/requirements.txt",
			want: []string{
				"pkg:pypi/flask@3.0.2|required",
				"pkg:pypi/pytest@8.1.1|required",
				"pkg:pypi/urllib3@2.2.1|required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := fixturePath(t, tt.fixture)
			components, err := tt.parse(path)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			got := componentKeys(components)
			if !equalSlices(got, tt.want) {
				t.Fatalf("unexpected components\nwant=%v\n got=%v", tt.want, got)
			}
		})
	}
}

func TestGoParsersStablePURLs(t *testing.T) {
	goModPath := fixturePath(t, "go/go.mod")
	goSumPath := fixturePath(t, "go/go.sum")

	modComponents, direct, err := parseGoMod(goModPath)
	if err != nil {
		t.Fatalf("parseGoMod failed: %v", err)
	}
	sumComponents, err := parseGoSum(goSumPath, direct)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	gotMod := componentKeys(modComponents)
	wantMod := []string{
		"pkg:golang/github.com/google/uuid@1.6.0|required",
		"pkg:golang/golang.org/x/text@0.14.0|transitive",
	}
	if !equalSlices(gotMod, wantMod) {
		t.Fatalf("unexpected go.mod components\nwant=%v\n got=%v", wantMod, gotMod)
	}

	gotSum := componentKeys(sumComponents)
	wantSum := []string{
		"pkg:golang/github.com/google/uuid@1.6.0|required",
		"pkg:golang/github.com/pkg/errors@0.9.1|transitive",
	}
	if !equalSlices(gotSum, wantSum) {
		t.Fatalf("unexpected go.sum components\nwant=%v\n got=%v", wantSum, gotSum)
	}
}

func TestBuildSBOMSummaryIncludesEcosystemAndScopeCounts(t *testing.T) {
	report, err := Build(context.Background(), BuildOptions{TargetPath: fixturePath(t, "repo")})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if report.Schema != schemaVersion {
		t.Fatalf("unexpected schema: %s", report.Schema)
	}
	if report.Summary.TotalComponents == 0 {
		t.Fatalf("expected components in report")
	}

	for _, eco := range []string{"npm", "python", "go"} {
		if report.Summary.ByEcosystem[eco] == 0 {
			t.Fatalf("expected non-zero ecosystem count for %s", eco)
		}
	}

	for _, scope := range []string{"required", "dev", "transitive", "test"} {
		if report.Summary.ByScope[scope] == 0 {
			t.Fatalf("expected non-zero scope count for %s", scope)
		}
	}

	if report.Summary.FilesErrored == 0 {
		t.Fatalf("expected at least one parse warning from malformed fixture")
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected warnings for malformed fixture")
	}
	if !containsWarningFor(report.Warnings, "bad/package-lock.json") {
		t.Fatalf("expected warning for malformed lockfile, got: %v", report.Warnings)
	}
}

func TestBuildUsesCacheKeyedByLockfileHash(t *testing.T) {
	target := fixturePath(t, "repo")
	cacheDir := filepath.Join(t.TempDir(), "catalog-cache")

	first, err := Build(context.Background(), BuildOptions{
		TargetPath: target,
		CacheDir:   cacheDir,
	})
	if err != nil {
		t.Fatalf("first Build failed: %v", err)
	}
	if first.Cache == nil || first.Cache.Hit {
		t.Fatalf("expected first build cache miss, got %+v", first.Cache)
	}
	if first.Cache.Key == "" {
		t.Fatalf("expected cache key to be set")
	}

	second, err := Build(context.Background(), BuildOptions{
		TargetPath: target,
		CacheDir:   cacheDir,
	})
	if err != nil {
		t.Fatalf("second Build failed: %v", err)
	}
	if second.Cache == nil || !second.Cache.Hit {
		t.Fatalf("expected second build cache hit, got %+v", second.Cache)
	}
	if second.Cache.Key != first.Cache.Key {
		t.Fatalf("cache key changed unexpectedly: first=%s second=%s", first.Cache.Key, second.Cache.Key)
	}
}

func TestBuildProgressCallback(t *testing.T) {
	target := fixturePath(t, "repo")
	events := make([]Progress, 0)
	report, err := Build(context.Background(), BuildOptions{
		TargetPath: target,
		Progress: func(event Progress) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if report.Summary.TotalComponents == 0 {
		t.Fatalf("expected components")
	}
	if len(events) == 0 {
		t.Fatalf("expected progress events")
	}
}

func fixturePath(t *testing.T, relative string) string {
	t.Helper()
	return filepath.Join("testdata", filepath.FromSlash(relative))
}

func componentKeys(components []Component) []string {
	keys := make([]string, 0, len(components))
	for _, c := range components {
		keys = append(keys, c.PURL+"|"+string(c.Scope))
	}
	sort.Strings(keys)
	return keys
}

func equalSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func containsWarningFor(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
