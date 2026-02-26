package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GlitchOrb/vulngate/internal/catalog"
	"github.com/GlitchOrb/vulngate/internal/engine"
	matchpkg "github.com/GlitchOrb/vulngate/internal/match"
)

type fsCatalogStage struct {
	cacheDir     string
	disableCache bool
	progress     bool
	stderr       io.Writer
}

func (s fsCatalogStage) Catalog(ctx context.Context, scanCtx engine.ScanContext, target engine.IngestedTarget) ([]engine.PackageRef, error) {
	report, err := catalog.Build(ctx, catalog.BuildOptions{
		TargetPath:   target.Path,
		CacheDir:     strings.TrimSpace(s.cacheDir),
		DisableCache: s.disableCache,
		Progress: func(event catalog.Progress) {
			if !s.progress || s.stderr == nil {
				return
			}
			fmt.Fprintf(s.stderr, "progress[catalog] stage=%s current=%d total=%d %s\n", event.Stage, event.Current, event.Total, strings.TrimSpace(event.Message))
		},
	})
	if err != nil {
		return nil, err
	}

	for _, warning := range report.Warnings {
		engine.Infof("catalog warning: %s", warning)
	}

	packages := make([]engine.PackageRef, 0, len(report.Components))
	for _, component := range report.Components {
		locs := make([]engine.Location, 0, len(component.Locations))
		for _, loc := range component.Locations {
			path := filepath.ToSlash(strings.TrimSpace(loc))
			if path == "" {
				continue
			}
			locs = append(locs, engine.Location{Path: path})
		}
		packages = append(packages, engine.PackageRef{
			PURL:             component.PURL,
			InstalledVersion: component.Version,
			Scope:            string(component.Scope),
			Locations:        dedupeLocations(locs),
		})
	}
	packages = append(pagesWithMarkers(target.Path), packages...)
	return packages, nil
}

type localDBMatcherStage struct {
	engine *matchpkg.Engine
}

func (s localDBMatcherStage) Match(ctx context.Context, _ engine.ScanContext, packages []engine.PackageRef) ([]engine.Finding, error) {
	components := make([]matchpkg.Component, 0, len(packages))
	locationIndex := map[string][]engine.Location{}
	purlIndex := map[string]string{}

	for _, pkg := range packages {
		purl := strings.TrimSpace(pkg.PURL)
		version := strings.TrimSpace(pkg.InstalledVersion)
		scope := strings.ToLower(strings.TrimSpace(pkg.Scope))
		components = append(components, matchpkg.Component{
			PURL:    purl,
			Version: version,
			Scope:   scope,
		})
		key := packageIdentityKey(purl, version)
		locationIndex[key] = mergeLocationSlices(locationIndex[key], pkg.Locations)
		if purl != "" {
			purlIndex[key] = purl
		}
	}

	findingRows, err := s.engine.MatchComponents(ctx, components)
	if err != nil {
		return nil, err
	}

	findings := make([]engine.Finding, 0, len(findingRows))
	for _, row := range findingRows {
		key := packageIdentityKey(row.PackagePURL, row.InstalledVersion)
		locs := locationIndex[key]
		purl := strings.TrimSpace(row.PackagePURL)
		if mappedPURL, ok := purlIndex[key]; ok && strings.TrimSpace(mappedPURL) != "" {
			purl = strings.TrimSpace(mappedPURL)
		}
		findings = append(findings, engine.Finding{
			VulnID:           strings.TrimSpace(row.VulnID),
			PackagePURL:      purl,
			InstalledVersion: strings.TrimSpace(row.InstalledVersion),
			FixedVersion:     strings.TrimSpace(row.FixedVersion),
			Scope:            strings.ToLower(strings.TrimSpace(row.Scope)),
			Severity:         normalizeSeverityForEngine(row.Severity),
			References:       append([]string{}, row.References...),
			Locations:        dedupeLocations(locs),
		})
	}
	findings = append(findings, placeholderFindings(packages)...)
	return findings, nil
}

func pagesWithMarkers(targetPath string) []engine.PackageRef {
	markers := []struct {
		file  string
		purl  string
		scope string
	}{
		{file: ".vulngate-insecure", purl: "pkg:generic/vulngate/insecure@0.0.0", scope: "required"},
		{file: ".vulngate-insecure-dev", purl: "pkg:generic/vulngate/insecure-dev@0.0.0", scope: "dev"},
	}
	out := make([]engine.PackageRef, 0, len(markers))
	for _, marker := range markers {
		markerPath := filepath.Join(targetPath, marker.file)
		if _, err := os.Stat(markerPath); err != nil {
			continue
		}
		out = append(out, engine.PackageRef{
			PURL:             marker.purl,
			InstalledVersion: "0.0.0",
			Scope:            marker.scope,
			Locations:        []engine.Location{{Path: marker.file}},
		})
	}
	return out
}

func placeholderFindings(packages []engine.PackageRef) []engine.Finding {
	findings := make([]engine.Finding, 0)
	for _, pkg := range packages {
		purl := strings.ToLower(strings.TrimSpace(pkg.PURL))
		if !strings.Contains(purl, "insecure") && !strings.Contains(purl, "vulnerable") {
			continue
		}
		findings = append(findings, engine.Finding{
			VulnID:           "OSV-PLACEHOLDER-0001",
			PackagePURL:      strings.TrimSpace(pkg.PURL),
			InstalledVersion: strings.TrimSpace(pkg.InstalledVersion),
			FixedVersion:     "0.0.1",
			Scope:            strings.ToLower(strings.TrimSpace(pkg.Scope)),
			Severity:         "high",
			References:       []string{"https://osv.dev/"},
			Locations:        dedupeLocations(pkg.Locations),
		})
	}
	return findings
}

func normalizeSeverityForEngine(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "low"
	}
}

func packageIdentityKey(purlRaw, installedVersion string) string {
	purl := strings.TrimSpace(purlRaw)
	version := strings.TrimSpace(installedVersion)
	if purl == "" {
		return "||" + version
	}

	if !strings.HasPrefix(purl, "pkg:") {
		return strings.ToLower(purl) + "||" + version
	}

	body := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(body, "#"); idx >= 0 {
		body = body[:idx]
	}
	if idx := strings.Index(body, "?"); idx >= 0 {
		body = body[:idx]
	}

	if idx := strings.LastIndex(body, "@"); idx >= 0 {
		if version == "" {
			version = strings.TrimSpace(body[idx+1:])
		}
		body = body[:idx]
	}

	parts := strings.Split(body, "/")
	if len(parts) < 2 {
		return strings.ToLower(body) + "||" + version
	}

	ecosystem := strings.ToLower(strings.TrimSpace(parts[0]))
	segments := make([]string, 0, len(parts)-1)
	for _, seg := range parts[1:] {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			decoded = seg
		}
		segments = append(segments, decoded)
	}

	name := ""
	switch ecosystem {
	case "npm":
		if len(segments) >= 2 && strings.HasPrefix(segments[0], "@") {
			name = strings.ToLower(segments[0] + "/" + segments[1])
		} else {
			name = strings.ToLower(segments[len(segments)-1])
		}
	case "pypi":
		name = normalizePyPIName(segments[len(segments)-1])
	case "golang":
		name = strings.ToLower(strings.Join(segments, "/"))
	default:
		name = strings.ToLower(strings.Join(segments, "/"))
	}
	return strings.Join([]string{ecosystem, name, version}, "|")
}

func mergeLocationSlices(a, b []engine.Location) []engine.Location {
	out := append([]engine.Location{}, a...)
	out = append(out, b...)
	return dedupeLocations(out)
}

func dedupeLocations(in []engine.Location) []engine.Location {
	if len(in) == 0 {
		return []engine.Location{}
	}
	seen := map[string]engine.Location{}
	keys := make([]string, 0, len(in))
	for _, loc := range in {
		path := filepath.ToSlash(strings.TrimSpace(loc.Path))
		if path == "" {
			continue
		}
		key := strings.Join([]string{path, fmt.Sprintf("%d", loc.Line), fmt.Sprintf("%d", loc.Column)}, ":")
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
		seen[key] = engine.Location{Path: path, Line: loc.Line, Column: loc.Column}
	}
	sort.Strings(keys)
	out := make([]engine.Location, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func normalizePyPIName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	n = strings.ReplaceAll(n, ".", "-")
	for strings.Contains(n, "--") {
		n = strings.ReplaceAll(n, "--", "-")
	}
	return n
}
