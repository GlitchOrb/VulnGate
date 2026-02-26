package tier1

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

type graphIndex struct {
	runtime       map[packageCoordinate]bool
	all           map[packageCoordinate]bool
	ecosystems    map[string]bool
	parseWarnings []string
}

func newGraphIndex() graphIndex {
	return graphIndex{
		runtime:       map[packageCoordinate]bool{},
		all:           map[packageCoordinate]bool{},
		ecosystems:    map[string]bool{},
		parseWarnings: []string{},
	}
}

func (g *graphIndex) load(ctx context.Context, targetPath string, profile Profile) error {
	packageLockFiles := make([]string, 0)

	err := filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".hg", ".svn":
				return filepath.SkipDir
			}
			return nil
		}

		if d.Name() == "package-lock.json" {
			packageLockFiles = append(packageLockFiles, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan target for lockfiles: %w", err)
	}

	sort.Strings(packageLockFiles)
	for _, lockPath := range packageLockFiles {
		runtimeRefs, allRefs, parseErr := parsePackageLockRuntime(lockPath, profile)
		if parseErr != nil {
			g.parseWarnings = append(g.parseWarnings, fmt.Sprintf("%s: %v", lockPath, parseErr))
			continue
		}
		g.ecosystems["npm"] = true
		for _, ref := range runtimeRefs {
			g.runtime[ref] = true
		}
		for _, ref := range allRefs {
			g.all[ref] = true
		}
	}
	return nil
}

func (g graphIndex) hasEcosystem(ecosystem string) bool {
	return g.ecosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
}

func (g graphIndex) runtimeContains(coord packageCoordinate) bool {
	return g.runtime[normalizeCoordinate(coord)]
}

func (g graphIndex) allContains(coord packageCoordinate) bool {
	return g.all[normalizeCoordinate(coord)]
}

func normalizeCoordinate(coord packageCoordinate) packageCoordinate {
	return packageCoordinate{
		Ecosystem: strings.ToLower(strings.TrimSpace(coord.Ecosystem)),
		Name:      strings.ToLower(strings.TrimSpace(coord.Name)),
		Version:   strings.TrimSpace(coord.Version),
	}
}
