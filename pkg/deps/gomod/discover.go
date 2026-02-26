package gomod

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GlitchOrb/vulngate/pkg/model"
)

var singleRequirePattern = regexp.MustCompile(`^require\s+([^\s]+)\s+([^\s]+)`)
var blockRequirePattern = regexp.MustCompile(`^([^\s]+)\s+([^\s]+)`)

func Discover(targetPath string) ([]model.Dependency, error) {
	goModPath := filepath.Join(targetPath, "go.mod")
	f, err := os.Open(goModPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []model.Dependency{}, nil
		}
		return nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer f.Close()

	deps := []model.Dependency{}
	seen := map[string]bool{}
	inBlock := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "require (") {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}

		if inBlock {
			line = strings.Split(line, "//")[0]
			line = strings.TrimSpace(line)
			match := blockRequirePattern.FindStringSubmatch(line)
			if len(match) != 3 {
				continue
			}
			addDep(&deps, seen, match[1], match[2])
			continue
		}

		match := singleRequirePattern.FindStringSubmatch(line)
		if len(match) == 3 {
			addDep(&deps, seen, match[1], match[2])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go.mod: %w", err)
	}

	return deps, nil
}

func addDep(deps *[]model.Dependency, seen map[string]bool, modulePath, version string) {
	version = strings.TrimPrefix(version, "v")
	purl := fmt.Sprintf("pkg:golang/%s@%s", strings.ToLower(modulePath), version)
	if seen[purl] {
		return
	}
	seen[purl] = true
	*deps = append(*deps, model.Dependency{PURL: purl, Version: version})
}
