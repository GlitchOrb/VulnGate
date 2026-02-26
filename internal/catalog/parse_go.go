package catalog

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var goModSingleRequirePattern = regexp.MustCompile(`^require\s+([^\s]+)\s+([^\s]+)`)
var goModBlockRequirePattern = regexp.MustCompile(`^([^\s]+)\s+([^\s]+)`)

func parseGoMod(path string) ([]Component, map[string]Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer f.Close()

	components := []Component{}
	seen := map[string]bool{}
	direct := map[string]Scope{}

	inRequireBlock := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		modulePath := ""
		version := ""
		scope := ScopeRequired

		if inRequireBlock {
			rawLine := line
			if strings.Contains(strings.ToLower(rawLine), "indirect") {
				scope = ScopeTransitive
			}
			line = strings.TrimSpace(strings.Split(rawLine, "//")[0])
			match := goModBlockRequirePattern.FindStringSubmatch(line)
			if len(match) == 3 {
				modulePath = match[1]
				version = match[2]
			}
		} else {
			if strings.Contains(strings.ToLower(line), "indirect") {
				scope = ScopeTransitive
			}
			line = strings.TrimSpace(strings.Split(line, "//")[0])
			match := goModSingleRequirePattern.FindStringSubmatch(line)
			if len(match) == 3 {
				modulePath = match[1]
				version = match[2]
			}
		}

		if modulePath == "" || version == "" {
			continue
		}

		version = strings.TrimPrefix(version, "v")
		component := Component{
			PURL:      BuildPURL(EcosystemGo, modulePath, version),
			Name:      modulePath,
			Version:   version,
			Scope:     scope,
			Ecosystem: EcosystemGo,
			Locations: []string{path},
		}
		key := component.PURL + "|" + string(component.Scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, component)
		direct[component.PURL] = scope
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan go.mod: %w", err)
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		if components[i].Version != components[j].Version {
			return components[i].Version < components[j].Version
		}
		return components[i].Scope < components[j].Scope
	})

	return components, direct, nil
}

func parseGoSum(path string, direct map[string]Scope) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open go.sum: %w", err)
	}
	defer f.Close()

	components := []Component{}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		modulePath := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if modulePath == "" || version == "" {
			continue
		}

		version = strings.TrimSuffix(version, "/go.mod")
		version = strings.TrimPrefix(version, "v")
		if version == "" {
			continue
		}

		purl := BuildPURL(EcosystemGo, modulePath, version)
		scope := ScopeTransitive
		if s, ok := direct[purl]; ok {
			scope = s
		}

		component := Component{
			PURL:      purl,
			Name:      modulePath,
			Version:   version,
			Scope:     scope,
			Ecosystem: EcosystemGo,
			Locations: []string{path},
		}
		key := component.PURL + "|" + string(component.Scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, component)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go.sum: %w", err)
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		if components[i].Version != components[j].Version {
			return components[i].Version < components[j].Version
		}
		return components[i].Scope < components[j].Scope
	})

	return components, nil
}
