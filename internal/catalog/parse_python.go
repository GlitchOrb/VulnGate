package catalog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var requirementPattern = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(==|~=|>=|<=|!=|>|<)?\s*([A-Za-z0-9*+_.\-]+)?`)

func parsePoetryLock(path string) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open poetry lock file: %w", err)
	}
	defer f.Close()

	type poetryPackage struct {
		name     string
		version  string
		category string
		group    string
		optional bool
	}

	flush := func(current *poetryPackage, out *[]Component) {
		if current == nil {
			return
		}
		if strings.TrimSpace(current.name) == "" || strings.TrimSpace(current.version) == "" {
			return
		}

		scope := poetryScope(current.category, current.group, current.optional)
		*out = append(*out, Component{
			PURL:      BuildPURL(EcosystemPython, current.name, current.version),
			Name:      current.name,
			Version:   current.version,
			Scope:     scope,
			Ecosystem: EcosystemPython,
			Locations: []string{path},
		})
	}

	components := []Component{}
	var current *poetryPackage

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			flush(current, &components)
			current = &poetryPackage{}
			continue
		}
		if current == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "name ="):
			current.name = parseTOMLString(line)
		case strings.HasPrefix(line, "version ="):
			current.version = parseTOMLString(line)
		case strings.HasPrefix(line, "category ="):
			current.category = parseTOMLString(line)
		case strings.HasPrefix(line, "group ="):
			current.group = parseTOMLString(line)
		case strings.HasPrefix(line, "optional ="):
			current.optional = strings.Contains(strings.ToLower(line), "true")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan poetry lock file: %w", err)
	}

	flush(current, &components)
	return dedupeComponents(components), nil
}

func parseRequirements(path string) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open requirements file: %w", err)
	}
	defer f.Close()

	scope := requirementsScope(path)
	components := []Component{}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "-e ") {
			continue
		}

		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		match := requirementPattern.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}

		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		version := ""
		if len(match) >= 4 {
			version = strings.TrimSpace(match[3])
		}
		if version == "" {
			continue
		}

		component := Component{
			PURL:      BuildPURL(EcosystemPython, name, version),
			Name:      name,
			Version:   version,
			Scope:     scope,
			Ecosystem: EcosystemPython,
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
		return nil, fmt.Errorf("scan requirements file: %w", err)
	}

	return components, nil
}

func parseTOMLString(line string) string {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return ""
	}
	value := strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, "\"")
	value = strings.Trim(value, "'")
	return strings.TrimSpace(value)
}

func poetryScope(category, group string, optional bool) Scope {
	c := strings.ToLower(strings.TrimSpace(category))
	g := strings.ToLower(strings.TrimSpace(group))

	switch {
	case strings.Contains(c, "test") || strings.Contains(g, "test"):
		return ScopeTest
	case strings.Contains(c, "dev") || strings.Contains(g, "dev"):
		return ScopeDev
	case optional:
		return ScopeOptional
	default:
		return ScopeRequired
	}
}

func requirementsScope(path string) Scope {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(name, "test"):
		return ScopeTest
	case strings.Contains(name, "dev"):
		return ScopeDev
	default:
		return ScopeRequired
	}
}

func dedupeComponents(in []Component) []Component {
	seen := map[string]bool{}
	out := make([]Component, 0, len(in))
	for _, c := range in {
		key := c.PURL + "|" + string(c.Scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}
