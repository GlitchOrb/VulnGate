package catalog

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

func parsePNPMLock(path string) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pnpm lock file: %w", err)
	}
	defer f.Close()

	rootScopes := map[string]Scope{}
	components := []Component{}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(f)
	section := ""
	inRootImporter := false
	currentImporterDepsScope := ScopeUnknown

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := leadingSpaces(line)
		if indent == 0 {
			inRootImporter = false
			currentImporterDepsScope = ScopeUnknown
			switch strings.TrimSuffix(trimmed, ":") {
			case "importers":
				section = "importers"
			case "packages":
				section = "packages"
			default:
				section = ""
			}
			continue
		}

		switch section {
		case "importers":
			handlePNPMImporterLine(trimmed, indent, &inRootImporter, &currentImporterDepsScope, rootScopes)
		case "packages":
			if indent == 2 && strings.HasSuffix(trimmed, ":") {
				rawKey := trimQuotes(strings.TrimSuffix(trimmed, ":"))
				name, version := parsePNPMPackageKey(rawKey)
				if name == "" || version == "" {
					continue
				}
				scope := ScopeTransitive
				if s, ok := rootScopes[name]; ok {
					scope = s
				}
				component := Component{
					PURL:      BuildPURL(EcosystemNPM, name, version),
					Name:      name,
					Version:   version,
					Scope:     scope,
					Ecosystem: EcosystemNPM,
					Locations: []string{path},
				}
				key := component.PURL + "|" + string(component.Scope)
				if seen[key] {
					continue
				}
				seen[key] = true
				components = append(components, component)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan pnpm lock file: %w", err)
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

func handlePNPMImporterLine(trimmed string, indent int, inRootImporter *bool, depScope *Scope, rootScopes map[string]Scope) {
	if indent == 2 && strings.HasSuffix(trimmed, ":") {
		name := trimQuotes(strings.TrimSuffix(trimmed, ":"))
		*inRootImporter = (name == "." || name == "")
		*depScope = ScopeUnknown
		return
	}

	if !*inRootImporter {
		return
	}

	if indent == 4 && strings.HasSuffix(trimmed, ":") {
		switch strings.TrimSuffix(trimmed, ":") {
		case "dependencies":
			*depScope = ScopeRequired
		case "devDependencies":
			*depScope = ScopeDev
		case "optionalDependencies":
			*depScope = ScopeOptional
		default:
			*depScope = ScopeUnknown
		}
		return
	}

	if *depScope == ScopeUnknown {
		return
	}

	if indent >= 6 && strings.HasSuffix(trimmed, ":") {
		name := trimQuotes(strings.TrimSuffix(trimmed, ":"))
		if name == "version" || name == "specifier" || strings.Contains(name, " ") {
			return
		}
		if _, exists := rootScopes[name]; !exists {
			rootScopes[name] = *depScope
		}
	}
}

func parsePNPMPackageKey(key string) (string, string) {
	k := strings.TrimSpace(key)
	k = strings.TrimPrefix(k, "/")
	if idx := strings.Index(k, "("); idx >= 0 {
		k = k[:idx]
	}

	at := strings.LastIndex(k, "@")
	if at <= 0 || at == len(k)-1 {
		return "", ""
	}
	name := k[:at]
	version := k[at+1:]
	return name, version
}

func trimQuotes(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "\"")
	v = strings.TrimSuffix(v, "\"")
	v = strings.TrimPrefix(v, "'")
	v = strings.TrimSuffix(v, "'")
	return strings.TrimSpace(v)
}

func leadingSpaces(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			return i
		}
	}
	return len(s)
}
