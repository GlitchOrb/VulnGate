package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type packageLockFile struct {
	Packages     map[string]packageLockPackage    `json:"packages"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

type packageLockPackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dev             bool              `json:"dev"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type packageLockDependency struct {
	Version      string                           `json:"version"`
	Dev          bool                             `json:"dev"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

func parsePackageLock(path string) ([]Component, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock file: %w", err)
	}

	var lock packageLockFile
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("decode package-lock json: %w", err)
	}

	components := []Component{}
	seen := map[string]bool{}

	rootDeps := map[string]Scope{}
	if root, ok := lock.Packages[""]; ok {
		for name := range root.Dependencies {
			rootDeps[name] = ScopeRequired
		}
		for name := range root.DevDependencies {
			rootDeps[name] = ScopeDev
		}
	}

	if len(lock.Packages) > 0 {
		keys := make([]string, 0, len(lock.Packages))
		for key := range lock.Packages {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			if key == "" {
				continue
			}
			entry := lock.Packages[key]
			name := strings.TrimSpace(entry.Name)
			if name == "" {
				name = nameFromNodeModulesPath(key)
			}
			version := strings.TrimSpace(entry.Version)
			if name == "" || version == "" {
				continue
			}

			scope := ScopeTransitive
			if entry.Dev {
				scope = ScopeDev
			} else if s, ok := rootDeps[name]; ok {
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
		return components, nil
	}

	if len(lock.Dependencies) == 0 {
		return []Component{}, nil
	}

	walkPackageLockDeps(lock.Dependencies, ScopeRequired, path, seen, &components)
	return components, nil
}

func walkPackageLockDeps(deps map[string]packageLockDependency, parentScope Scope, path string, seen map[string]bool, out *[]Component) {
	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		dep := deps[name]
		scope := parentScope
		if dep.Dev {
			scope = ScopeDev
		}

		version := strings.TrimSpace(dep.Version)
		if strings.TrimSpace(name) != "" && version != "" {
			component := Component{
				PURL:      BuildPURL(EcosystemNPM, name, version),
				Name:      name,
				Version:   version,
				Scope:     scope,
				Ecosystem: EcosystemNPM,
				Locations: []string{path},
			}
			key := component.PURL + "|" + string(component.Scope)
			if !seen[key] {
				seen[key] = true
				*out = append(*out, component)
			}
		}

		if len(dep.Dependencies) > 0 {
			walkPackageLockDeps(dep.Dependencies, scope, path, seen, out)
		}
	}
}

func nameFromNodeModulesPath(path string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return ""
	}
	name := strings.TrimSpace(path[idx+len(marker):])
	if name == "" {
		return ""
	}
	name = strings.TrimPrefix(name, "/")
	parts := strings.Split(name, "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "@") {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}
