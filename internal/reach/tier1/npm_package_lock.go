package tier1

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

type lockNode struct {
	Name    string
	Version string
	Dev     bool
	Deps    []string
}

func parsePackageLockRuntime(path string, profile Profile) ([]packageCoordinate, []packageCoordinate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read package-lock file: %w", err)
	}

	var lock packageLockFile
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, nil, fmt.Errorf("decode package-lock json: %w", err)
	}

	if len(lock.Packages) > 0 {
		return parseRuntimeFromPackages(lock, profile), parseAllFromPackages(lock), nil
	}
	if len(lock.Dependencies) > 0 {
		return parseRuntimeFromDependencies(lock.Dependencies, profile), parseAllFromDependencies(lock.Dependencies), nil
	}
	return []packageCoordinate{}, []packageCoordinate{}, nil
}

func parseRuntimeFromPackages(lock packageLockFile, profile Profile) []packageCoordinate {
	nodes := map[string]lockNode{}
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
			name = packageNameFromPath(key)
		}
		version := strings.TrimSpace(entry.Version)
		if name == "" || version == "" {
			continue
		}
		deps := sortedKeys(entry.Dependencies)
		nodes[key] = lockNode{
			Name:    strings.ToLower(name),
			Version: version,
			Dev:     entry.Dev,
			Deps:    deps,
		}
	}

	runtimeSet := map[packageCoordinate]bool{}
	visited := map[string]bool{}
	queue := []string{}

	root := lock.Packages[""]
	rootDepNames := sortedKeys(root.Dependencies)
	if profile == ProfileDev {
		rootDepNames = mergeStringSlices(rootDepNames, sortedKeys(root.DevDependencies))
	}

	for _, depName := range rootDepNames {
		if resolved := resolveNodePath("", depName, nodes); resolved != "" {
			queue = append(queue, resolved)
		}
	}

	if len(queue) == 0 {
		for path, node := range nodes {
			if profile == ProfileProd && node.Dev {
				continue
			}
			queue = append(queue, path)
		}
		sort.Strings(queue)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true

		node, ok := nodes[current]
		if !ok {
			continue
		}
		runtimeSet[packageCoordinate{Ecosystem: "npm", Name: node.Name, Version: node.Version}] = true

		for _, depName := range node.Deps {
			if resolved := resolveNodePath(current, depName, nodes); resolved != "" {
				queue = append(queue, resolved)
			}
		}
	}

	out := make([]packageCoordinate, 0, len(runtimeSet))
	for coord := range runtimeSet {
		out = append(out, normalizeCoordinate(coord))
	}
	sortCoordinates(out)
	return out
}

func parseAllFromPackages(lock packageLockFile) []packageCoordinate {
	allSet := map[packageCoordinate]bool{}
	for path, entry := range lock.Packages {
		if path == "" {
			continue
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = packageNameFromPath(path)
		}
		version := strings.TrimSpace(entry.Version)
		if name == "" || version == "" {
			continue
		}
		allSet[packageCoordinate{Ecosystem: "npm", Name: strings.ToLower(name), Version: version}] = true
	}
	out := make([]packageCoordinate, 0, len(allSet))
	for coord := range allSet {
		out = append(out, normalizeCoordinate(coord))
	}
	sortCoordinates(out)
	return out
}

func parseRuntimeFromDependencies(deps map[string]packageLockDependency, profile Profile) []packageCoordinate {
	runtimeSet := map[packageCoordinate]bool{}
	var walk func(name string, dep packageLockDependency, parentRuntime bool)
	walk = func(name string, dep packageLockDependency, parentRuntime bool) {
		version := strings.TrimSpace(dep.Version)
		depRuntime := parentRuntime && (!dep.Dev || profile == ProfileDev)
		if strings.TrimSpace(name) != "" && version != "" && depRuntime {
			runtimeSet[packageCoordinate{Ecosystem: "npm", Name: strings.ToLower(strings.TrimSpace(name)), Version: version}] = true
		}
		for _, childName := range sortedKeysDependency(dep.Dependencies) {
			walk(childName, dep.Dependencies[childName], depRuntime)
		}
	}
	for _, name := range sortedKeysDependency(deps) {
		walk(name, deps[name], true)
	}
	out := make([]packageCoordinate, 0, len(runtimeSet))
	for coord := range runtimeSet {
		out = append(out, normalizeCoordinate(coord))
	}
	sortCoordinates(out)
	return out
}

func parseAllFromDependencies(deps map[string]packageLockDependency) []packageCoordinate {
	allSet := map[packageCoordinate]bool{}
	var walk func(name string, dep packageLockDependency)
	walk = func(name string, dep packageLockDependency) {
		version := strings.TrimSpace(dep.Version)
		if strings.TrimSpace(name) != "" && version != "" {
			allSet[packageCoordinate{Ecosystem: "npm", Name: strings.ToLower(strings.TrimSpace(name)), Version: version}] = true
		}
		for _, childName := range sortedKeysDependency(dep.Dependencies) {
			walk(childName, dep.Dependencies[childName])
		}
	}
	for _, name := range sortedKeysDependency(deps) {
		walk(name, deps[name])
	}
	out := make([]packageCoordinate, 0, len(allSet))
	for coord := range allSet {
		out = append(out, normalizeCoordinate(coord))
	}
	sortCoordinates(out)
	return out
}

func resolveNodePath(parentPath, depName string, nodes map[string]lockNode) string {
	dep := strings.TrimSpace(depName)
	if dep == "" {
		return ""
	}

	current := strings.TrimSpace(parentPath)
	for {
		candidate := joinNodePath(current, dep)
		if _, ok := nodes[candidate]; ok {
			return candidate
		}

		next, ok := parentNodePath(current)
		if !ok {
			break
		}
		current = next
	}

	fallback := "node_modules/" + dep
	if _, ok := nodes[fallback]; ok {
		return fallback
	}
	if _, ok := nodes[dep]; ok {
		return dep
	}
	return ""
}

func joinNodePath(parent, dep string) string {
	if strings.TrimSpace(parent) == "" {
		return "node_modules/" + dep
	}
	return parent + "/node_modules/" + dep
}

func parentNodePath(path string) (string, bool) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", false
	}
	idx := strings.LastIndex(p, "/node_modules/")
	if idx >= 0 {
		return p[:idx], true
	}
	if strings.HasPrefix(p, "node_modules/") {
		return "", true
	}
	return "", false
}

func packageNameFromPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	idx := strings.LastIndex(trimmed, "node_modules/")
	if idx < 0 {
		return ""
	}
	tail := strings.TrimPrefix(trimmed[idx+len("node_modules/"):], "/")
	parts := strings.Split(tail, "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "@") {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func sortedKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedKeysDependency(values map[string]packageLockDependency) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortCoordinates(values []packageCoordinate) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Ecosystem != values[j].Ecosystem {
			return values[i].Ecosystem < values[j].Ecosystem
		}
		if values[i].Name != values[j].Name {
			return values[i].Name < values[j].Name
		}
		return values[i].Version < values[j].Version
	})
}

func mergeStringSlices(a, b []string) []string {
	set := map[string]bool{}
	for _, item := range a {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[item] = true
	}
	for _, item := range b {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[item] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
