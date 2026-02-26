package catalog

import (
	"net/url"
	"regexp"
	"strings"
)

var pep503Pattern = regexp.MustCompile(`[-_.]+`)

func BuildPURL(ecosystem Ecosystem, name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ""
	}

	var purl string
	switch ecosystem {
	case EcosystemNPM:
		purl = buildNPMPURL(name)
	case EcosystemPython:
		normalized := pep503Pattern.ReplaceAllString(strings.ToLower(name), "-")
		purl = "pkg:pypi/" + escapePath(normalized)
	case EcosystemGo:
		purl = "pkg:golang/" + escapePath(name)
	default:
		purl = "pkg:generic/" + escapePath(strings.ToLower(name))
	}

	if version != "" {
		purl += "@" + escapeVersion(version)
	}
	return purl
}

func buildNPMPURL(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	parts := strings.Split(n, "/")
	if len(parts) == 2 && strings.HasPrefix(parts[0], "@") {
		return "pkg:npm/" + escapePath(parts[0]) + "/" + escapePath(parts[1])
	}
	return "pkg:npm/" + escapePath(n)
}

func escapePath(value string) string {
	if value == "" {
		return ""
	}
	segments := strings.Split(value, "/")
	for i := range segments {
		escaped := url.PathEscape(segments[i])
		escaped = strings.ReplaceAll(escaped, "@", "%40")
		segments[i] = escaped
	}
	return strings.Join(segments, "/")
}

func escapeVersion(version string) string {
	return url.PathEscape(strings.TrimSpace(version))
}
