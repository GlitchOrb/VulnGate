package match

import (
	"fmt"
	"net/url"
	"strings"
)

type packageCoordinate struct {
	ecosystem string
	name      string
	version   string
}

func parseComponentPURL(raw string) (packageCoordinate, error) {
	purl := strings.TrimSpace(raw)
	if !strings.HasPrefix(purl, "pkg:") {
		return packageCoordinate{}, fmt.Errorf("invalid purl %q: missing pkg: prefix", raw)
	}

	body := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(body, "#"); idx >= 0 {
		body = body[:idx]
	}
	if idx := strings.Index(body, "?"); idx >= 0 {
		body = body[:idx]
	}

	version := ""
	if idx := strings.LastIndex(body, "@"); idx >= 0 {
		version = body[idx+1:]
		body = body[:idx]
	}

	parts := strings.Split(body, "/")
	if len(parts) < 2 {
		return packageCoordinate{}, fmt.Errorf("invalid purl %q: expected type and name", raw)
	}

	typeRaw := strings.ToLower(strings.TrimSpace(parts[0]))
	nameParts := parts[1:]
	for i := range nameParts {
		decoded, err := url.PathUnescape(nameParts[i])
		if err != nil {
			decoded = nameParts[i]
		}
		nameParts[i] = decoded
	}

	coord := packageCoordinate{}
	switch typeRaw {
	case "npm":
		coord.ecosystem = "npm"
		if len(nameParts) >= 2 && strings.HasPrefix(nameParts[0], "@") {
			coord.name = strings.ToLower(nameParts[0] + "/" + nameParts[1])
		} else {
			coord.name = strings.ToLower(nameParts[len(nameParts)-1])
		}
	case "pypi":
		coord.ecosystem = "pypi"
		coord.name = normalizePyPIName(nameParts[len(nameParts)-1])
	case "golang":
		coord.ecosystem = "golang"
		coord.name = strings.ToLower(strings.Join(nameParts, "/"))
	default:
		coord.ecosystem = typeRaw
		coord.name = strings.ToLower(strings.Join(nameParts, "/"))
	}

	coord.version = strings.TrimSpace(version)
	return coord, nil
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
