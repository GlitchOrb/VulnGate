package runtime

import (
	"fmt"
	"net/url"
	"strings"
)

type packageCoordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

func parsePURL(raw string) (packageCoordinate, error) {
	purl := strings.TrimSpace(raw)
	if !strings.HasPrefix(purl, "pkg:") {
		return packageCoordinate{}, fmt.Errorf("missing pkg prefix")
	}

	body := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(body, "#"); idx >= 0 {
		body = body[:idx]
	}
	if idx := strings.Index(body, "?"); idx >= 0 {
		body = body[:idx]
	}

	version := ""
	if at := strings.LastIndex(body, "@"); at >= 0 {
		version = strings.TrimSpace(body[at+1:])
		body = body[:at]
	}

	parts := strings.Split(body, "/")
	if len(parts) < 2 {
		return packageCoordinate{}, fmt.Errorf("missing package name")
	}

	typeRaw := strings.ToLower(strings.TrimSpace(parts[0]))
	nameParts := parts[1:]
	for i := range nameParts {
		decoded, err := url.PathUnescape(nameParts[i])
		if err == nil {
			nameParts[i] = decoded
		}
	}

	coord := packageCoordinate{Ecosystem: typeRaw, Version: strings.TrimSpace(version)}
	switch typeRaw {
	case "npm":
		coord.Ecosystem = "npm"
		if len(nameParts) >= 2 && strings.HasPrefix(nameParts[0], "@") {
			coord.Name = strings.ToLower(nameParts[0] + "/" + nameParts[1])
		} else {
			coord.Name = strings.ToLower(nameParts[len(nameParts)-1])
		}
	case "pypi":
		coord.Ecosystem = "pypi"
		coord.Name = normalizePythonName(nameParts[len(nameParts)-1])
	case "golang":
		coord.Ecosystem = "golang"
		coord.Name = strings.ToLower(strings.Join(nameParts, "/"))
	default:
		coord.Name = strings.ToLower(strings.Join(nameParts, "/"))
	}
	return coord, nil
}

func normalizePythonName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	n = strings.ReplaceAll(n, ".", "-")
	for strings.Contains(n, "--") {
		n = strings.ReplaceAll(n, "--", "-")
	}
	return n
}

func exactKey(coord packageCoordinate) string {
	return strings.Join([]string{coord.Ecosystem, coord.Name, coord.Version}, "|")
}

func packageKey(coord packageCoordinate) string {
	return strings.Join([]string{coord.Ecosystem, coord.Name}, "|")
}

func canonicalPURL(coord packageCoordinate) string {
	parts := strings.Split(coord.Name, "/")
	for i := range parts {
		escaped := url.PathEscape(parts[i])
		escaped = strings.ReplaceAll(escaped, "@", "%40")
		parts[i] = escaped
	}

	purl := "pkg:" + coord.Ecosystem + "/" + strings.Join(parts, "/")
	if strings.TrimSpace(coord.Version) != "" {
		purl += "@" + url.PathEscape(coord.Version)
	}
	return purl
}
