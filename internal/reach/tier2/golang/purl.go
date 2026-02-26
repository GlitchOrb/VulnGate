package golang

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

	coord := packageCoordinate{
		Ecosystem: typeRaw,
		Name:      strings.ToLower(strings.TrimSpace(strings.Join(nameParts, "/"))),
		Version:   strings.TrimSpace(version),
	}
	if typeRaw == "golang" {
		coord.Ecosystem = "golang"
	}
	return coord, nil
}
