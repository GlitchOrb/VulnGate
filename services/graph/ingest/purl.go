package ingest

import (
	"fmt"
	"net/url"
	"strings"
)

type purlParts struct {
	PURL      string
	Ecosystem string
	Name      string
	Version   string
}

func parsePURL(raw string) (purlParts, error) {
	purl := strings.TrimSpace(raw)
	if !strings.HasPrefix(purl, "pkg:") {
		return purlParts{}, fmt.Errorf("invalid purl %q: missing pkg: prefix", raw)
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
		return purlParts{}, fmt.Errorf("invalid purl %q: missing package name", raw)
	}

	typeRaw := strings.ToLower(strings.TrimSpace(parts[0]))
	nameParts := parts[1:]
	for i := range nameParts {
		decoded, err := url.PathUnescape(nameParts[i])
		if err == nil {
			nameParts[i] = decoded
		}
	}

	name := strings.ToLower(strings.Join(nameParts, "/"))
	if typeRaw == "npm" && len(nameParts) >= 2 && strings.HasPrefix(nameParts[0], "@") {
		name = strings.ToLower(nameParts[0] + "/" + nameParts[1])
	}

	return purlParts{
		PURL:      strings.ToLower(purl),
		Ecosystem: typeRaw,
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(version),
	}, nil
}

func fallbackPURL(name, version string) string {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	cleanVersion := strings.TrimSpace(version)
	if cleanName == "" {
		cleanName = "unknown"
	}
	purl := "pkg:generic/" + cleanName
	if cleanVersion != "" {
		purl += "@" + cleanVersion
	}
	return purl
}
