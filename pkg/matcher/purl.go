package matcher

import (
	"fmt"
	"net/url"
	"strings"
)

type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

func ParsePURL(raw string) (PURL, error) {
	if !strings.HasPrefix(raw, "pkg:") {
		return PURL{}, fmt.Errorf("invalid purl %q: missing pkg: prefix", raw)
	}

	rest := strings.TrimPrefix(raw, "pkg:")
	var subpath string
	if idx := strings.Index(rest, "#"); idx >= 0 {
		subpath = rest[idx+1:]
		rest = rest[:idx]
	}

	qualifiers := map[string]string{}
	if idx := strings.Index(rest, "?"); idx >= 0 {
		q := rest[idx+1:]
		rest = rest[:idx]
		parsed, err := url.ParseQuery(q)
		if err != nil {
			return PURL{}, fmt.Errorf("invalid purl qualifiers: %w", err)
		}
		for k, v := range parsed {
			if len(v) > 0 {
				qualifiers[strings.ToLower(k)] = v[0]
			}
		}
	}

	var version string
	if idx := strings.LastIndex(rest, "@"); idx >= 0 {
		version = rest[idx+1:]
		rest = rest[:idx]
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return PURL{}, fmt.Errorf("invalid purl %q: expected type/name", raw)
	}

	p := PURL{
		Type:       strings.ToLower(parts[0]),
		Name:       strings.ToLower(parts[len(parts)-1]),
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}
	if len(parts) > 2 {
		p.Namespace = strings.ToLower(strings.Join(parts[1:len(parts)-1], "/"))
	}
	if p.Type == "" || p.Name == "" {
		return PURL{}, fmt.Errorf("invalid purl %q: empty type or name", raw)
	}
	return p, nil
}

func (p PURL) PackageKey() string {
	if p.Namespace == "" {
		return fmt.Sprintf("%s/%s", p.Type, p.Name)
	}
	return fmt.Sprintf("%s/%s/%s", p.Type, p.Namespace, p.Name)
}
