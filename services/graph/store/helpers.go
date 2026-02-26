package store

import (
	"sort"
	"strings"
)

func normalizeID(raw string) string {
	return strings.TrimSpace(raw)
}

func normalizePURL(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

type stringSet map[string]bool

func newStringSet(items ...string) stringSet {
	s := stringSet{}
	for _, item := range items {
		n := strings.TrimSpace(item)
		if n == "" {
			continue
		}
		s[n] = true
	}
	return s
}

func (s stringSet) add(item string) {
	if s == nil {
		return
	}
	n := strings.TrimSpace(item)
	if n == "" {
		return
	}
	s[n] = true
}

func (s stringSet) has(item string) bool {
	if s == nil {
		return false
	}
	return s[strings.TrimSpace(item)]
}

func (s stringSet) toSortedSlice() []string {
	if len(s) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(s))
	for item := range s {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
