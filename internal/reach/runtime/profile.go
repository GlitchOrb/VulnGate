package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rawProfileDoc struct {
	Schema      string     `json:"schema"`
	GeneratedAt string     `json:"generatedAt"`
	Events      []rawEvent `json:"events"`
}

type rawEvent struct {
	PURL      string          `json:"purl"`
	Symbol    string          `json:"symbol"`
	Count     json.RawMessage `json:"count"`
	FirstSeen json.RawMessage `json:"firstSeen"`
	LastSeen  json.RawMessage `json:"lastSeen"`
}

func LoadProfileFile(path string) (Profile, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, nil, fmt.Errorf("read profile file: %w", err)
	}
	return ParseProfileJSON(raw)
}

func ParseProfileJSON(data []byte) (Profile, []string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Profile{}, nil, fmt.Errorf("empty profile payload")
	}

	warnings := []string{}
	profile := Profile{Schema: ProfileSchema}

	switch trimmed[0] {
	case '[':
		var rawEvents []rawEvent
		if err := json.Unmarshal(trimmed, &rawEvents); err != nil {
			return Profile{}, nil, fmt.Errorf("decode profile events array: %w", err)
		}
		events, eventWarnings := parseEvents(rawEvents)
		warnings = append(warnings, eventWarnings...)
		profile.Events = events
	default:
		var doc rawProfileDoc
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return Profile{}, nil, fmt.Errorf("decode profile object: %w", err)
		}
		if schema := strings.TrimSpace(doc.Schema); schema != "" {
			profile.Schema = schema
		}
		if generatedAt := strings.TrimSpace(doc.GeneratedAt); generatedAt != "" {
			t, err := parseTimestampString(generatedAt)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("invalid generatedAt %q: %v", generatedAt, err))
			} else {
				profile.GeneratedAt = t.UTC()
			}
		}
		events, eventWarnings := parseEvents(doc.Events)
		warnings = append(warnings, eventWarnings...)
		profile.Events = events
	}

	return NormalizeProfile(profile), warnings, nil
}

func WriteProfileFile(path string, profile Profile) error {
	normalized := NormalizeProfile(profile)
	if normalized.Schema == "" {
		normalized.Schema = ProfileSchema
	}
	if normalized.GeneratedAt.IsZero() {
		normalized.GeneratedAt = time.Now().UTC().Truncate(time.Second)
	}

	payload, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create profile directory: %w", err)
		}
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write profile file: %w", err)
	}
	return nil
}

func NormalizeProfile(profile Profile) Profile {
	out := Profile{
		Schema:      strings.TrimSpace(profile.Schema),
		GeneratedAt: profile.GeneratedAt.UTC(),
		Events:      []Event{},
	}
	if out.Schema == "" {
		out.Schema = ProfileSchema
	}

	type aggregate struct {
		Event
	}

	groups := map[string]aggregate{}
	order := make([]string, 0, len(profile.Events))

	for _, event := range profile.Events {
		coord, err := parsePURL(event.PURL)
		if err != nil {
			continue
		}
		purl := canonicalPURL(coord)
		symbol := strings.TrimSpace(event.Symbol)
		if symbol == "" {
			symbol = "(package)"
		}

		key := purl + "|" + symbol
		existing, ok := groups[key]
		if !ok {
			groups[key] = aggregate{Event: Event{
				PURL:      purl,
				Symbol:    symbol,
				Count:     event.Count,
				FirstSeen: normalizeTime(event.FirstSeen),
				LastSeen:  normalizeTime(event.LastSeen),
			}}
			order = append(order, key)
			continue
		}

		existing.Count += event.Count
		existing.FirstSeen = earlierTime(existing.FirstSeen, normalizeTime(event.FirstSeen))
		existing.LastSeen = laterTime(existing.LastSeen, normalizeTime(event.LastSeen))
		groups[key] = existing
	}

	sort.Strings(order)
	out.Events = make([]Event, 0, len(order))
	for _, key := range order {
		ev := groups[key].Event
		if ev.Count == 0 {
			continue
		}
		out.Events = append(out.Events, ev)
	}

	sort.Slice(out.Events, func(i, j int) bool {
		if out.Events[i].PURL != out.Events[j].PURL {
			return out.Events[i].PURL < out.Events[j].PURL
		}
		return out.Events[i].Symbol < out.Events[j].Symbol
	})

	return out
}

func parseEvents(rawEvents []rawEvent) ([]Event, []string) {
	events := make([]Event, 0, len(rawEvents))
	warnings := []string{}

	for i, rawEvent := range rawEvents {
		event, eventWarnings, ok := parseEvent(rawEvent, i)
		warnings = append(warnings, eventWarnings...)
		if !ok {
			continue
		}
		events = append(events, event)
	}
	return events, warnings
}

func parseEvent(rawEvent rawEvent, index int) (Event, []string, bool) {
	warnings := []string{}
	prefix := fmt.Sprintf("event[%d]", index)

	coord, err := parsePURL(rawEvent.PURL)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s invalid purl %q: %v", prefix, rawEvent.PURL, err))
		return Event{}, warnings, false
	}

	symbol := strings.TrimSpace(rawEvent.Symbol)
	if symbol == "" {
		symbol = "(package)"
	}

	count, err := parseCount(rawEvent.Count)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s invalid count: %v", prefix, err))
		return Event{}, warnings, false
	}

	firstSeen, err := parseTimestamp(rawEvent.FirstSeen)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s invalid firstSeen: %v", prefix, err))
	}
	lastSeen, err := parseTimestamp(rawEvent.LastSeen)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s invalid lastSeen: %v", prefix, err))
	}

	if !firstSeen.IsZero() && !lastSeen.IsZero() && lastSeen.Before(firstSeen) {
		warnings = append(warnings, fmt.Sprintf("%s lastSeen is before firstSeen; swapping values", prefix))
		firstSeen, lastSeen = lastSeen, firstSeen
	}

	return Event{
		PURL:      canonicalPURL(coord),
		Symbol:    symbol,
		Count:     count,
		FirstSeen: firstSeen.UTC(),
		LastSeen:  lastSeen.UTC(),
	}, warnings, true
}

func parseCount(raw json.RawMessage) (uint64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return 0, nil
	}

	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		text := strings.TrimSpace(number.String())
		if strings.Contains(text, ".") {
			return 0, fmt.Errorf("count must be integer, got %q", text)
		}
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse integer %q: %w", text, err)
		}
		if parsed < 0 {
			return 0, fmt.Errorf("count must be >= 0")
		}
		return uint64(parsed), nil
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		text = strings.TrimSpace(text)
		if text == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse uint %q: %w", text, err)
		}
		return parsed, nil
	}

	return 0, fmt.Errorf("unsupported count value %q", trimmed)
}

func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return time.Time{}, nil
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if strings.TrimSpace(text) == "" {
			return time.Time{}, nil
		}
		return parseTimestampString(text)
	}

	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return parseUnixNumber(number.String())
	}

	return time.Time{}, fmt.Errorf("unsupported timestamp value %q", trimmed)
}

func parseTimestampString(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}

	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, value); err == nil {
			return ts.UTC(), nil
		}
	}

	if unix, err := parseUnixNumber(value); err == nil {
		return unix, nil
	}

	return time.Time{}, fmt.Errorf("unsupported time format %q", value)
}

func parseUnixNumber(raw string) (time.Time, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return time.Time{}, fmt.Errorf("empty unix timestamp")
	}

	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse unix timestamp %q: %w", text, err)
	}

	if parsed > 1_000_000_000_000 {
		return time.UnixMilli(parsed).UTC(), nil
	}
	return time.Unix(parsed, 0).UTC(), nil
}

func normalizeTime(ts time.Time) time.Time {
	if ts.IsZero() {
		return time.Time{}
	}
	return ts.UTC()
}

func earlierTime(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}

func laterTime(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.After(a):
		return b
	default:
		return a
	}
}
