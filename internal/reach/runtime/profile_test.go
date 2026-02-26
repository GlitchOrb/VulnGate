package runtime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseProfileJSONTableDriven(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		wantEvents    int
		wantWarnings  int
		wantFirstPURL string
		wantCount     uint64
	}{
		{
			name: "array payload with malformed records",
			payload: `[
				{"purl":"pkg:npm/left-pad@1.3.0","symbol":"leftpad","count":2,"firstSeen":"2026-01-01T00:00:00Z","lastSeen":"2026-01-02T00:00:00Z"},
				{"purl":"","symbol":"bad","count":1}
			]`,
			wantEvents:    1,
			wantWarnings:  1,
			wantFirstPURL: "pkg:npm/left-pad@1.3.0",
			wantCount:     2,
		},
		{
			name: "object payload normalized and merged",
			payload: `{
				"schema":"vulngate-runtime-profile-v1",
				"generatedAt":"2026-01-03T00:00:00Z",
				"events":[
					{"purl":"pkg:pypi/Requests@2.31.0","symbol":"requests.api.get","count":"3","firstSeen":1735689600,"lastSeen":1735776000},
					{"purl":"pkg:pypi/requests@2.31.0","symbol":"requests.api.get","count":4}
				]
			}`,
			wantEvents:    1,
			wantWarnings:  0,
			wantFirstPURL: "pkg:pypi/requests@2.31.0",
			wantCount:     7,
		},
		{
			name:         "malformed json",
			payload:      `{`,
			wantEvents:   0,
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, warnings, err := ParseProfileJSON([]byte(tt.payload))
			if tt.name == "malformed json" {
				if err == nil {
					t.Fatalf("expected parse error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProfileJSON returned error: %v", err)
			}
			if len(warnings) < tt.wantWarnings {
				t.Fatalf("expected at least %d warnings, got %d (%v)", tt.wantWarnings, len(warnings), warnings)
			}
			if len(profile.Events) != tt.wantEvents {
				t.Fatalf("expected %d normalized events, got %d", tt.wantEvents, len(profile.Events))
			}
			if tt.wantEvents > 0 {
				if profile.Events[0].PURL != tt.wantFirstPURL {
					t.Fatalf("expected normalized purl %q, got %q", tt.wantFirstPURL, profile.Events[0].PURL)
				}
				if profile.Events[0].Count != tt.wantCount {
					t.Fatalf("expected count %d, got %d", tt.wantCount, profile.Events[0].Count)
				}
			}
		})
	}
}

func TestWriteProfileFileRoundTrip(t *testing.T) {
	path := t.TempDir() + "/runtime-profile.json"

	in := Profile{
		Events: []Event{{
			PURL:      "pkg:golang/github.com/example/lib@1.2.3",
			Symbol:    "github.com/example/lib.Do",
			Count:     11,
			FirstSeen: time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, 1, 10, 12, 30, 0, 0, time.UTC),
		}},
	}

	if err := WriteProfileFile(path, in); err != nil {
		t.Fatalf("WriteProfileFile failed: %v", err)
	}

	loaded, warnings, err := LoadProfileFile(path)
	if err != nil {
		t.Fatalf("LoadProfileFile failed: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if loaded.Schema != ProfileSchema {
		t.Fatalf("expected schema %q, got %q", ProfileSchema, loaded.Schema)
	}
	if len(loaded.Events) != 1 {
		t.Fatalf("expected one event, got %d", len(loaded.Events))
	}

	raw, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("marshal loaded profile: %v", err)
	}
	if !strings.Contains(string(raw), "github.com/example/lib@1.2.3") {
		t.Fatalf("unexpected profile payload: %s", string(raw))
	}
}
