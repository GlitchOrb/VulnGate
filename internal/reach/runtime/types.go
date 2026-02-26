package runtime

import "time"

const ProfileSchema = "vulngate-runtime-profile-v1"

type Event struct {
	PURL      string    `json:"purl"`
	Symbol    string    `json:"symbol"`
	Count     uint64    `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

type Profile struct {
	Schema      string    `json:"schema,omitempty"`
	GeneratedAt time.Time `json:"generatedAt,omitempty"`
	Events      []Event   `json:"events"`
}
