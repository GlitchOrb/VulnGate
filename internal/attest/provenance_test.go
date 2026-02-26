package attest

import (
	"context"
	"path/filepath"
	"testing"
)

func TestValidateSignConfigTable(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SignConfig
		wantErr bool
	}{
		{name: "default none", cfg: SignConfig{}, wantErr: false},
		{name: "none explicit", cfg: SignConfig{Mode: "none"}, wantErr: false},
		{name: "cosign", cfg: SignConfig{Mode: "cosign"}, wantErr: false},
		{name: "unknown", cfg: SignConfig{Mode: "gpg"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error state: err=%v wantErr=%t", err, tt.wantErr)
			}
		})
	}
}

func TestBuildProvenanceIncludesToolAndDBStatus(t *testing.T) {
	missingDB := filepath.Join(t.TempDir(), "missing-test.db")
	prov := BuildProvenance(context.Background(), ProvenanceOptions{
		RepoPath: ".",
		DBPath:   missingDB,
	})
	if prov.Tool.Name != "VulnGate" {
		t.Fatalf("unexpected tool name: %s", prov.Tool.Name)
	}
	if prov.Tool.Version == "" {
		t.Fatalf("expected non-empty tool version")
	}
	if prov.Database.Status == "" {
		t.Fatalf("expected database status")
	}
	props := prov.AsRunProperties()
	if _, ok := props["toolVersion"]; !ok {
		t.Fatalf("expected toolVersion run property")
	}
	if _, ok := props["dbStatus"]; !ok {
		t.Fatalf("expected dbStatus run property")
	}
}

func TestShouldEmitBundle(t *testing.T) {
	if !ShouldEmitBundle("bundle.json", "none") {
		t.Fatalf("expected explicit bundle path to enable emission")
	}
	if !ShouldEmitBundle("", "cosign") {
		t.Fatalf("expected signer mode cosign to enable emission")
	}
	if ShouldEmitBundle("", "none") {
		t.Fatalf("expected no bundle emission when path empty and signer none")
	}
}
