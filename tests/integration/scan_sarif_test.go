package integration

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GlitchOrb/vulngate/internal/cli"
)

func TestScanProducesSarifAndFailCodeWhenPolicyViolates(t *testing.T) {
	temp := t.TempDir()
	dbPath := filepath.Join(temp, "vulngate.db")

	seedStdout := bytes.Buffer{}
	seedStderr := bytes.Buffer{}
	seedApp := cli.New(&seedStdout, &seedStderr)
	if code := seedApp.Run(context.Background(), []string{"db", "seed-example", "--db", dbPath}); code != 0 {
		t.Fatalf("seed-example failed with code %d: %s", code, seedStderr.String())
	}

	scanStdout := bytes.Buffer{}
	scanStderr := bytes.Buffer{}
	scanApp := cli.New(&scanStdout, &scanStderr)
	code := scanApp.Run(context.Background(), []string{
		"scan",
		"--db", dbPath,
		"--dep", "pkg:golang/github.com/example/insecure-lib@1.2.3",
		"--project", "integration-test",
	})

	if code != 3 {
		t.Fatalf("expected policy failure exit code 3, got %d; stderr=%s", code, scanStderr.String())
	}
	if !strings.Contains(scanStdout.String(), `"version": "2.1.0"`) {
		t.Fatalf("expected sarif output, got: %s", scanStdout.String())
	}
}
