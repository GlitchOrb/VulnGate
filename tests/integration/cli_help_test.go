package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/GlitchOrb/vulngate/internal/cli"
)

func TestHelpWorks(t *testing.T) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	app := cli.New(&stdout, &stderr)

	exitCode := app.Run(context.Background(), []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected help usage in stdout, got: %s", stdout.String())
	}
}
