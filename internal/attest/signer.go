package attest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SignResult struct {
	Signature   string
	Certificate string
	Bundle      string
}

type Signer interface {
	Name() string
	Sign(ctx context.Context, artifactPath string, cfg SignConfig) (SignResult, error)
}

type NoopSigner struct{}

func (NoopSigner) Name() string {
	return "none"
}

func (NoopSigner) Sign(_ context.Context, _ string, _ SignConfig) (SignResult, error) {
	return SignResult{}, nil
}

type CosignSigner struct {
	Binary string
}

func (s CosignSigner) Name() string {
	return "cosign"
}

func (s CosignSigner) Sign(ctx context.Context, artifactPath string, cfg SignConfig) (SignResult, error) {
	artifact := strings.TrimSpace(artifactPath)
	if artifact == "" {
		return SignResult{}, fmt.Errorf("artifact path is empty")
	}

	bin := strings.TrimSpace(s.Binary)
	if bin == "" {
		bin = strings.TrimSpace(cfg.CosignBinary)
	}
	if bin == "" {
		bin = "cosign"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return SignResult{}, fmt.Errorf("cosign binary not found: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "vulngate-cosign-")
	if err != nil {
		return SignResult{}, fmt.Errorf("create cosign temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	sigPath := filepath.Join(tmpDir, "artifact.sig")
	certPath := filepath.Join(tmpDir, "artifact.pem")
	bundlePath := filepath.Join(tmpDir, "artifact.bundle.json")

	args := []string{
		"sign-blob",
		"--yes",
		"--output-signature", sigPath,
		"--output-certificate", certPath,
		"--output-bundle", bundlePath,
	}
	if key := strings.TrimSpace(cfg.KeyRef); key != "" {
		args = append(args, "--key", key)
	}
	if token := strings.TrimSpace(cfg.IdentityToken); token != "" {
		args = append(args, "--identity-token", token)
	}
	args = append(args, artifact)

	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return SignResult{}, fmt.Errorf("cosign sign-blob failed: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
	}

	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return SignResult{}, fmt.Errorf("read cosign signature: %w", err)
	}
	cert, _ := os.ReadFile(certPath)
	bundle, _ := os.ReadFile(bundlePath)

	return SignResult{
		Signature:   strings.TrimSpace(string(signature)),
		Certificate: strings.TrimSpace(string(cert)),
		Bundle:      strings.TrimSpace(string(bundle)),
	}, nil
}

func NewSigner(cfg SignConfig) (Signer, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "", "none":
		return NoopSigner{}, nil
	case "cosign":
		return CosignSigner{Binary: cfg.CosignBinary}, nil
	default:
		return nil, fmt.Errorf("unsupported signer %q (expected none|cosign)", cfg.Mode)
	}
}
