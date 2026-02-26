package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func BuildBundle(ctx context.Context, opts BundleOptions) (Bundle, error) {
	if len(opts.Artifacts) == 0 {
		return Bundle{}, fmt.Errorf("at least one artifact is required")
	}
	if err := ValidateSignConfig(opts.Signing); err != nil {
		return Bundle{}, err
	}

	provenance := opts.Provenance
	if provenance.GeneratedAt.IsZero() {
		provenance.GeneratedAt = time.Now().UTC()
	}

	signer := opts.Signer
	if signer == nil {
		var err error
		signer, err = NewSigner(opts.Signing)
		if err != nil {
			return Bundle{}, err
		}
	}

	signingEnabled := shouldSign(opts.Signing.Mode)

	records := make([]ArtifactRecord, 0, len(opts.Artifacts))
	for _, input := range opts.Artifacts {
		record, err := buildArtifactRecord(ctx, input, signer, opts.Signing, signingEnabled, opts.TempDir)
		if err != nil {
			return Bundle{}, err
		}
		records = append(records, record)
	}

	return Bundle{
		Schema:      BundleSchema,
		GeneratedAt: time.Now().UTC(),
		Provenance:  provenance,
		Artifacts:   records,
	}, nil
}

func buildArtifactRecord(ctx context.Context, input ArtifactInput, signer Signer, cfg SignConfig, signingEnabled bool, tempDir string) (ArtifactRecord, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = "artifact"
	}
	kind := strings.TrimSpace(input.Kind)
	if kind == "" {
		kind = "generic"
	}

	payloadPath, payload, cleanup, err := materializeArtifact(input, tempDir)
	if err != nil {
		return ArtifactRecord{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	sum := sha256.Sum256(payload)
	artifactPath := filepath.ToSlash(strings.TrimSpace(input.Path))
	if artifactPath == "" {
		artifactPath = "inline:" + name
	}
	record := ArtifactRecord{
		Name:      name,
		Kind:      kind,
		MediaType: strings.TrimSpace(input.MediaType),
		Path:      artifactPath,
		SHA256:    hex.EncodeToString(sum[:]),
		Size:      int64(len(payload)),
		Signed:    false,
	}

	if !signingEnabled {
		return record, nil
	}

	signResult, err := signer.Sign(ctx, payloadPath, cfg)
	if err != nil {
		return ArtifactRecord{}, fmt.Errorf("sign artifact %s: %w", name, err)
	}

	record.Signed = true
	record.Signer = signer.Name()
	record.Signature = SignatureMaterial{
		Signature:   signResult.Signature,
		Certificate: signResult.Certificate,
		Bundle:      signResult.Bundle,
	}
	return record, nil
}

func materializeArtifact(input ArtifactInput, tempDir string) (path string, payload []byte, cleanup func(), err error) {
	if input.Path != "" {
		raw, readErr := os.ReadFile(input.Path)
		if readErr != nil {
			return "", nil, nil, fmt.Errorf("read artifact path %s: %w", input.Path, readErr)
		}
		abs, absErr := filepath.Abs(input.Path)
		if absErr != nil {
			abs = input.Path
		}
		return abs, raw, nil, nil
	}

	if len(input.Content) == 0 {
		return "", nil, nil, fmt.Errorf("artifact %q has no path and no content", input.Name)
	}

	tmpRoot := strings.TrimSpace(tempDir)
	if tmpRoot != "" {
		if err := os.MkdirAll(tmpRoot, 0o755); err != nil {
			return "", nil, nil, fmt.Errorf("create temp artifact directory: %w", err)
		}
	}
	tmpFile, err := os.CreateTemp(tmpRoot, "vulngate-artifact-*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create temp artifact file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(input.Content); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", nil, nil, fmt.Errorf("write temp artifact file: %w", err)
	}

	return tmpFile.Name(), append([]byte{}, input.Content...), func() {
		_ = os.Remove(tmpFile.Name())
	}, nil
}

func WriteBundle(path string, bundle Bundle) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("bundle output path is required")
	}

	abs, err := filepath.Abs(target)
	if err == nil {
		target = abs
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}

	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	return nil
}

func ShouldEmitBundle(bundlePath string, signerMode string) bool {
	return strings.TrimSpace(bundlePath) != "" || shouldSign(signerMode)
}
