# SLSA Integration (Staged)

> @GlitchOrb

This document describes VulnGate supply-chain integrity features in staged form.

## Stage A (MVP)

Implemented in MVP:

- Provenance metadata captured for scans/SBOM attestations:
  - tool version/commit/build date
  - local DB schema version and status
  - git commit/branch
  - build environment hints (CI provider, runner hints, GOOS/GOARCH)
- Optional signing via pluggable signer interface:
  - `none` (default)
  - `cosign` (when installed/configured)
- Attestation bundle artifact emitted as JSON:
  - schema: `vulngate-attestation-bundle-v1`
  - provenance + per-artifact digests + optional signature materials

## CLI Examples

Unsigned scan attestation:

```bash
vulngate scan ./repo --attest-bundle artifacts/scan.attest.json > artifacts/scan.sarif
```

Cosign-signed scan attestation:

```bash
export COSIGN_ID_TOKEN=...
vulngate scan ./repo \
  --signer cosign \
  --sign-key cosign.key \
  --attest-bundle artifacts/scan.attest.json \
  > artifacts/scan.sarif
```

If `--signer cosign` is set without `--attest-bundle`, VulnGate writes
`./vulngate-attestation.json` by default.

Cosign-signed SBOM attestation:

```bash
vulngate sbom ./repo --format json \
  --signer cosign \
  --sign-key cosign.key \
  --attest-bundle artifacts/sbom.attest.json \
  > artifacts/sbom.json
```

GitHub Actions reference workflow:

- `.github/workflows/attest-example.yml`

## Stage B (Later)

Planned guidance and optional integration:

- SLSA build provenance ingestion and linking to scan artifacts.
- In-toto predicate support and policy checks.
- Split trust domains for build/test/sign steps.
- Hermetic and reproducible build profile guidance.

Placeholder interfaces already exist in `internal/attest/slsa.go`:

- `SLSAProvenanceProvider`
- `HardwareAttestor`

These are intentionally unimplemented contracts for future providers.

## Toward SLSA Level 4

For SLSA L4 progression, VulnGate currently provides interfaces and documentation only.
Hardware-backed attestation integration (for example TPM/SEV/TEE/HSM-backed build proofs) remains a future implementation track.

Recommended stepwise path:

1. Enable reproducible builds and signed artifacts (Stage A).
2. Add verifiable build provenance + in-toto predicates (Stage B).
3. Move signing/build to hardened isolated runners with hardware roots of trust.
4. Enforce provenance verification gates before deployment.
