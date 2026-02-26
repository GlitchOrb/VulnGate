# Release Checklist

> @GlitchOrb

Use this checklist before cutting a release tag.

## 1) Versioning

- [ ] Select next version per [VERSIONING.md](VERSIONING.md)
- [ ] Update version metadata if applicable (`internal/buildinfo`)
- [ ] Verify CLI reports expected version (`vulngate version`)

## 2) Changelog

- [ ] Move relevant entries from `Unreleased` to a new release section in [CHANGELOG.md](CHANGELOG.md)
- [ ] Include notable breaking changes and migration notes
- [ ] Include security-relevant fixes explicitly

## 3) Security Policy

- [ ] Confirm disclosure/reporting instructions in [SECURITY.md](SECURITY.md) are current
- [ ] Confirm no secrets or signing keys are committed
- [ ] Run full CI (`lint`, `test`, build matrix)

## 4) Contribution Guide Alignment

- [ ] Validate contribution workflow in [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] Ensure new commands/flags are documented in README/docs
- [ ] Ensure new modules include tests and fixtures

## 5) Release Artifacts

- [ ] Build cross-platform binaries (`make build-cross`)
- [ ] Generate SARIF from a sample scan and validate with GitHub upload action
- [ ] Generate SBOM and attestation bundle examples
- [ ] Sign artifacts when signing identity/keys are configured

## 6) Final Publish

- [ ] Tag release (`vX.Y.Z`)
- [ ] Publish release notes from changelog
- [ ] Upload binaries and example artifacts
- [ ] Announce release and highlight known limitations
