# Changelog

> @GlitchOrb

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Documentation finalization for quickstart, CI snippets, and release process
- Ready-to-use examples for OSV DB import and policy pass/fail scan fixtures
- Release governance docs: versioning, contribution guide, security policy, release checklist

## [0.1.0] - 2026-02-26

### Added

- CLI skeleton with `scan`, `sbom`, `db`, `reach`, and `fix` commands
- SARIF renderer with stable fingerprints and deduplication
- Local SQLite vulnerability DB schema/init/import primitives
- PURL cataloging for npm, pnpm, Python, and Go manifests/lockfiles
- Policy gating with reachability-aware rules and ignore expiration
- Reachability Tier-1, optional Tier-2 (Go static), and Tier-2R profile import
- Optional graph service module and optional auto-remediation module
- Supply-chain attestation/signing interfaces and staged SLSA docs
- CI for lint/test/build matrix
