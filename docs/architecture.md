# VulnGate Architecture Skeleton

> @GlitchOrb

This document describes the core scan pipeline implemented in `internal/engine`.

## Design Goals

- CLI-first execution with deterministic output.
- Stage-based architecture with explicit extension points.
- Clear error boundaries per stage.
- `stdout` reserved for final SARIF JSON only.
- All logging and diagnostics written to `stderr`.

## Core Pipeline Stages

`Pipeline.Run()` orchestrates the following internal interfaces in order:

1. `TargetIngestor`
2. `SBOMCataloger`
3. `Matcher` (PURL + OSV style matching boundary)
4. `ReachabilityAnalyzer` (Tier-1/Tier-2)
5. `DeduplicatorFingerprinter`
6. `PolicyEngine`
7. `Renderer` (SARIF 2.1.0)

Every stage returns strongly typed outputs that feed the next stage.

## ScanContext

`ScanContext` carries run-scoped metadata:

- Repository metadata:
  - `commit`
  - `branch`
  - `url`
- CI metadata:
  - `provider`
  - `pipelineID`
  - `jobID`
  - `runURL`
- Target descriptor:
  - `type` (`fs`, `image`, `sbom`)
  - `path`
- Request timestamp (`requestedAt`)

## Finding Model

`Finding` is the normalized vulnerability record for downstream stages:

- `vulnID` (OSV/GHSA/CVE style IDs)
- `packagePURL`
- `installedVersion`
- `fixedVersion`
- `severity`
- `references`
- `locations`
- `reachability` flags (`tier1`, `tier2`, `tier2Runtime`)
- runtime evidence metadata:
  - `runtimeStatus`
  - `runtimeReason`
  - `runtimeCallCount`
  - `runtimeSymbols`
  - `runtimeFirstSeen` / `runtimeLastSeen`
- `fingerprints`

## Error Boundaries

`Run()` wraps stage failures in `StageError` with a stable stage name (for example `target_ingest`, `matcher`, `policy_engine`).
This allows callers and CI wrappers to identify where execution failed without parsing free-form logs.

## Extension Points

To replace placeholders, implement the corresponding interface and inject it through `PipelineConfig`:

- Real target ingestion for source trees, containers, and SBOM files.
- Real cataloging from lockfiles/SBOM parsers.
- Real OSV/GHSA matching backed by local SQLite/feeds.
- Reachability implementations (dependency graph, static call graph, runtime eBPF).
- Optional org-wide graph mode service (`services/graph`) for GUAC-style impact analysis.
- Optional supply-chain attestation/signing module (`internal/attest`) for provenance bundles.
- Custom fingerprint strategies.
- Organization policy engines and gating logic.
- Additional output renderers (SARIF is default contract).

## CLI Contract

`cmd/vulngate` exposes:

- `vulngate scan [--target-type fs|image|sbom] [--runtime-profile path] [--debug] <target-path>`
- `vulngate fix [--policy path] --auto-fix [--model local] [--test-cmd "..."] <repo-path>`
- `vulngate scan ... [--attest-bundle path] [--signer none|cosign]`
- `vulngate sbom ... [--attest-bundle path] [--signer none|cosign]`
- `vulngate reach import --profile <profile.json> [--out .vulngate-runtime-profile.json]`

Output contract:

- `stdout`: final SARIF JSON only.
- `stderr`: debug/info/error logs.
