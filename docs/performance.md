# Performance And Hardening Notes

> @GlitchOrb

This document summarizes the hardening/performance pass for VulnGate CLI modules.

## What Was Added

- Dependency catalog cache (`internal/catalog`):
  - Cache key is a deterministic SHA-256 over discovered lockfiles/manifests content.
  - Cache payload stores internal SBOM report.
  - CLI controls:
    - `vulngate sbom --cache-dir .vulngate/cache/catalog`
    - `vulngate sbom --no-cache`
- Matching engine concurrency + safe query caching (`internal/match`):
  - Bounded worker pool via `EngineOptions.WorkerCount`.
  - Per-run query caches for affected packages, aliases, refs, and ranges.
  - Optional progress callback (`EngineOptions.Progress`).
- UX improvements:
  - Optional progress indicators on stderr:
    - `vulngate scan --progress ...`
    - `vulngate sbom --progress ...`
  - Clear summary lines:
    - `scan summary: ...`
    - `sbom summary: ...`
- Error taxonomy (stderr):
  - `error[parse]: ...`
  - `error[tool]: ...`
  - `error[policy]: ...`

## Stress Fixture

- Synthetic stress fixture:
  - `tests/stress/large-repo/requirements.txt` (1200+ entries)
- Validation test:
  - `internal/catalog/stress_test.go`

## Benchmarks

Added benchmark suites:

- `internal/catalog/benchmark_test.go`
  - `BenchmarkBuildStressFixture/no-cache`
  - `BenchmarkBuildStressFixture/cache-hit`
- `internal/match/benchmark_test.go`
  - `BenchmarkMatch10kComponents/sequential-no-cache`
  - `BenchmarkMatch10kComponents/parallel-with-cache`

### Run Benchmarks

```bash
go test -run '^$' -bench BenchmarkBuildStressFixture -benchmem ./internal/catalog
go test -run '^$' -bench BenchmarkMatch10kComponents -benchmem ./internal/match
```

### Profiling

CPU profile:

```bash
go test -run '^$' -bench BenchmarkMatch10kComponents/parallel-with-cache -cpuprofile cpu.out ./internal/match
go tool pprof -http=:0 cpu.out
```

Memory profile:

```bash
go test -run '^$' -bench BenchmarkBuildStressFixture/cache-hit -memprofile mem.out ./internal/catalog
go tool pprof -http=:0 mem.out
```

## Targets

- Match target: 10k components <= ~2s on a typical modern developer machine in parallel+cache mode.
- Catalog target: repeated scans on unchanged lockfiles should become cache hits with significantly lower latency.
- Memory goal: bounded by per-run caches + component cardinality; no unbounded global cache state retained across runs.
