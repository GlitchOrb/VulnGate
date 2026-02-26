# Reachability Analysis

> @GlitchOrb

VulnGate currently supports two reachability tiers in the CLI pipeline.

## Tier-1: Dependency Reachability

Tier-1 determines if a vulnerable component is in runtime dependency closure.

- Status: `true|false|unknown`
- Reason examples:
  - `included in runtime dependency closure`
  - `only devDependency`
  - `not in runtime dependency closure`

Tier-1 is always enabled.

## Tier-2: Static Call Graph (Go)

Tier-2 is currently implemented for **Go** as an optional feature.

Enable it with:

```bash
vulngate scan --enable-tier2-go <target-path>
```

Implementation overview:

- Uses `go/packages` to load project packages.
- Builds SSA via `x/tools/go/ssa`.
- Runs RTA call graph analysis (`x/tools/go/callgraph/rta`).
- Maps vulnerable package PURLs (`pkg:golang/...`) to reachable call graph nodes.

Output fields per finding:

- `tier2Status`: `true|false|unknown`
- `tier2Reason`: textual explanation
- `tier2Evidence`: call chain snippet when reachable (e.g. `main.main -> ... -> vulnerable.Func`)

## Tier-2R: Runtime Reachability (Profile Import)

Tier-2R is optional and driven by imported runtime profiles (for example from the `runtime-ebpf` agent).

Import profile data:

```bash
vulngate reach import --profile profile.json --out .vulngate-runtime-profile.json
```

Run scan with Tier-2R correlation:

```bash
vulngate scan <target-path>
```

By default, `scan` auto-loads `<target-path>/.vulngate-runtime-profile.json` if present.
You can override with `--runtime-profile <path>`.

Output fields per finding:

- `runtimeStatus`: `true|false|unknown`
- `runtimeReason`: textual explanation of profile correlation
- `runtimeCallCount`: total observed runtime calls
- `runtimeSymbols`: `symbol:count` entries
- `runtimeFirstSeen`, `runtimeLastSeen`: observed time window (UTC)

## Fail-Open Behavior

Tier-2 and Tier-2R are best-effort and **must not break scans**.

If static analysis fails (package load/build issues, unsupported target, etc.), scan continues and findings are marked with:

- `tier2Status=unknown`
- `tier2Reason=tier2 go analysis unavailable: ...`

## Current Limitations

- Tier-2 currently supports only Go filesystem targets.
- Matching is package-level for MVP; symbol-level hint correlation is limited.
- Dynamic dispatch/reflection/cgo behavior may produce `unknown` or conservative results.
- No runtime tracing correlation yet (Tier-2R planned).
- Runtime evidence is only as good as observed traffic/workload coverage.
- Tier-2R currently relies on imported profiles, not live attachment from `vulngate scan`.

## Roadmap

1. Add symbol-hint aware matching (OSV symbol data when available).
2. Expand Tier-2 to additional ecosystems (JS/TS, Java).
3. Expand Tier-2R live integrations beyond imported profile workflows.
4. Add confidence scoring and explainability improvements for policy gating.
