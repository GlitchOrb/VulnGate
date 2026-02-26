# eBPF Runtime Reachability (Tier-2R)

> @GlitchOrb

VulnGate provides an optional Linux runtime profiler under `runtime-ebpf/agent`.
It collects runtime symbol-hit evidence and exports profile JSON that can be imported into `vulngate scan`.

## Goals

- Keep runtime reachability **opt-in** and safe-by-default.
- Support environments where eBPF is unavailable by keeping `scan` functional without it.
- Produce offline-importable profile artifacts for air-gapped CI.

## Modes

1. `attach` mode:
   - Continuous profiling for staging/production workloads.
   - Attaches uprobes and snapshots symbol counters on a configurable interval.

2. `replay` mode:
   - For integration test environments with replayed traffic.
   - Attaches probes, executes a replay command, then exports a profile.

## Profile Event Contract

Each runtime event follows:

```json
{
  "purl": "pkg:golang/github.com/example/app@1.2.3",
  "symbol": "main.main",
  "count": 42,
  "firstSeen": "2026-02-20T10:00:00Z",
  "lastSeen": "2026-02-20T10:05:00Z"
}
```

The agent writes a normalized profile file (`schema: vulngate-runtime-profile-v1`) with an `events` array.

## CLI Integration

Import runtime profile:

```bash
vulngate reach import --profile profile.json --out .vulngate-runtime-profile.json
```

Run scan and correlate findings:

```bash
vulngate scan ./repo
```

`scan` auto-loads `./repo/.vulngate-runtime-profile.json` when present, or use:

```bash
vulngate scan --runtime-profile ./profile.json ./repo
```

SARIF result properties include:

- `reachable_runtime` (boolean)
- `runtimeReachable` (`true|false|unknown`)
- `runtimeCallCount`
- `runtimeSymbols`
- `runtimeFirstSeen`, `runtimeLastSeen`

## Security and Permissions

The runtime agent requires Linux eBPF capabilities and process visibility.
Typical container requirements:

- privileged container or capability set including `BPF`, `PERFMON`, `SYS_ADMIN`, `SYS_RESOURCE`
- `hostPID: true` when probing host processes
- access to target binaries/symbols

Operational guidance:

- Scope probes to specific binaries/symbols.
- Treat profile output as sensitive operational telemetry.
- Use read-only roots where possible and isolate output paths.
- Prefer dedicated nodes/namespaces for profiling workloads.

## Deployment Notes

- Helm chart: `runtime-ebpf/charts/vulngate-runtime-profiler`
- Example config: `runtime-ebpf/examples/profiler-config.json`
- Build agent on Linux:

```bash
go build ./runtime-ebpf/agent
```

## Limitations (MVP)

- Linux only.
- Uprobe symbol availability depends on binary symbol tables/debug info.
- Runtime evidence indicates observed execution, not complete exploitability proof.
