# VulnGate Runtime eBPF Agent

Linux-only runtime profiler for Tier-2R reachability evidence.

## Build

```bash
go build ./runtime-ebpf/agent
```

## Run (attach mode)

```bash
./agent \
  --mode attach \
  --config runtime-ebpf/examples/profiler-config.json \
  --output profile.json
```

## Run (replay mode)

```bash
./agent \
  --mode replay \
  --config runtime-ebpf/examples/profiler-config.json \
  --replay-cmd 'go test ./...' \
  --output profile.json
```

Import the generated profile into VulnGate:

```bash
vulngate reach import --profile profile.json
vulngate scan ./repo
```
