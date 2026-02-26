# VulnGate Policy Gating

> @GlitchOrb

`vulngate scan` loads policy configuration from `.vulngate.yml` in the target path by default.
Use `--config <path>` to point to a different file.

## Exit Codes

- `0`: policy passed
- `1`: policy failed (build should be gated)
- `2`: tool/config/runtime error

## Config Schema

```yaml
policy:
  fail_on_severity: [CRITICAL, HIGH]

  scope:
    production_mode: true
    ignore_dev_dependencies: true
    ignore_test_dependencies: true

  reachability:
    require_reachable_for_severities: [high, critical]

  ignore:
    - vuln_id: GHSA-xxxx-yyyy-zzzz
      expires: 2026-12-31
      reason: "awaiting upstream fix"

    - purl: pkg:npm/lodash@4.17.20
      expires: 2026-10-01

    - path: "examples/**"
      expires: 2026-09-30
```

## Behavior

1. Findings are filtered by scope rules when `production_mode: true`.
2. Active ignore rules are applied (`vuln_id`, `purl`, `path`) with expiration support.
3. Remaining findings are evaluated against `fail_on_severity`.
4. For severities listed in `require_reachable_for_severities`, only reachable findings fail the gate.

Reachability is considered true when any of Tier-1, Tier-2, or Tier-2R is true.

## Stderr Policy Summary

`scan` writes a policy summary to `stderr`, including:

- total findings
- considered/ignored counts
- violations count
- counts by severity with reachable vs unreachable

## Deterministic Fixtures

Sample repos and configs are included for deterministic pass/fail coverage:

- `internal/policy/testdata/repo-pass`
- `internal/policy/testdata/repo-fail`

These fixtures are used by unit and CLI tests to verify policy outcomes consistently.
