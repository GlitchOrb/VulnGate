# Versioning Policy

> @GlitchOrb

VulnGate follows Semantic Versioning (`MAJOR.MINOR.PATCH`).

- `MAJOR`: incompatible CLI/output/behavior changes
- `MINOR`: backward-compatible features, new optional modules/flags
- `PATCH`: backward-compatible bug fixes and hardening updates

## Compatibility Notes

- SARIF output contract is considered part of the public interface.
- Exit code semantics for `scan` are stable:
  - `0` pass
  - `1` policy fail
  - `2` tool error
- New flags should default to non-breaking behavior.
