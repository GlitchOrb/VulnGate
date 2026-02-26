# Contributing

> @GlitchOrb

Thanks for contributing to VulnGate.

## Development Setup

```bash
go mod download
make fmt
make lint
make test
make build
```

## Branch and PR Guidelines

- Keep PRs scoped to one concern.
- Add/update tests for behavior changes.
- Update docs for new flags, commands, or module contracts.
- Preserve CLI contracts:
  - `scan` stdout is SARIF JSON only
  - logs/errors must go to stderr

## Commit and Review Expectations

- Use clear commit messages with intent and impact.
- Include before/after behavior in PR description.
- Call out policy/exit code changes explicitly.

## Module Extension

For scanner and renderer extension points, see:
- `docs/DEVELOPER_GUIDE.md`
- `docs/architecture.md`
