# Auto-Remediation Loop

> @GlitchOrb

`vulngate fix` provides an optional, offline-capable Detect-Repair-Validate workflow.

## Safety Model

- Disabled by default; requires explicit `--auto-fix`.
- Never pushes commits or branches automatically.
- Writes full audit artifacts (prompt, model output, patch, report) to disk.
- Runs generated patch in a temporary git worktree/branch for isolation.
- Applies strict patch checks:
  - minimal change limits
  - no added network calls
  - no added secrets/tokens/keys
  - no test bypass/deletion patterns

## CLI Usage

```bash
vulngate fix --auto-fix --model local ./repo
```

With validation tests:

```bash
vulngate fix --auto-fix --model local --test-cmd "go test ./..." ./repo
```

Path-first form is also supported:

```bash
vulngate fix ./repo --policy .vulngate.yml --model local --auto-fix
```

Optional local runtime command adapter:

```bash
vulngate fix --auto-fix --model local --llm-cmd "llama.cpp --prompt -" ./repo
```

## Workflow

1. Detect:
- Runs local scan.
- Selects top reachable `critical/high` findings as candidates.

2. Repair:
- Builds a constrained prompt.
- Calls local adapter (`local` model).
- Expects a git diff patch.

3. Validate:
- Creates temporary git worktree + branch.
- Applies patch.
- Runs configured tests.
- Re-runs scan and verifies:
  - targeted findings are resolved
  - no new critical findings are introduced

## Audit Artifacts

Default location:

`<repo>/.vulngate/autofix/<timestamp>/`

Artifacts:

- `prompt.txt`
- `model-output.txt`
- `patch.diff`
- `validation-tests.log` (if tests configured)
- `report.json`

## Output and Exit Codes

- `stdout`: JSON remediation report.
- `stderr`: execution logs and summary.
- Exit codes:
  - `0`: validated success
  - `1`: aborted (safety or validation failure)
  - `2`: tool/runtime error

## Hallucination Mitigation Strategy

- Constrained prompt requiring diff-only output.
- Static safety filters before patch application.
- Isolated worktree validation.
- Mandatory re-scan comparison against targeted findings.
- Optional test execution guardrail.
- Full audit trail for human review and reproducibility.

## Current Limitations

- MVP targets deterministic local/offline operation and placeholder findings.
- `local` adapter falls back to deterministic heuristic patching when no external local LLM command is provided.
- Advanced semantic patching and multi-file dependency upgrades are roadmap items.
