# Examples

> @GlitchOrb

This directory contains runnable examples and fixtures.

## Vulnerability DB sample dataset

- `vulndb/osv/` contains sample OSV JSON records.
- `vulndb/osv-real/` contains real OSV advisory data for reproducible demos.

Import it with:

```bash
vulngate db init --db ./vulngate.db
vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
```

## Scan fixtures

- `repos/policy-fail/` deterministic policy failure target
- `repos/policy-pass/` deterministic policy pass target
- `repos/real-vuln-npm-lodash/` fixture with a real vulnerable dependency (`lodash@4.17.20`)

Example:

```bash
vulngate scan --db ./vulngate.db ./examples/repos/policy-fail > fail.sarif
vulngate scan --db ./vulngate.db ./examples/repos/policy-pass > pass.sarif
```

Real vulnerability demo:

```bash
./examples/scripts/run_real_vuln_demo.sh
```

## CI templates

- `ci/github-actions-code-scanning.yml`
- `ci/gitlab-ci.yml`
- `ci/Jenkinsfile`
