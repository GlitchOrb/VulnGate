# VulnGate

> @GlitchOrb

VulnGate is an open-source, offline-first CI/CD vulnerability scanner and policy gate.
The MVP is a single-binary CLI with **SARIF 2.1.0 to stdout** and logs/errors on stderr.

## Quickstart

### 0) Prerequisites

- Go 1.23+ (or use CI artifacts)
- Linux/macOS/Windows shell

### 1) Install

Build locally:

```bash
go build -o ./bin/vulngate ./cmd/vulngate
./bin/vulngate --help
```

Or install into `GOBIN`:

```bash
go install ./cmd/vulngate
vulngate --help
```

### 2) Initialize and import local vulnerability DB

If installed via `go install`, use:

```bash
vulngate db init --db ./vulngate.db
vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
```

One-liner form:

```bash
vulngate db init --db ./vulngate.db && vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
```

If using local build output, replace `vulngate` with `./bin/vulngate`.

### 3) Run scan and emit SARIF

```bash
vulngate scan --db ./vulngate.db . > results.sarif
```

Exit codes:

- `0`: policy pass
- `1`: policy fail (gate violation)
- `2`: tool error

### 4) Upload SARIF to GitHub code scanning

Add this step in a GitHub Actions job after creating `results.sarif`:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

A complete ready-to-use workflow is provided at:
- `examples/ci/github-actions-code-scanning.yml`

## CI Snippets

### GitHub Actions

```yaml
name: VulnGate SARIF Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  vulngate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go build -o ./bin/vulngate ./cmd/vulngate
      - run: |
          ./bin/vulngate db init --db ./vulngate.db
          ./bin/vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
      - run: |
          set +e
          ./bin/vulngate scan --db ./vulngate.db . > results.sarif
          CODE=$?
          echo "scan_exit=$CODE" >> "$GITHUB_OUTPUT"
          test "$CODE" -ne 2
        id: scan
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
      - run: test "${{ steps.scan.outputs.scan_exit }}" != "1"
```

Full file: `examples/ci/github-actions-code-scanning.yml`

### GitLab CI

```yaml
stages: [scan]
vulngate_scan:
  stage: scan
  image: golang:1.24
  script:
    - go build -o ./bin/vulngate ./cmd/vulngate
    - ./bin/vulngate db init --db ./vulngate.db
    - ./bin/vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
    - |
      set +e
      ./bin/vulngate scan --db ./vulngate.db . > results.sarif
      SCAN_EXIT=$?
      set -e
      if [ "$SCAN_EXIT" -eq 2 ]; then exit 2; fi
      if [ "$SCAN_EXIT" -eq 1 ]; then exit 1; fi
  artifacts:
    when: always
    paths: [results.sarif, vulngate.db]
```

Full file: `examples/ci/gitlab-ci.yml`

### Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Build and Scan') {
      steps {
        sh '''
          go build -o ./bin/vulngate ./cmd/vulngate
          ./bin/vulngate db init --db ./vulngate.db
          ./bin/vulngate db import --db ./vulngate.db --source ./examples/vulndb/osv
          set +e
          ./bin/vulngate scan --db ./vulngate.db . > results.sarif
          SCAN_EXIT=$?
          set -e
          echo "$SCAN_EXIT" > .vulngate_scan_exit
          if [ "$SCAN_EXIT" -eq 2 ]; then exit 2; fi
        '''
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'results.sarif', fingerprint: true }
  }
}
```

Full file: `examples/ci/Jenkinsfile`

## Example Fixtures

Ready-to-use fixtures are under `examples/`:

- `examples/vulndb/osv/` - sample OSV JSON dataset for `db import`
- `examples/vulndb/osv-real/` - real OSV advisory dataset for reproducible real-vulnerability tests
- `examples/repos/policy-fail/` - deterministic policy-fail scan target
- `examples/repos/policy-pass/` - deterministic policy-pass scan target
- `examples/repos/real-vuln-npm-lodash/` - real vulnerable dependency fixture (`lodash@4.17.20`)
- `tests/stress/large-repo/` - stress fixture for performance validation

Fixture walkthrough:

```bash
./bin/vulngate scan --db ./vulngate.db ./examples/repos/policy-fail > fail.sarif
./bin/vulngate scan --db ./vulngate.db ./examples/repos/policy-pass > pass.sarif
```

Real vulnerability demo:

```bash
./examples/scripts/run_real_vuln_demo.sh
```

## License

MIT
