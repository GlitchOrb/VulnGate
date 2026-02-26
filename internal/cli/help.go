package cli

import "fmt"

func (a *App) printRootHelp() {
	fmt.Fprint(a.stdout, `VulnGate - Offline-first CI/CD vulnerability gate

Usage:
  vulngate <command> [options]

Commands:
  scan          Run scanners and emit SARIF 2.1.0 to stdout
  db            Vulnerability DB operations
  version       Print build version
  help          Show this help

Run "vulngate <command> --help" for command details.
`)
}

func (a *App) printScanHelp() {
	fmt.Fprint(a.stdout, `Usage:
  vulngate scan [options]

Options:
  --format sarif                    Output format (required to remain sarif for MVP)
  --db <path>                       SQLite vulnerability DB path (default: vulngate.db)
  --target <path>                   Project path for go.mod dependency discovery
  --project <name>                  Logical project name in SARIF output
  --dep <purl@version>              Dependency PURL, repeatable
  --policy-min-severity <level>     low|medium|high|critical (default: high)
  --policy-reachability <mode>      any|reachable (default: reachable)
  --policy-min-tier <tier>          tier0|tier1|tier2|tier2r (default: tier1)
  --static-reachability-file <path> File listing vuln IDs reachable by static call graph
  --enable-runtime-ebpf             Enable Tier-2R runtime reachability placeholder analyzer

Behavior:
  - SARIF 2.1.0 is emitted to stdout.
  - Logs are emitted to stderr.
  - Exit code 3 indicates policy gate failure.
`)
}

func (a *App) printDBHelp() {
	fmt.Fprint(a.stdout, `Usage:
  vulngate db <command> [options]

Commands:
  seed-example   Seed a sample vulnerability into the local SQLite DB
`)
}
