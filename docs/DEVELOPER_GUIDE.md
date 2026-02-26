# Developer Guide

> @GlitchOrb

## Prerequisites

- Go 1.22+
- No external SaaS required
- Optional: local SQLite client for manual DB inspection

## Add a New Scanner Module

1. Create a plugin package under `plugins/scanners/<name>/`.
2. Implement the `engine.Scanner` contract:
   - `Name() string`
   - `Scan(context.Context, model.ScanRequest) ([]model.Finding, error)`
3. Keep scanner logic focused:
   - dependency extraction should stay in discovery packages
   - matching should reuse `pkg/matcher`
   - DB access should go through `pkg/vulndb/sqlite`
4. Register the scanner in `internal/cli/cli.go` during `runScan`.
5. Add tests under the plugin package and/or `tests/integration`.

Scanner skeleton:

```go
package myscanner

import (
    "context"
    "github.com/GlitchOrb/vulngate/pkg/model"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "my-scanner" }

func (s *Scanner) Scan(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
    return []model.Finding{}, nil
}
```

## Add a New Output Renderer

1. Create `plugins/renderers/<format>/renderer.go`.
2. Implement the `engine.Renderer` contract:
   - `Name() string`
   - `Render(io.Writer, model.Report) error`
3. Register the renderer in `internal/cli/cli.go`.
4. Add tests for formatting correctness and deterministic ordering.

Renderer skeleton:

```go
package myformat

import (
    "io"
    "github.com/GlitchOrb/vulngate/pkg/model"
)

type Renderer struct{}

func New() *Renderer { return &Renderer{} }
func (r *Renderer) Name() string { return "myformat" }
func (r *Renderer) Render(w io.Writer, report model.Report) error { return nil }
```

## Testing Expectations

Run locally before PR:

```bash
make fmt
make lint
make test
```

## Design Constraints

- Scan output format remains SARIF 2.1.0 to stdout.
- Logs/errors remain on stderr.
- Keep dependencies minimal and security-vetted.
- Preserve offline-first behavior.
