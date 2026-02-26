# VulnGate Graph Service

> @GlitchOrb

Optional GUAC-style graph mode for organization-wide impact analysis.

## Run

```bash
go run ./services/graph/cmd/graphd --backend memory --addr :8090
```

## Neo4j

```bash
docker compose -f services/graph/docker-compose.yml up --build
```
