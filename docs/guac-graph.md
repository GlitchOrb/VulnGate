# GUAC-Style Graph Mode

> @GlitchOrb

`graph mode` is an optional, separate service for organization-wide impact analysis.
CLI scan remains fully independent and offline-capable.

## Scope

- Service path: `services/graph/`
- Backends via interface: `memory` (default), `neo4j` (optional)
- Ingestion inputs:
  - CycloneDX JSON SBOM
  - OpenVEX JSON (VEX)
  - Attestation metadata JSON
- Query API:
  - `Which services are affected by vuln X?`
  - `What is blast radius of package PURL@version?`
  - `What vulnerabilities affect service S?`

## Graph Schema

Node labels:

- `Service` `{name}`
- `Artifact` `{id, name, type, digest, source}`
- `Package` `{purl, name, version, ecosystem}`
- `Vulnerability` `{id, severity}`
- `Attestation` `{id, type, predicateType, issuer, subjectDigest, metadata}`
- `VEXStatement` `{id, status, justification, artifactID, timestamp}`

Edges:

- `(Service)-[:DEPLOYS]->(Artifact)`
- `(Artifact)-[:CONTAINS]->(Package)`
- `(Package)-[:DEPENDS_ON]->(Package)`
- `(Package)-[:AFFECTED_BY]->(Vulnerability)`
- `(Artifact)-[:HAS_ATTESTATION]->(Attestation)`
- `(VEXStatement)-[:ASSERTS]->(Vulnerability)`
- `(VEXStatement)-[:APPLIES_TO]->(Package)`

This follows GUAC-like concepts (artifacts, packages, dependencies, vulnerabilities, attestations) while staying minimal for MVP.

## API Endpoints

Ingest:

- `POST /ingest/cyclonedx`
- `POST /ingest/openvex`
- `POST /ingest/attestations`
- `POST /ingest/bundle`

Export (from scan artifacts):

- `POST /export/cyclonedx`
- `POST /export/openvex`
- `POST /export/attestations`

Queries:

- `GET /query/services-by-vuln?vuln=<VULN_ID>`
- `GET /query/blast-radius?purl=<PURL@VERSION>`
- `GET /query/vulns-by-service?service=<SERVICE>`

Health:

- `GET /healthz`

## Canonical Query Examples

1. Services affected by vulnerability:

```bash
curl 'http://localhost:8090/query/services-by-vuln?vuln=OSV-2026-9999'
```

2. Blast radius of package:

```bash
curl 'http://localhost:8090/query/blast-radius?purl=pkg:npm/lodash@4.17.20'
```

3. Vulnerabilities affecting a service:

```bash
curl 'http://localhost:8090/query/vulns-by-service?service=checkout'
```

## Local Run

```bash
go run ./services/graph/cmd/graphd --backend memory --addr :8090
```

Neo4j backend via Docker Compose:

```bash
docker compose -f services/graph/docker-compose.yml up --build
```

## Notes

- This mode is optional and does not change `vulngate scan` contract.
- For strict air-gapped mode, use `memory` backend or self-hosted Neo4j inside the environment.
