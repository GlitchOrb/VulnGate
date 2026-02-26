package store

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/GlitchOrb/vulngate/services/graph/model"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jConfig struct {
	URI      string
	Username string
	Password string
	Database string
}

type Neo4jStore struct {
	driver   neo4j.DriverWithContext
	database string
}

func NewNeo4jStore(ctx context.Context, cfg Neo4jConfig) (*Neo4jStore, error) {
	uri := strings.TrimSpace(cfg.URI)
	if uri == "" {
		return nil, fmt.Errorf("neo4j uri is empty")
	}
	user := strings.TrimSpace(cfg.Username)
	if user == "" {
		user = "neo4j"
	}
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, cfg.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("create neo4j driver: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("verify neo4j connectivity: %w", err)
	}
	return &Neo4jStore{driver: driver, database: strings.TrimSpace(cfg.Database)}, nil
}

func (n *Neo4jStore) UpsertService(ctx context.Context, name string) error {
	service := normalizeID(name)
	if service == "" {
		return fmt.Errorf("service is empty")
	}
	return n.write(ctx, `MERGE (s:Service {name:$name})`, map[string]any{"name": service})
}

func (n *Neo4jStore) UpsertArtifact(ctx context.Context, artifact model.Artifact) error {
	artifact.ID = normalizeID(artifact.ID)
	if artifact.ID == "" {
		return fmt.Errorf("artifact id is empty")
	}
	return n.write(ctx, `
MERGE (a:Artifact {id:$id})
SET a.name=$name, a.type=$type, a.digest=$digest, a.source=$source
`, map[string]any{
		"id":     artifact.ID,
		"name":   strings.TrimSpace(artifact.Name),
		"type":   strings.TrimSpace(artifact.Type),
		"digest": strings.TrimSpace(artifact.Digest),
		"source": strings.TrimSpace(artifact.Source),
	})
}

func (n *Neo4jStore) LinkServiceArtifact(ctx context.Context, service string, artifactID string) error {
	service = normalizeID(service)
	artifactID = normalizeID(artifactID)
	if service == "" || artifactID == "" {
		return fmt.Errorf("service or artifact id is empty")
	}
	return n.write(ctx, `
MERGE (s:Service {name:$service})
MERGE (a:Artifact {id:$artifactID})
MERGE (s)-[:DEPLOYS]->(a)
`, map[string]any{"service": service, "artifactID": artifactID})
}

func (n *Neo4jStore) UpsertPackage(ctx context.Context, pkg model.Package) error {
	pkg.PURL = normalizePURL(pkg.PURL)
	if pkg.PURL == "" {
		return fmt.Errorf("package purl is empty")
	}
	return n.write(ctx, `
MERGE (p:Package {purl:$purl})
SET p.name=$name, p.version=$version, p.ecosystem=$ecosystem
`, map[string]any{
		"purl":      pkg.PURL,
		"name":      strings.TrimSpace(pkg.Name),
		"version":   strings.TrimSpace(pkg.Version),
		"ecosystem": strings.TrimSpace(pkg.Ecosystem),
	})
}

func (n *Neo4jStore) LinkArtifactPackage(ctx context.Context, artifactID string, purl string) error {
	artifactID = normalizeID(artifactID)
	purl = normalizePURL(purl)
	if artifactID == "" || purl == "" {
		return fmt.Errorf("artifact id or purl is empty")
	}
	return n.write(ctx, `
MERGE (a:Artifact {id:$artifactID})
MERGE (p:Package {purl:$purl})
MERGE (a)-[:CONTAINS]->(p)
`, map[string]any{"artifactID": artifactID, "purl": purl})
}

func (n *Neo4jStore) LinkPackageDependency(ctx context.Context, fromPURL string, toPURL string) error {
	fromPURL = normalizePURL(fromPURL)
	toPURL = normalizePURL(toPURL)
	if fromPURL == "" || toPURL == "" {
		return fmt.Errorf("dependency purl is empty")
	}
	return n.write(ctx, `
MERGE (a:Package {purl:$from})
MERGE (b:Package {purl:$to})
MERGE (a)-[:DEPENDS_ON]->(b)
`, map[string]any{"from": fromPURL, "to": toPURL})
}

func (n *Neo4jStore) UpsertVulnerability(ctx context.Context, vuln model.Vulnerability) error {
	vuln.ID = normalizeID(vuln.ID)
	if vuln.ID == "" {
		return fmt.Errorf("vulnerability id is empty")
	}
	return n.write(ctx, `
MERGE (v:Vulnerability {id:$id})
SET v.severity=$severity
`, map[string]any{"id": vuln.ID, "severity": strings.TrimSpace(vuln.Severity)})
}

func (n *Neo4jStore) LinkPackageVulnerability(ctx context.Context, packagePURL string, vulnID string, source string) error {
	packagePURL = normalizePURL(packagePURL)
	vulnID = normalizeID(vulnID)
	if packagePURL == "" || vulnID == "" {
		return fmt.Errorf("package purl or vulnerability id is empty")
	}
	return n.write(ctx, `
MERGE (p:Package {purl:$purl})
MERGE (v:Vulnerability {id:$vuln})
MERGE (p)-[r:AFFECTED_BY]->(v)
SET r.source=$source
`, map[string]any{"purl": packagePURL, "vuln": vulnID, "source": strings.TrimSpace(source)})
}

func (n *Neo4jStore) RecordVEXStatement(ctx context.Context, statement model.VEXStatement) error {
	statement.ID = normalizeID(statement.ID)
	statement.VulnID = normalizeID(statement.VulnID)
	statement.PackagePURL = normalizePURL(statement.PackagePURL)
	if statement.ID == "" {
		statement.ID = fmt.Sprintf("%s|%s|%s", statement.VulnID, statement.PackagePURL, strings.ToLower(strings.TrimSpace(statement.Status)))
	}
	if statement.VulnID == "" || statement.PackagePURL == "" {
		return fmt.Errorf("vex statement requires vuln id and package purl")
	}

	return n.write(ctx, `
MERGE (v:Vulnerability {id:$vuln})
MERGE (p:Package {purl:$purl})
MERGE (x:VEXStatement {id:$id})
SET x.status=$status, x.justification=$justification, x.artifactID=$artifactID, x.timestamp=$timestamp
MERGE (x)-[:ASSERTS]->(v)
MERGE (x)-[:APPLIES_TO]->(p)
`, map[string]any{
		"id":            statement.ID,
		"vuln":          statement.VulnID,
		"purl":          statement.PackagePURL,
		"status":        strings.TrimSpace(statement.Status),
		"justification": strings.TrimSpace(statement.Justification),
		"artifactID":    strings.TrimSpace(statement.ArtifactID),
		"timestamp":     statement.Timestamp,
	})
}

func (n *Neo4jStore) UpsertAttestation(ctx context.Context, att model.Attestation) error {
	att.ID = normalizeID(att.ID)
	if att.ID == "" {
		return fmt.Errorf("attestation id is empty")
	}
	return n.write(ctx, `
MERGE (a:Attestation {id:$id})
SET a.type=$type, a.predicateType=$predicateType, a.issuer=$issuer, a.subjectDigest=$subjectDigest, a.metadata=$metadata
`, map[string]any{
		"id":            att.ID,
		"type":          strings.TrimSpace(att.Type),
		"predicateType": strings.TrimSpace(att.PredicateType),
		"issuer":        strings.TrimSpace(att.Issuer),
		"subjectDigest": strings.TrimSpace(att.SubjectDigest),
		"metadata":      att.Metadata,
	})
}

func (n *Neo4jStore) LinkArtifactAttestation(ctx context.Context, artifactID string, attestationID string) error {
	artifactID = normalizeID(artifactID)
	attestationID = normalizeID(attestationID)
	if artifactID == "" || attestationID == "" {
		return fmt.Errorf("artifact id or attestation id is empty")
	}
	return n.write(ctx, `
MERGE (artifact:Artifact {id:$artifactID})
MERGE (att:Attestation {id:$attestationID})
MERGE (artifact)-[:HAS_ATTESTATION]->(att)
`, map[string]any{"artifactID": artifactID, "attestationID": attestationID})
}

func (n *Neo4jStore) QueryServicesByVulnerability(ctx context.Context, vulnID string) (model.ServicesByVulnResult, error) {
	vulnID = normalizeID(vulnID)
	if vulnID == "" {
		return model.ServicesByVulnResult{}, fmt.Errorf("vulnerability id is empty")
	}

	records, err := n.read(ctx, `
MATCH (v:Vulnerability {id:$vulnID})<-[:AFFECTED_BY]-(p:Package)<-[:CONTAINS]-(a:Artifact)<-[:DEPLOYS]-(s:Service)
RETURN s.name AS service, collect(DISTINCT a.id) AS artifacts, collect(DISTINCT p.purl) AS packages
ORDER BY service
`, map[string]any{"vulnID": vulnID})
	if err != nil {
		return model.ServicesByVulnResult{}, err
	}

	out := model.ServicesByVulnResult{VulnID: vulnID, Services: []model.ServiceImpact{}}
	for _, record := range records {
		service, _ := record["service"].(string)
		out.Services = append(out.Services, model.ServiceImpact{
			Service:      strings.TrimSpace(service),
			ArtifactIDs:  anyToSortedStrings(record["artifacts"]),
			PackagePURLs: anyToSortedStrings(record["packages"]),
		})
	}
	return out, nil
}

func (n *Neo4jStore) QueryBlastRadius(ctx context.Context, packagePURL string) (model.BlastRadiusResult, error) {
	packagePURL = normalizePURL(packagePURL)
	if packagePURL == "" {
		return model.BlastRadiusResult{}, fmt.Errorf("package purl is empty")
	}

	records, err := n.read(ctx, `
MATCH (target:Package {purl:$purl})
OPTIONAL MATCH (d:Package)-[:DEPENDS_ON]->(target)
WITH target, collect(DISTINCT d.purl) AS direct
OPTIONAL MATCH (t:Package)-[:DEPENDS_ON*1..]->(target)
WITH target, direct, collect(DISTINCT t.purl) AS allDeps
OPTIONAL MATCH (target)-[:AFFECTED_BY]->(v:Vulnerability)
WITH target, direct, allDeps, collect(DISTINCT v.id) AS vulns
UNWIND (allDeps + [target.purl]) AS impacted
OPTIONAL MATCH (p:Package {purl:impacted})<-[:CONTAINS]-(a:Artifact)<-[:DEPLOYS]-(s:Service)
RETURN target.purl AS purl, direct, allDeps, collect(DISTINCT a.id) AS artifacts, collect(DISTINCT s.name) AS services, vulns
`, map[string]any{"purl": packagePURL})
	if err != nil {
		return model.BlastRadiusResult{}, err
	}
	if len(records) == 0 {
		return model.BlastRadiusResult{PackagePURL: packagePURL}, nil
	}

	record := records[0]
	direct := anyToStringSet(record["direct"])
	allDeps := anyToStringSet(record["allDeps"])
	transitive := newStringSet()
	for dep := range allDeps {
		if !direct.has(dep) {
			transitive.add(dep)
		}
	}

	return model.BlastRadiusResult{
		PackagePURL:            packagePURL,
		Services:               anyToSortedStrings(record["services"]),
		Artifacts:              anyToSortedStrings(record["artifacts"]),
		DirectDependents:       direct.toSortedSlice(),
		TransitiveDependents:   transitive.toSortedSlice(),
		RelatedVulnerabilities: anyToSortedStrings(record["vulns"]),
	}, nil
}

func (n *Neo4jStore) QueryVulnerabilitiesByService(ctx context.Context, service string) (model.VulnsByServiceResult, error) {
	service = normalizeID(service)
	if service == "" {
		return model.VulnsByServiceResult{}, fmt.Errorf("service is empty")
	}

	records, err := n.read(ctx, `
MATCH (s:Service {name:$service})-[:DEPLOYS]->(a:Artifact)-[:CONTAINS]->(p:Package)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN v.id AS vulnID, collect(DISTINCT a.id) AS artifacts, collect(DISTINCT p.purl) AS packages
ORDER BY vulnID
`, map[string]any{"service": service})
	if err != nil {
		return model.VulnsByServiceResult{}, err
	}

	result := model.VulnsByServiceResult{Service: service, Vulns: []model.VulnerabilityImpact{}}
	for _, record := range records {
		vulnID, _ := record["vulnID"].(string)
		result.Vulns = append(result.Vulns, model.VulnerabilityImpact{
			VulnID:       strings.TrimSpace(vulnID),
			ArtifactIDs:  anyToSortedStrings(record["artifacts"]),
			PackagePURLs: anyToSortedStrings(record["packages"]),
		})
	}
	return result, nil
}

func (n *Neo4jStore) Close() error {
	if n.driver == nil {
		return nil
	}
	return n.driver.Close(context.Background())
}

func (n *Neo4jStore) write(ctx context.Context, query string, params map[string]any) error {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: n.database})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("neo4j write query failed: %w", err)
	}
	return nil
}

func (n *Neo4jStore) read(ctx context.Context, query string, params map[string]any) ([]map[string]any, error) {
	session := n.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: n.database})
	defer session.Close(ctx)

	resultAny, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		rows := []map[string]any{}
		for result.Next(ctx) {
			record := result.Record()
			rows = append(rows, record.AsMap())
		}
		if err := result.Err(); err != nil {
			return nil, err
		}
		return rows, nil
	})
	if err != nil {
		return nil, fmt.Errorf("neo4j read query failed: %w", err)
	}
	rows, ok := resultAny.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected neo4j read result type %T", resultAny)
	}
	return rows, nil
}

func anyToSortedStrings(raw any) []string {
	return anyToStringSet(raw).toSortedSlice()
}

func anyToStringSet(raw any) stringSet {
	set := newStringSet()
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			set.add(fmt.Sprintf("%v", item))
		}
	case []string:
		for _, item := range typed {
			set.add(item)
		}
	case nil:
		return set
	default:
		set.add(fmt.Sprintf("%v", typed))
	}

	clean := newStringSet()
	for item := range set {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" || strings.EqualFold(trimmed, "<nil>") {
			continue
		}
		clean.add(trimmed)
	}
	return clean
}

func sortUnique(values []string) []string {
	set := newStringSet(values...)
	out := set.toSortedSlice()
	sort.Strings(out)
	return out
}
