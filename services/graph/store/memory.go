package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/GlitchOrb/vulngate/services/graph/model"
)

type MemoryStore struct {
	mu sync.RWMutex

	services     map[string]bool
	artifacts    map[string]model.Artifact
	packages     map[string]model.Package
	vulns        map[string]model.Vulnerability
	attestations map[string]model.Attestation
	vex          map[string]model.VEXStatement

	serviceArtifacts     map[string]stringSet
	artifactServices     map[string]stringSet
	artifactPackages     map[string]stringSet
	packageArtifacts     map[string]stringSet
	packageDeps          map[string]stringSet
	reverseDeps          map[string]stringSet
	packageVulns         map[string]stringSet
	vulnPackages         map[string]stringSet
	artifactAttestations map[string]stringSet
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		services:             map[string]bool{},
		artifacts:            map[string]model.Artifact{},
		packages:             map[string]model.Package{},
		vulns:                map[string]model.Vulnerability{},
		attestations:         map[string]model.Attestation{},
		vex:                  map[string]model.VEXStatement{},
		serviceArtifacts:     map[string]stringSet{},
		artifactServices:     map[string]stringSet{},
		artifactPackages:     map[string]stringSet{},
		packageArtifacts:     map[string]stringSet{},
		packageDeps:          map[string]stringSet{},
		reverseDeps:          map[string]stringSet{},
		packageVulns:         map[string]stringSet{},
		vulnPackages:         map[string]stringSet{},
		artifactAttestations: map[string]stringSet{},
	}
}

func (m *MemoryStore) UpsertService(_ context.Context, name string) error {
	service := normalizeID(name)
	if service == "" {
		return fmt.Errorf("service is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[service] = true
	return nil
}

func (m *MemoryStore) UpsertArtifact(_ context.Context, artifact model.Artifact) error {
	artifact.ID = normalizeID(artifact.ID)
	if artifact.ID == "" {
		return fmt.Errorf("artifact id is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.artifacts[artifact.ID]; ok {
		if artifact.Name == "" {
			artifact.Name = existing.Name
		}
		if artifact.Type == "" {
			artifact.Type = existing.Type
		}
		if artifact.Digest == "" {
			artifact.Digest = existing.Digest
		}
		if artifact.Source == "" {
			artifact.Source = existing.Source
		}
	}
	m.artifacts[artifact.ID] = artifact
	return nil
}

func (m *MemoryStore) LinkServiceArtifact(_ context.Context, service string, artifactID string) error {
	service = normalizeID(service)
	artifactID = normalizeID(artifactID)
	if service == "" || artifactID == "" {
		return fmt.Errorf("service or artifact id is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[service] = true
	if _, ok := m.artifacts[artifactID]; !ok {
		m.artifacts[artifactID] = model.Artifact{ID: artifactID}
	}
	m.ensureSet(m.serviceArtifacts, service).add(artifactID)
	m.ensureSet(m.artifactServices, artifactID).add(service)
	return nil
}

func (m *MemoryStore) UpsertPackage(_ context.Context, pkg model.Package) error {
	pkg.PURL = normalizePURL(pkg.PURL)
	if pkg.PURL == "" {
		return fmt.Errorf("package purl is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.packages[pkg.PURL]; ok {
		if pkg.Name == "" {
			pkg.Name = existing.Name
		}
		if pkg.Version == "" {
			pkg.Version = existing.Version
		}
		if pkg.Ecosystem == "" {
			pkg.Ecosystem = existing.Ecosystem
		}
	}
	m.packages[pkg.PURL] = pkg
	return nil
}

func (m *MemoryStore) LinkArtifactPackage(_ context.Context, artifactID string, purl string) error {
	artifactID = normalizeID(artifactID)
	purl = normalizePURL(purl)
	if artifactID == "" || purl == "" {
		return fmt.Errorf("artifact id or purl is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.artifacts[artifactID]; !ok {
		m.artifacts[artifactID] = model.Artifact{ID: artifactID}
	}
	if _, ok := m.packages[purl]; !ok {
		m.packages[purl] = model.Package{PURL: purl}
	}
	m.ensureSet(m.artifactPackages, artifactID).add(purl)
	m.ensureSet(m.packageArtifacts, purl).add(artifactID)
	return nil
}

func (m *MemoryStore) LinkPackageDependency(_ context.Context, fromPURL string, toPURL string) error {
	fromPURL = normalizePURL(fromPURL)
	toPURL = normalizePURL(toPURL)
	if fromPURL == "" || toPURL == "" {
		return fmt.Errorf("dependency purl is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.packages[fromPURL]; !ok {
		m.packages[fromPURL] = model.Package{PURL: fromPURL}
	}
	if _, ok := m.packages[toPURL]; !ok {
		m.packages[toPURL] = model.Package{PURL: toPURL}
	}
	m.ensureSet(m.packageDeps, fromPURL).add(toPURL)
	m.ensureSet(m.reverseDeps, toPURL).add(fromPURL)
	return nil
}

func (m *MemoryStore) UpsertVulnerability(_ context.Context, vuln model.Vulnerability) error {
	vuln.ID = normalizeID(vuln.ID)
	if vuln.ID == "" {
		return fmt.Errorf("vulnerability id is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.vulns[vuln.ID]; ok && vuln.Severity == "" {
		vuln.Severity = existing.Severity
	}
	m.vulns[vuln.ID] = vuln
	return nil
}

func (m *MemoryStore) LinkPackageVulnerability(_ context.Context, packagePURL string, vulnID string, _ string) error {
	packagePURL = normalizePURL(packagePURL)
	vulnID = normalizeID(vulnID)
	if packagePURL == "" || vulnID == "" {
		return fmt.Errorf("package purl or vulnerability id is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.packages[packagePURL]; !ok {
		m.packages[packagePURL] = model.Package{PURL: packagePURL}
	}
	if _, ok := m.vulns[vulnID]; !ok {
		m.vulns[vulnID] = model.Vulnerability{ID: vulnID}
	}
	m.ensureSet(m.packageVulns, packagePURL).add(vulnID)
	m.ensureSet(m.vulnPackages, vulnID).add(packagePURL)
	return nil
}

func (m *MemoryStore) RecordVEXStatement(_ context.Context, statement model.VEXStatement) error {
	statement.ID = normalizeID(statement.ID)
	statement.VulnID = normalizeID(statement.VulnID)
	statement.PackagePURL = normalizePURL(statement.PackagePURL)
	if statement.ID == "" {
		statement.ID = fmt.Sprintf("%s|%s|%s", statement.VulnID, statement.PackagePURL, strings.ToLower(strings.TrimSpace(statement.Status)))
	}
	if statement.VulnID == "" || statement.PackagePURL == "" {
		return fmt.Errorf("vex statement requires vuln id and package purl")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.vex[statement.ID] = statement
	return nil
}

func (m *MemoryStore) UpsertAttestation(_ context.Context, att model.Attestation) error {
	att.ID = normalizeID(att.ID)
	if att.ID == "" {
		return fmt.Errorf("attestation id is empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestations[att.ID] = att
	return nil
}

func (m *MemoryStore) LinkArtifactAttestation(_ context.Context, artifactID string, attestationID string) error {
	artifactID = normalizeID(artifactID)
	attestationID = normalizeID(attestationID)
	if artifactID == "" || attestationID == "" {
		return fmt.Errorf("artifact id or attestation id is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.artifacts[artifactID]; !ok {
		m.artifacts[artifactID] = model.Artifact{ID: artifactID}
	}
	if _, ok := m.attestations[attestationID]; !ok {
		m.attestations[attestationID] = model.Attestation{ID: attestationID}
	}
	m.ensureSet(m.artifactAttestations, artifactID).add(attestationID)
	return nil
}

func (m *MemoryStore) QueryServicesByVulnerability(_ context.Context, vulnID string) (model.ServicesByVulnResult, error) {
	vulnID = normalizeID(vulnID)
	result := model.ServicesByVulnResult{VulnID: vulnID, Services: []model.ServiceImpact{}}
	if vulnID == "" {
		return result, fmt.Errorf("vulnerability id is empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	services := map[string]*struct {
		artifacts stringSet
		packages  stringSet
	}{}

	for pkg := range m.vulnPackages[vulnID] {
		for artifactID := range m.packageArtifacts[pkg] {
			for service := range m.artifactServices[artifactID] {
				entry := services[service]
				if entry == nil {
					entry = &struct {
						artifacts stringSet
						packages  stringSet
					}{artifacts: newStringSet(), packages: newStringSet()}
					services[service] = entry
				}
				entry.artifacts.add(artifactID)
				entry.packages.add(pkg)
			}
		}
	}

	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := services[name]
		result.Services = append(result.Services, model.ServiceImpact{
			Service:      name,
			ArtifactIDs:  entry.artifacts.toSortedSlice(),
			PackagePURLs: entry.packages.toSortedSlice(),
		})
	}
	return result, nil
}

func (m *MemoryStore) QueryBlastRadius(_ context.Context, packagePURL string) (model.BlastRadiusResult, error) {
	packagePURL = normalizePURL(packagePURL)
	if packagePURL == "" {
		return model.BlastRadiusResult{}, fmt.Errorf("package purl is empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	direct := newStringSet()
	for dep := range m.reverseDeps[packagePURL] {
		direct.add(dep)
	}

	allDependents := newStringSet()
	queue := direct.toSortedSlice()
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if allDependents.has(cur) {
			continue
		}
		allDependents.add(cur)
		for parent := range m.reverseDeps[cur] {
			if !allDependents.has(parent) {
				queue = append(queue, parent)
			}
		}
	}

	transitive := newStringSet()
	for dep := range allDependents {
		if !direct.has(dep) {
			transitive.add(dep)
		}
	}

	impactedPackages := newStringSet(packagePURL)
	for dep := range allDependents {
		impactedPackages.add(dep)
	}

	artifacts := newStringSet()
	services := newStringSet()
	for pkg := range impactedPackages {
		for artifactID := range m.packageArtifacts[pkg] {
			artifacts.add(artifactID)
			for service := range m.artifactServices[artifactID] {
				services.add(service)
			}
		}
	}

	vulns := newStringSet()
	for vuln := range m.packageVulns[packagePURL] {
		vulns.add(vuln)
	}

	return model.BlastRadiusResult{
		PackagePURL:            packagePURL,
		Services:               services.toSortedSlice(),
		Artifacts:              artifacts.toSortedSlice(),
		DirectDependents:       direct.toSortedSlice(),
		TransitiveDependents:   transitive.toSortedSlice(),
		RelatedVulnerabilities: vulns.toSortedSlice(),
	}, nil
}

func (m *MemoryStore) QueryVulnerabilitiesByService(_ context.Context, service string) (model.VulnsByServiceResult, error) {
	service = normalizeID(service)
	if service == "" {
		return model.VulnsByServiceResult{}, fmt.Errorf("service is empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	impacts := map[string]*struct {
		artifacts stringSet
		packages  stringSet
	}{}

	for artifactID := range m.serviceArtifacts[service] {
		for pkg := range m.artifactPackages[artifactID] {
			for vuln := range m.packageVulns[pkg] {
				entry := impacts[vuln]
				if entry == nil {
					entry = &struct {
						artifacts stringSet
						packages  stringSet
					}{artifacts: newStringSet(), packages: newStringSet()}
					impacts[vuln] = entry
				}
				entry.artifacts.add(artifactID)
				entry.packages.add(pkg)
			}
		}
	}

	ids := make([]string, 0, len(impacts))
	for vulnID := range impacts {
		ids = append(ids, vulnID)
	}
	sort.Strings(ids)

	result := model.VulnsByServiceResult{Service: service, Vulns: []model.VulnerabilityImpact{}}
	for _, vulnID := range ids {
		entry := impacts[vulnID]
		result.Vulns = append(result.Vulns, model.VulnerabilityImpact{
			VulnID:       vulnID,
			ArtifactIDs:  entry.artifacts.toSortedSlice(),
			PackagePURLs: entry.packages.toSortedSlice(),
		})
	}
	return result, nil
}

func (m *MemoryStore) Close() error {
	return nil
}

func (m *MemoryStore) ensureSet(target map[string]stringSet, key string) stringSet {
	set, ok := target[key]
	if ok {
		return set
	}
	set = newStringSet()
	target[key] = set
	return set
}
