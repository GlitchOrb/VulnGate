package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GlitchOrb/vulngate/services/graph/model"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

func TestGraphAPIIngestAndCanonicalQueries(t *testing.T) {
	graphStore := store.NewMemoryStore()
	t.Cleanup(func() { _ = graphStore.Close() })

	srv := httptest.NewServer(NewServer(graphStore, nil).Handler())
	t.Cleanup(srv.Close)

	postFixture(t, srv.URL+"/ingest/cyclonedx", filepath.Join("..", "testdata", "ingest_checkout.json"))
	postFixture(t, srv.URL+"/ingest/cyclonedx", filepath.Join("..", "testdata", "ingest_cart.json"))
	postFixture(t, srv.URL+"/ingest/openvex", filepath.Join("..", "testdata", "ingest_openvex.json"))
	postFixture(t, srv.URL+"/ingest/attestations", filepath.Join("..", "testdata", "ingest_attestations.json"))

	t.Run("services affected by vuln", func(t *testing.T) {
		resp := getJSON(t, srv.URL+"/query/services-by-vuln?vuln=OSV-2026-9999")
		var payload model.ServicesByVulnResult
		decodeInto(t, resp, &payload)

		if payload.VulnID != "OSV-2026-9999" {
			t.Fatalf("unexpected vuln id: %s", payload.VulnID)
		}
		services := []string{}
		for _, item := range payload.Services {
			services = append(services, item.Service)
		}
		if strings.Join(services, ",") != "cart,checkout" {
			t.Fatalf("unexpected impacted services: %v", services)
		}
	})

	t.Run("blast radius by package", func(t *testing.T) {
		resp := getJSON(t, srv.URL+"/query/blast-radius?purl=pkg:npm/lodash@4.17.20")
		var payload model.BlastRadiusResult
		decodeInto(t, resp, &payload)

		if payload.PackagePURL != "pkg:npm/lodash@4.17.20" {
			t.Fatalf("unexpected package purl: %s", payload.PackagePURL)
		}
		if !contains(payload.Services, "checkout") || !contains(payload.Services, "cart") {
			t.Fatalf("expected checkout and cart in blast radius services, got %v", payload.Services)
		}
		if !contains(payload.DirectDependents, "pkg:npm/axios@1.5.0") {
			t.Fatalf("expected axios direct dependent, got %v", payload.DirectDependents)
		}
	})

	t.Run("vulnerabilities by service", func(t *testing.T) {
		resp := getJSON(t, srv.URL+"/query/vulns-by-service?service=checkout")
		var payload model.VulnsByServiceResult
		decodeInto(t, resp, &payload)

		if payload.Service != "checkout" {
			t.Fatalf("unexpected service: %s", payload.Service)
		}
		vulns := []string{}
		for _, item := range payload.Vulns {
			vulns = append(vulns, item.VulnID)
		}
		if !contains(vulns, "OSV-2026-9999") || !contains(vulns, "CVE-2026-1111") {
			t.Fatalf("expected OSV and CVE vulns for checkout, got %v", vulns)
		}
	})
}

func TestExportEndpointsReturnExpectedShapes(t *testing.T) {
	graphStore := store.NewMemoryStore()
	t.Cleanup(func() { _ = graphStore.Close() })

	srv := httptest.NewServer(NewServer(graphStore, nil).Handler())
	t.Cleanup(srv.Close)

	payload := `{
  "service": "checkout",
  "artifactID": "ghcr.io/acme/checkout:1.0.0",
  "author": "VulnGate",
  "findings": [
    {"vulnID": "OSV-2026-9999", "packagePURL": "pkg:npm/lodash@4.17.20", "reachable": true}
  ]
}`

	resp := postJSON(t, srv.URL+"/export/openvex", []byte(payload))
	var body map[string]any
	decodeInto(t, resp, &body)
	if _, ok := body["document"]; !ok {
		t.Fatalf("expected document field in openvex export response: %v", body)
	}
}

func postFixture(t *testing.T, url string, fixturePath string) {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	postJSON(t, url, raw)
}

func postJSON(t *testing.T, url string, payload []byte) []byte {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, string(body))
	}
	return body
}

func getJSON(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, string(body))
	}
	return body
}

func decodeInto(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode json: %v raw=%s", err, string(raw))
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
