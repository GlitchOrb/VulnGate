package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/GlitchOrb/vulngate/services/graph/export"
	"github.com/GlitchOrb/vulngate/services/graph/ingest"
	"github.com/GlitchOrb/vulngate/services/graph/store"
)

type Server struct {
	store  store.GraphStore
	logger *log.Logger
	mux    *http.ServeMux
}

func NewServer(graph store.GraphStore, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{store: graph, logger: logger, mux: http.NewServeMux()}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return withRequestLogging(s.logger, s.mux)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)

	s.mux.HandleFunc("/ingest/cyclonedx", s.handleIngestCycloneDX)
	s.mux.HandleFunc("/ingest/openvex", s.handleIngestOpenVEX)
	s.mux.HandleFunc("/ingest/attestations", s.handleIngestAttestations)
	s.mux.HandleFunc("/ingest/bundle", s.handleIngestBundle)

	s.mux.HandleFunc("/export/cyclonedx", s.handleExportCycloneDX)
	s.mux.HandleFunc("/export/openvex", s.handleExportOpenVEX)
	s.mux.HandleFunc("/export/attestations", s.handleExportAttestations)

	s.mux.HandleFunc("/query/services-by-vuln", s.handleQueryServicesByVuln)
	s.mux.HandleFunc("/query/blast-radius", s.handleQueryBlastRadius)
	s.mux.HandleFunc("/query/vulns-by-service", s.handleQueryVulnsByService)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "vulngate-graph"})
}

func (s *Server) handleIngestCycloneDX(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req ingest.CycloneDXIngestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := ingest.IngestCycloneDX(r.Context(), s.store, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleIngestOpenVEX(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req ingest.OpenVEXIngestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := ingest.IngestOpenVEX(r.Context(), s.store, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleIngestAttestations(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req ingest.AttestationIngestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := ingest.IngestAttestations(r.Context(), s.store, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleIngestBundle(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req ingest.BundleIngestRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := ingest.IngestBundle(r.Context(), s.store, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportCycloneDX(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req export.CycloneDXExportRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	payload, err := export.ToCycloneDX(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleExportOpenVEX(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req export.OpenVEXExportRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	payload, err := export.ToOpenVEX(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleExportAttestations(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req export.AttestationsExportRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	payload, err := export.ToAttestations(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleQueryServicesByVuln(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	vulnID := strings.TrimSpace(r.URL.Query().Get("vuln"))
	if vulnID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing query param: vuln"))
		return
	}

	result, err := s.store.QueryServicesByVulnerability(r.Context(), vulnID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleQueryBlastRadius(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	purl := strings.TrimSpace(r.URL.Query().Get("purl"))
	if purl == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing query param: purl"))
		return
	}

	result, err := s.store.QueryBlastRadius(r.Context(), purl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleQueryVulnsByService(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	if service == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing query param: service"))
		return
	}

	result, err := s.store.QueryVulnerabilitiesByService(r.Context(), service)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func allowMethod(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method == expected {
		return true
	}
	w.Header().Set("Allow", expected)
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
	return false
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, 4<<20)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode request json: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request must contain a single JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = fmt.Errorf("unknown error")
	}
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func withRequestLogging(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if logger != nil {
			logger.Printf("graph api %s %s duration=%s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func ContextWithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 15*time.Second)
}
