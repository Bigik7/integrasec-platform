package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Bigik7/integrasec-platform/backend/internal/config"
	"github.com/Bigik7/integrasec-platform/backend/internal/model"
	"github.com/Bigik7/integrasec-platform/backend/internal/storage"
)

var machineIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

type Server struct {
	cfg   config.Config
	store *storage.Store
	mux   *http.ServeMux
}

type registerMachineRequest struct {
	MachineID string `json:"machine_id"`
	Hostname  string `json:"hostname"`
	AgentKey  string `json:"agent_key"`
}

func New(cfg config.Config, store *storage.Store) *Server {
	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("POST /api/v1/machines/register", s.registerMachine)
	s.mux.HandleFunc("GET /api/v1/machines", s.withAgentAuth(s.listMachines))
	s.mux.HandleFunc("POST /api/v1/events", s.withAgentAuth(s.ingestEvents))
	s.mux.HandleFunc("GET /api/v1/events", s.withAgentAuth(s.listEvents))

	if _, err := os.Stat(s.cfg.FrontendDir); err == nil {
		fileServer := http.FileServer(http.Dir(s.cfg.FrontendDir))
		s.mux.Handle("/", fileServer)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"timestamp_utc": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) registerMachine(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Bootstrap-Key") != s.cfg.BootstrapKey {
		writeError(w, http.StatusUnauthorized, "invalid bootstrap key")
		return
	}

	var req registerMachineRequest
	if err := s.decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !machineIDPattern.MatchString(req.MachineID) {
		writeError(w, http.StatusBadRequest, "machine_id is invalid")
		return
	}
	if req.Hostname == "" || len(req.Hostname) > 255 {
		writeError(w, http.StatusBadRequest, "hostname is invalid")
		return
	}
	if len(req.AgentKey) < 16 || len(req.AgentKey) > 128 {
		writeError(w, http.StatusBadRequest, "agent_key must be 16-128 chars")
		return
	}

	if err := s.store.RegisterMachine(req.MachineID, req.Hostname, req.AgentKey); err != nil {
		log.Printf("register machine failed: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot register machine")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (s *Server) listMachines(w http.ResponseWriter, _ *http.Request, _ string) {
	machines, err := s.store.ListMachines()
	if err != nil {
		log.Printf("list machines failed: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot list machines")
		return
	}
	writeJSON(w, http.StatusOK, machines)
}

func (s *Server) ingestEvents(w http.ResponseWriter, r *http.Request, authMachine string) {
	var events []model.IntegrityEvent
	if err := s.decodeJSON(r, &events); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(events) == 0 {
		writeError(w, http.StatusBadRequest, "events cannot be empty")
		return
	}
	if len(events) > 5000 {
		writeError(w, http.StatusBadRequest, "too many events in one request")
		return
	}

	for i := range events {
		if err := validateEvent(events[i], authMachine); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("event[%d]: %v", i, err))
			return
		}
	}

	if err := s.store.InsertEvents(events); err != nil {
		log.Printf("insert events failed: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot store events")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(events)})
}

func validateEvent(e model.IntegrityEvent, authMachine string) error {
	if e.Machine != authMachine {
		return fmt.Errorf("machine does not match authenticated key")
	}
	if e.Path == "" || !filepath.IsAbs(e.Path) {
		return errors.New("path must be absolute")
	}
	clean := filepath.Clean(e.Path)
	if strings.Contains(e.Path, "..") || clean != e.Path || strings.Contains(clean, "..") {
		return errors.New("path contains traversal")
	}
	if e.Type != "added" && e.Type != "deleted" && e.Type != "modified" {
		return errors.New("invalid event type")
	}
	if !validHashOptional(e.OldHash) || !validHashOptional(e.NewHash) {
		return errors.New("hashes must be empty or SHA-256 hex")
	}
	if e.Severity != "low" && e.Severity != "medium" && e.Severity != "high" && e.Severity != "critical" {
		return errors.New("invalid severity")
	}
	ts, err := time.Parse(time.RFC3339, e.TimestampUTC)
	if err != nil {
		return errors.New("timestamp_utc must be RFC3339")
	}
	if ts.Location() != time.UTC {
		return errors.New("timestamp_utc must be UTC")
	}
	return nil
}

func validHashOptional(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request, _ string) {
	machineID := r.URL.Query().Get("machine")
	eventType := r.URL.Query().Get("type")
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil || limit <= 0 || limit > 500 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
	}
	if machineID != "" && !machineIDPattern.MatchString(machineID) {
		writeError(w, http.StatusBadRequest, "machine filter is invalid")
		return
	}

	events, err := s.store.ListEvents(machineID, eventType, limit)
	if err != nil {
		log.Printf("list events failed: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot list events")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) withAgentAuth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentKey := r.Header.Get("X-Agent-Key")
		if agentKey == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Agent-Key")
			return
		}
		machineID, ok, err := s.store.FindMachineByAgentKey(agentKey)
		if err != nil {
			log.Printf("auth failed: %v", err)
			writeError(w, http.StatusInternalServerError, "authentication failed")
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid agent key")
			return
		}
		next(w, r, machineID)
	}
}

func (s *Server) decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, s.cfg.MaxBodyBytes)
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON payload")
	}
	if dec.More() {
		return errors.New("payload must contain a single JSON object or array")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
