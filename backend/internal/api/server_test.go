package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bigik7/integrasec-platform/backend/internal/config"
	"github.com/Bigik7/integrasec-platform/backend/internal/model"
	"github.com/Bigik7/integrasec-platform/backend/internal/storage"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Config{
		BootstrapKey: "bootstrap-secret",
		MaxBodyBytes: 1024 * 1024,
		FrontendDir:  t.TempDir(),
	}
	return New(cfg, store)
}

func TestHealth(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp := httptest.NewRecorder()

	srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
}

func TestE2ERegisterAndEventFlow(t *testing.T) {
	srv := setupTestServer(t)
	h := srv.Handler()

	registerBody := []byte(`{"machine_id":"m1","hostname":"srv1","agent_key":"1234567890abcdef"}`)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/machines/register", bytes.NewReader(registerBody))
	registerReq.Header.Set("X-Bootstrap-Key", "bootstrap-secret")
	registerResp := httptest.NewRecorder()
	h.ServeHTTP(registerResp, registerReq)
	if registerResp.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", registerResp.Code, registerResp.Body.String())
	}

	events := []model.IntegrityEvent{{
		Machine:      "m1",
		Path:         "/etc/ssh/sshd_config",
		Type:         "modified",
		OldHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NewHash:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TimestampUTC: time.Now().UTC().Format(time.RFC3339),
		Severity:     "high",
	}}
	payload, _ := json.Marshal(events)
	eventReq := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(payload))
	eventReq.Header.Set("X-Agent-Key", "1234567890abcdef")
	eventResp := httptest.NewRecorder()
	h.ServeHTTP(eventResp, eventReq)
	if eventResp.Code != http.StatusAccepted {
		t.Fatalf("event status = %d body=%s", eventResp.Code, eventResp.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/events?machine=m1&limit=10", nil)
	listReq.Header.Set("X-Agent-Key", "1234567890abcdef")
	listResp := httptest.NewRecorder()
	h.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}

	var got []model.IntegrityEvent
	if err := json.Unmarshal(listResp.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Machine != "m1" {
		t.Fatalf("unexpected machine: %s", got[0].Machine)
	}
}

func TestRejectTraversalPath(t *testing.T) {
	srv := setupTestServer(t)
	h := srv.Handler()

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/machines/register", bytes.NewReader([]byte(`{"machine_id":"m1","hostname":"srv1","agent_key":"1234567890abcdef"}`)))
	registerReq.Header.Set("X-Bootstrap-Key", "bootstrap-secret")
	h.ServeHTTP(httptest.NewRecorder(), registerReq)

	events := []model.IntegrityEvent{{
		Machine:      "m1",
		Path:         "/tmp/../etc/passwd",
		Type:         "added",
		NewHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TimestampUTC: time.Now().UTC().Format(time.RFC3339),
		Severity:     "medium",
	}}
	payload, _ := json.Marshal(events)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(payload))
	req.Header.Set("X-Agent-Key", "1234567890abcdef")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", resp.Code, resp.Body.String())
	}
}
