package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Bigik7/integrasec-platform/agent/internal/integrity"
)

func SendEvents(baseURL, agentKey string, events []integrity.Event) error {
	if baseURL == "" || len(events) == 0 {
		return nil
	}
	if agentKey == "" {
		return fmt.Errorf("agent key is empty")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/events"

	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", agentKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("backend rejected events (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}
