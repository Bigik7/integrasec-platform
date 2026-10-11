package model

type Machine struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	RegisteredUTC string `json:"registered_utc"`
}

type IntegrityEvent struct {
	Machine      string `json:"machine"`
	Path         string `json:"path"`
	Type         string `json:"type"`
	OldHash      string `json:"old_hash,omitempty"`
	NewHash      string `json:"new_hash,omitempty"`
	TimestampUTC string `json:"timestamp_utc"`
	Severity     string `json:"severity"`
}
