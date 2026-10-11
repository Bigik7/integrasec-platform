package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Bigik7/integrasec-platform/agent/internal/integrity"
)

func PrintEvents(w io.Writer, events []integrity.Event, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
	}

	if len(events) == 0 {
		_, err := fmt.Fprintln(w, "Aucun changement détecté.")
		return err
	}
	for _, event := range events {
		if _, err := fmt.Fprintf(w, "[%s] %s | %s | old=%s new=%s\n", event.Severity, event.Type, event.Path, event.OldHash, event.NewHash); err != nil {
			return err
		}
	}
	return nil
}
