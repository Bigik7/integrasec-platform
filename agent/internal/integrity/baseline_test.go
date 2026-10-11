package integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompareBaseline(t *testing.T) {
	t.Parallel()
	baseline := Baseline{Files: map[string]FileEntry{
		"/tmp/keep": {Path: "/tmp/keep", Hash: "aaa"},
		"/tmp/del":  {Path: "/tmp/del", Hash: "bbb"},
	}}
	current := map[string]FileEntry{
		"/tmp/keep": {Path: "/tmp/keep", Hash: "ccc"},
		"/tmp/new":  {Path: "/tmp/new", Hash: "ddd"},
	}
	events := CompareBaseline("m1", baseline, current, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	found := map[string]bool{}
	for _, event := range events {
		found[event.Type] = true
		if event.TimestampUTC != "2026-01-01T00:00:00Z" {
			t.Fatalf("timestamp should be UTC, got %s", event.TimestampUTC)
		}
	}
	for _, typ := range []string{"added", "deleted", "modified"} {
		if !found[typ] {
			t.Fatalf("missing event type %s", typ)
		}
	}
}

func TestBuildSnapshotWithFileAndDirectory(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f1 := filepath.Join(tmp, "a.txt")
	if err := os.WriteFile(f1, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	f2 := filepath.Join(tmp, "sub", "b.txt")
	if err := os.WriteFile(f2, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapshot, errs := BuildSnapshot([]string{tmp, f1})
	if len(errs) != 0 {
		t.Fatalf("unexpected warnings: %v", errs)
	}
	if len(snapshot) != 2 {
		t.Fatalf("expected 2 files, got %d", len(snapshot))
	}
}
