package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "fichier.txt")
	if err := os.WriteFile(path, []byte("integrasec"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}
	const expected = "7dd87905c8b5ebdf026f73f3344f805512b896b9ad5292faa5ab6dff45cac213"
	if hash != expected {
		t.Fatalf("unexpected hash: got %s want %s", hash, expected)
	}
}
