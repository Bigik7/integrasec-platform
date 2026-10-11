package integrity

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FileEntry struct {
	Path       string `json:"path"`
	Hash       string `json:"hash"`
	Size       int64  `json:"size"`
	ModTimeUTC string `json:"mod_time_utc"`
}

type Baseline struct {
	CreatedAtUTC string               `json:"created_at_utc"`
	Files        map[string]FileEntry `json:"files"`
}

type Event struct {
	Machine      string `json:"machine"`
	Path         string `json:"path"`
	Type         string `json:"type"`
	OldHash      string `json:"old_hash,omitempty"`
	NewHash      string `json:"new_hash,omitempty"`
	TimestampUTC string `json:"timestamp_utc"`
	Severity     string `json:"severity"`
}

func BuildSnapshot(paths []string) (map[string]FileEntry, []error) {
	files := make(map[string]FileEntry)
	var errs []error

	for _, basePath := range paths {
		basePath = filepath.Clean(basePath)
		info, err := os.Stat(basePath)
		if err != nil {
			errs = append(errs, fmt.Errorf("stat path %s: %w", basePath, err))
			continue
		}

		if !info.IsDir() {
			hash, err := HashFile(basePath)
			if err != nil {
				errs = append(errs, fmt.Errorf("hash %s: %w", basePath, err))
				continue
			}
			files[basePath] = FileEntry{
				Path:       basePath,
				Hash:       hash,
				Size:       info.Size(),
				ModTimeUTC: info.ModTime().UTC().Format(time.RFC3339),
			}
			continue
		}

		err = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, fmt.Errorf("walk %s: %w", path, walkErr))
				if os.IsPermission(walkErr) {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}

			stat, err := d.Info()
			if err != nil {
				errs = append(errs, fmt.Errorf("file info %s: %w", path, err))
				return nil
			}

			hash, err := HashFile(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("hash %s: %w", path, err))
				return nil
			}

			cleanPath := filepath.Clean(path)
			files[cleanPath] = FileEntry{
				Path:       cleanPath,
				Hash:       hash,
				Size:       stat.Size(),
				ModTimeUTC: stat.ModTime().UTC().Format(time.RFC3339),
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("walk path %s: %w", basePath, err))
		}
	}

	return files, errs
}

func NewBaseline(paths []string) (Baseline, []error) {
	snapshot, errs := BuildSnapshot(paths)
	return Baseline{
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Files:        snapshot,
	}, errs
}

func SaveBaseline(path string, baseline Baseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline JSON: %w", err)
	}
	if b.Files == nil {
		b.Files = map[string]FileEntry{}
	}
	return b, nil
}

func CompareBaseline(machineID string, baseline Baseline, current map[string]FileEntry, now time.Time) []Event {
	events := make([]Event, 0)
	nowUTC := now.UTC().Format(time.RFC3339)

	for path, base := range baseline.Files {
		cur, ok := current[path]
		if !ok {
			events = append(events, Event{
				Machine:      machineID,
				Path:         path,
				Type:         "deleted",
				OldHash:      base.Hash,
				TimestampUTC: nowUTC,
				Severity:     "high",
			})
			continue
		}
		if cur.Hash != base.Hash {
			events = append(events, Event{
				Machine:      machineID,
				Path:         path,
				Type:         "modified",
				OldHash:      base.Hash,
				NewHash:      cur.Hash,
				TimestampUTC: nowUTC,
				Severity:     "high",
			})
		}
	}

	for path, cur := range current {
		if _, ok := baseline.Files[path]; !ok {
			events = append(events, Event{
				Machine:      machineID,
				Path:         path,
				Type:         "added",
				NewHash:      cur.Hash,
				TimestampUTC: nowUTC,
				Severity:     "medium",
			})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return strings.Compare(events[i].Path, events[j].Path) < 0
	})
	return events
}
