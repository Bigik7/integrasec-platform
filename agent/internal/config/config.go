package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	MachineID            string   `json:"machine_id"`
	Paths                []string `json:"paths"`
	BaselinePath         string   `json:"baseline_path"`
	BackendURL           string   `json:"backend_url"`
	AgentKeyEnv          string   `json:"agent_key_env"`
	WatchIntervalSeconds int      `json:"watch_interval_seconds"`
	Output               string   `json:"output"`
}

func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config JSON: %w", err)
	}

	if len(cfg.Paths) == 0 {
		return Config{}, errors.New("at least one path is required")
	}
	for i, p := range cfg.Paths {
		if !filepath.IsAbs(p) {
			return Config{}, fmt.Errorf("path must be absolute: %s", p)
		}
		cfg.Paths[i] = filepath.Clean(p)
	}

	if cfg.BaselinePath == "" {
		return Config{}, errors.New("baseline_path is required")
	}
	cfg.BaselinePath = filepath.Clean(cfg.BaselinePath)

	if cfg.WatchIntervalSeconds <= 0 {
		cfg.WatchIntervalSeconds = 30
	}
	if cfg.Output == "" {
		cfg.Output = "text"
	}
	if cfg.Output != "text" && cfg.Output != "json" {
		return Config{}, errors.New("output must be 'text' or 'json'")
	}

	return cfg, nil
}

func (c Config) AgentKey() string {
	if c.AgentKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.AgentKeyEnv)
}
