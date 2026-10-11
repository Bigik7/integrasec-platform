package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	Addr         string
	DBPath       string
	BootstrapKey string
	MaxBodyBytes int64
	FrontendDir  string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:         getenv("INTEGRASEC_ADDR", ":8080"),
		DBPath:       getenv("INTEGRASEC_DB_PATH", "./data/integrasec.db"),
		BootstrapKey: os.Getenv("INTEGRASEC_BOOTSTRAP_KEY"),
		FrontendDir:  getenv("INTEGRASEC_FRONTEND_DIR", "../frontend"),
	}

	maxBodyRaw := getenv("INTEGRASEC_MAX_BODY_BYTES", "1048576")
	maxBody, err := strconv.ParseInt(maxBodyRaw, 10, 64)
	if err != nil || maxBody <= 0 {
		return Config{}, fmt.Errorf("invalid INTEGRASEC_MAX_BODY_BYTES: %q", maxBodyRaw)
	}
	cfg.MaxBodyBytes = maxBody

	if cfg.BootstrapKey == "" {
		return Config{}, fmt.Errorf("INTEGRASEC_BOOTSTRAP_KEY is required")
	}

	cfg.DBPath = filepath.Clean(cfg.DBPath)
	cfg.FrontendDir = filepath.Clean(cfg.FrontendDir)

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
