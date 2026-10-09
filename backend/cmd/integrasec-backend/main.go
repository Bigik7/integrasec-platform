package main

import (
	"log"
	"net/http"

	"github.com/Bigik7/integrasec-platform/backend/internal/api"
	"github.com/Bigik7/integrasec-platform/backend/internal/config"
	"github.com/Bigik7/integrasec-platform/backend/internal/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	store, err := storage.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("cannot initialize storage: %v", err)
	}
	defer store.Close()

	srv := api.New(cfg, store)
	log.Printf("IntegraSec backend listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, srv.Handler()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
