package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/Bigik7/integrasec-platform/agent/internal/client"
	"github.com/Bigik7/integrasec-platform/agent/internal/config"
	"github.com/Bigik7/integrasec-platform/agent/internal/integrity"
	"github.com/Bigik7/integrasec-platform/agent/internal/output"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "baseline":
		runWithConfig(cmd, runBaseline)
	case "scan":
		runWithConfig(cmd, runScan)
	case "watch":
		runWithConfig(cmd, runWatch)
	default:
		usage()
		os.Exit(2)
	}
}

func runWithConfig(name string, runner func(context.Context, config.Config) error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	configPath := fs.String("config", "./config.example.json", "Chemin du fichier de configuration JSON")
	jsonOutput := fs.Bool("json", false, "Force la sortie JSON")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Configuration invalide: %v", err)
	}
	if *jsonOutput {
		cfg.Output = "json"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := runner(ctx, cfg); err != nil {
		log.Fatalf("Erreur: %v", err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: integrasec-agent <baseline|scan|watch> --config <fichier.json> [--json]`)
}

func runBaseline(_ context.Context, cfg config.Config) error {
	baseline, errs := integrity.NewBaseline(cfg.Paths)
	for _, err := range errs {
		log.Printf("warning: %v", err)
	}
	if err := integrity.SaveBaseline(cfg.BaselinePath, baseline); err != nil {
		return err
	}
	if cfg.Output == "json" {
		fmt.Printf("{\"status\":\"ok\",\"files\":%d,\"baseline\":%q}\n", len(baseline.Files), cfg.BaselinePath)
	} else {
		fmt.Printf("Baseline créée: %s (%d fichiers)\n", cfg.BaselinePath, len(baseline.Files))
	}
	return nil
}

func runScan(_ context.Context, cfg config.Config) error {
	events, _, err := scanOnce(cfg)
	if err != nil {
		return err
	}
	return output.PrintEvents(os.Stdout, events, cfg.Output)
}

func scanOnce(cfg config.Config) ([]integrity.Event, []error, error) {
	baseline, err := integrity.LoadBaseline(cfg.BaselinePath)
	if err != nil {
		return nil, nil, err
	}
	current, errs := integrity.BuildSnapshot(cfg.Paths)
	events := integrity.CompareBaseline(cfg.MachineID, baseline, current, time.Now())

	if err := client.SendEvents(cfg.BackendURL, cfg.AgentKey(), events); err != nil {
		return nil, errs, err
	}
	return events, errs, nil
}

func runWatch(ctx context.Context, cfg config.Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	for _, root := range cfg.Paths {
		if err := addRecursiveWatch(watcher, root); err != nil {
			log.Printf("warning: %v", err)
		}
	}

	ticker := time.NewTicker(time.Duration(cfg.WatchIntervalSeconds) * time.Second)
	defer ticker.Stop()
	trigger := make(chan struct{}, 1)

	runReliableScan := func(reason string) {
		events, warns, err := scanOnce(cfg)
		for _, w := range warns {
			log.Printf("warning: %v", w)
		}
		if err != nil {
			log.Printf("scan failed (%s): %v", reason, err)
			return
		}
		if err := output.PrintEvents(os.Stdout, events, cfg.Output); err != nil {
			log.Printf("output error: %v", err)
		}
	}

	runReliableScan("startup")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			runReliableScan("periodic")
		case <-trigger:
			runReliableScan("filesystem event")
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = addRecursiveWatch(watcher, event.Name)
				}
			}
			select {
			case trigger <- struct{}{}:
			default:
			}
		case err := <-watcher.Errors:
			if !errors.Is(err, os.ErrClosed) {
				log.Printf("watch error: %v", err)
			}
		}
	}
}

func addRecursiveWatch(w *fsnotify.Watcher, root string) error {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("cannot watch %s: %w", root, err)
	}
	if !info.IsDir() {
		return w.Add(root)
	}

	return filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsPermission(walkErr) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if err := w.Add(path); err != nil {
				log.Printf("warning: cannot watch %s: %v", path, err)
			}
		}
		return nil
	})
}
