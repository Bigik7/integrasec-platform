SHELL := /bin/bash

.PHONY: fmt lint test run-backend run-agent-baseline run-agent-scan run-agent-watch

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

lint:
	@files=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$files" ]; then \
		echo "Files need gofmt:"; echo "$$files"; exit 1; \
	fi

test:
	go test ./agent/... ./backend/...

run-backend:
	cd backend && go run ./cmd/integrasec-backend

run-agent-baseline:
	cd agent && go run ./cmd/integrasec-agent baseline --config ./config.example.json

run-agent-scan:
	cd agent && go run ./cmd/integrasec-agent scan --config ./config.example.json

run-agent-watch:
	cd agent && go run ./cmd/integrasec-agent watch --config ./config.example.json
