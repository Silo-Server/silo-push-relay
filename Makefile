# Silo Push Relay — developer workflow (mirrors silo-server's Makefile-driven setup).
# Commands assume the repository root is the cwd.

GO ?= env GOWORK=off go
BIN := bin

.PHONY: build run test test-integration vet lint fmt tidy \
        migrate-create migrate-up migrate-status relayctl docker loadtest

## build: compile the relay and relayctl binaries into ./bin
build:
	$(GO) build -o $(BIN)/relay ./cmd/relay
	$(GO) build -o $(BIN)/relayctl ./cmd/relayctl

## run: run the relay locally (PG/Redis wired in Phase 1)
run:
	$(GO) run ./cmd/relay

## test: unit + contract tests (no live providers)
test:
	$(GO) test ./...

## test-integration: APNs sandbox + FCM validateOnly contract tests (needs creds; Phase 3+)
test-integration:
	$(GO) test -tags=integration ./...

## vet: go vet
vet:
	$(GO) vet ./...

## lint: golangci-lint (installed in CI)
lint:
	golangci-lint run

## fmt: gofmt + goimports
fmt:
	gofmt -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "goimports not installed; skipping"

## tidy: go mod tidy
tidy:
	$(GO) mod tidy

## migrate-create: scaffold a timestamped Goose migration (NAME=add_thing)
migrate-create:
	@test -n "$(NAME)" || { echo "usage: make migrate-create NAME=add_thing"; exit 1; }
	@ts=$$(date -u +%Y%m%d%H%M%S); f=migrations/sql/$${ts}_$(NAME).sql; \
	 printf -- '-- +goose Up\n\n-- +goose Down\n' > $$f; \
	 echo "created $$f"

## migrate-up: apply migrations (needs RELAY_DATABASE_URL)
migrate-up:
	$(GO) run ./cmd/relayctl migrate up

## migrate-status: show migration state (needs RELAY_DATABASE_URL)
migrate-status:
	$(GO) run ./cmd/relayctl migrate status

## relayctl: build+run the admin CLI (ARGS="account list")
relayctl:
	$(GO) run ./cmd/relayctl $(ARGS)

## docker: build the container image
docker:
	docker build -f deploy/Dockerfile -t silo-push-relay:dev .

## loadtest: run the burst load scenario  [Phase 6]
loadtest:
	@echo "TODO(Phase 6): run k6/vegeta burst scenario"
