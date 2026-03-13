# ─── Variables ────────────────────────────────────────────────────────────────
APP_NAME   := go-auth-boilerplate
BINARY_DIR := bin
BINARY     := $(BINARY_DIR)/$(APP_NAME)
CMD        := ./cmd/api
DOCKER_COMPOSE := docker compose

# ─── Default target ───────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ─── Development ──────────────────────────────────────────────────────────────
.PHONY: run
run: ## Run the API server locally (requires .env)
	go run $(CMD)

.PHONY: build
build: ## Compile the binary
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BINARY) $(CMD)

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf $(BINARY_DIR)

# ─── Database ─────────────────────────────────────────────────────────────────
.PHONY: migrate
migrate: ## Apply SQL migrations (requires DB_DSN env var or .env)
	@echo "Applying migrations..."
	@export $$(cat .env | xargs) 2>/dev/null; \
	for f in sql/migrations/*.sql; do \
		echo "  -> $$f"; \
		mysql "$${DB_DSN}" < "$$f" 2>/dev/null || \
		mariadb "$${DB_DSN}" < "$$f"; \
	done
	@echo "Migrations applied."

.PHONY: migrate-docker
migrate-docker: ## Apply migrations against the Docker Compose DB
	$(DOCKER_COMPOSE) exec db sh -c \
	  'for f in /docker-entrypoint-initdb.d/*.sql; do mariadb -u root -prootpassword auth_db < "$$f"; done'

# ─── Code Generation ──────────────────────────────────────────────────────────
.PHONY: sqlc
sqlc: ## Regenerate sqlc code from SQL queries
	sqlc generate

.PHONY: mock
mock: ## Regenerate mocks (requires mockgen)
	go generate ./...

# ─── Quality ──────────────────────────────────────────────────────────────────
.PHONY: test
test: ## Run all unit tests
	go test -v -race -count=1 ./...

.PHONY: test-cover
test-cover: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: test-integration
test-integration: ## Run integration tests (requires running Docker Compose DB)
	go test -v -race -count=1 -tags=integration ./tests/integration/...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

# ─── Docker ───────────────────────────────────────────────────────────────────
.PHONY: docker-up
docker-up: ## Start all services with Docker Compose
	$(DOCKER_COMPOSE) up --build -d

.PHONY: docker-down
docker-down: ## Stop all Docker Compose services
	$(DOCKER_COMPOSE) down

.PHONY: docker-logs
docker-logs: ## Tail Docker Compose logs
	$(DOCKER_COMPOSE) logs -f

.PHONY: docker-db
docker-db: ## Start only the database container
	$(DOCKER_COMPOSE) up -d db

.PHONY: gen-project
gen-project: ## Run the project scaffold generator
	$(call log,gen-project,Running scaffold generator)
	go run scripts/gen/main.go

.PHONY: gen-md
gen-md: ## Generate project documentation markdown  (ARGS=... for extra flags)
	$(call log,gen-md,Generating project documentation)
	go run scripts/genMD/main.go $(ARGS)