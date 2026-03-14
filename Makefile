# =============================================================================
#  go-auth-boilerplate — Enterprise Makefile
#  Usage: make help
# =============================================================================

# ─── Metadata ─────────────────────────────────────────────────────────────────
APP_NAME    := go-auth-boilerplate
BINARY_DIR  := bin
BINARY      := $(BINARY_DIR)/$(APP_NAME)
CMD         := ./cmd/api
MODULE      := $(shell go list -m 2>/dev/null)
GIT_TAG     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME  := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS     := -w -s \
               -X main.Version=$(GIT_TAG) \
               -X main.Commit=$(GIT_COMMIT) \
               -X main.BuildTime=$(BUILD_TIME)

DOCKER_COMPOSE  := docker compose
MIGRATE_BIN     := $(shell which migrate 2>/dev/null || echo "$(GOPATH)/bin/migrate")
MIGRATIONS_DIR  := sql/migrations
MIGRATE_DB_URL  := $(shell grep -s '^DB_DSN' .env | cut -d= -f2- | sed 's|^|mysql://|')

# ─── Colour helpers ───────────────────────────────────────────────────────────
BOLD  := \033[1m
CYAN  := \033[36m
GREEN := \033[32m
YELLOW:= \033[33m
RED   := \033[31m
RESET := \033[0m

define log
	@printf "$(BOLD)$(CYAN)[$(1)]$(RESET) $(2)\n"
endef

define success
	@printf "$(GREEN)✔  $(1)$(RESET)\n"
endef

define warn
	@printf "$(YELLOW)⚠  $(1)$(RESET)\n"
endef

# ─── Default target ───────────────────────────────────────────────────────────
.DEFAULT_GOAL := help
.PHONY: help
help: ## Show this help message
	@printf "\n$(BOLD)$(APP_NAME)$(RESET) — available targets:\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-26s$(RESET) %s\n", $$1, $$2}'
	@echo ""


# =============================================================================
#  DEVELOPMENT
# =============================================================================

.PHONY: run
run: env-check ## Run the API server locally (requires .env)
	$(call log,run,Starting $(APP_NAME))
	go run $(CMD)

.PHONY: run-watch
run-watch: ## Hot-reload with air (go install github.com/air-verse/air@latest)
	$(call log,run-watch,Starting with hot-reload)
	@which air > /dev/null 2>&1 || (printf "$(RED)air not found. Install: go install github.com/air-verse/air@latest$(RESET)\n" && exit 1)
	air

.PHONY: build
build: ## Compile a production binary (CGO disabled, version-stamped)
	$(call log,build,Compiling $(BINARY))
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY) $(CMD)
	$(call success,Binary written to $(BINARY) [$(GIT_TAG) @ $(GIT_COMMIT)])

.PHONY: build-race
build-race: ## Build with race detector enabled (dev/staging only)
	$(call log,build-race,Compiling with race detector)
	@mkdir -p $(BINARY_DIR)
	go build -race -ldflags="$(LDFLAGS)" -o $(BINARY)-race $(CMD)

.PHONY: clean
clean: ## Remove build artefacts and coverage reports
	$(call log,clean,Removing artefacts)
	rm -rf $(BINARY_DIR) coverage.out coverage.html


# =============================================================================
#  ENVIRONMENT
# =============================================================================

.PHONY: env-check
env-check: ## Validate that all required .env variables are present
	$(call log,env-check,Validating environment)
	@missing=""; \
	for var in DB_DSN JWT_KEYS JWT_ISSUER JWT_AUDIENCE; do \
		val=$$(grep -s "^$${var}=" .env | cut -d= -f2-); \
		if [ -z "$$val" ]; then missing="$$missing $$var"; fi; \
	done; \
	if [ -n "$$missing" ]; then \
		printf "$(RED)Missing required vars:$(RESET)%s\n" "$$missing"; \
		exit 1; \
	fi
	$(call success,All required variables present)

.PHONY: env-example
env-example: ## Write a ready-to-use .env.example (safe — no real secrets)
	$(call log,env-example,Writing .env.example)
	@printf '%s\n' \
		'# --- Application ---' \
		'APP_ENV=development' \
		'APP_PORT=8080' \
		'' \
		'# --- Database ---' \
		'# Format: user:password@tcp(host:port)/dbname?parseTime=true' \
		'DB_DSN=appuser:secret@tcp(127.0.0.1:3306)/auth_db?parseTime=true&loc=UTC' \
		'' \
		'# --- JWT  (run: make jwt-gen-keyset) ---' \
		'JWT_KEYS=[{"id":"v1","secret":"REPLACE_WITH_64_BYTE_HEX_SECRET","active":true}]' \
		'JWT_ISSUER=go-auth-boilerplate' \
		'JWT_AUDIENCE=go-auth-boilerplate-users' \
		'JWT_ACCESS_TTL=15m' \
		'JWT_REFRESH_TTL=720h' \
		'' \
		'# --- Rate Limiting ---' \
		'RATE_LIMIT_RATE=5' \
		'RATE_LIMIT_BURST=10' \
		'RATE_LIMIT_TTL=10m' \
		'RATE_LIMIT_MAX_KEYS=10000' \
		'' \
		'# --- CORS ---' \
		'CORS_ALLOWED_ORIGINS=http://localhost:3000' \
		'CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Request-ID' \
		'CORS_ALLOW_CREDENTIALS=true' \
		'CORS_MAX_AGE=43200' \
		'' \
		'# --- Secure Headers ---' \
		'SEC_HSTS_ENABLED=false' \
		'SEC_HSTS_MAX_AGE=63072000' \
	> .env.example
	$(call success,.env.example written)


# =============================================================================
#  DATABASE MIGRATIONS  (golang-migrate CLI)
#  Install: https://github.com/golang-migrate/migrate/tree/master/cmd/migrate
#  go install -tags 'mysql' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
# =============================================================================

# Derive DB_URL from .env.  golang-migrate expects the mysql:// scheme.
# DB_DSN format:  user:pass@tcp(host:port)/dbname?parseTime=true
# migrate format: mysql://user:pass@tcp(host:port)/dbname?parseTime=true
_DB_URL := $(shell \
  dsn=$$(grep -s '^DB_DSN=' .env | cut -d= -f2- | tr -d '\r'); \
  [ -n "$$dsn" ] && printf 'mysql://%s' "$$dsn" || echo "")

.PHONY: _migrate-check
_migrate-check:
	@which migrate > /dev/null 2>&1 || \
		{ printf "$(RED)golang-migrate CLI not found.\n  Install: go install -tags 'mysql' github.com/golang-migrate/migrate/v4/cmd/migrate@latest$(RESET)\n"; exit 1; }
	@[ -n "$(_DB_URL)" ] || \
		{ printf "$(RED)DB_DSN not set in .env$(RESET)\n"; exit 1; }

.PHONY: migrate-up
migrate-up: _migrate-check ## Apply all pending migrations (alias: migrate)
	$(call log,migrate-up,Applying pending migrations)
	migrate -path $(MIGRATIONS_DIR) -database "$(_DB_URL)" up
	$(call success,All migrations applied)

.PHONY: migrate
migrate: migrate-up ## Alias for migrate-up

.PHONY: migrate-down
migrate-down: _migrate-check ## Roll back the last migration step
	$(call log,migrate-down,Rolling back one step)
	migrate -path $(MIGRATIONS_DIR) -database "$(_DB_URL)" down 1
	$(call success,One migration rolled back)

.PHONY: migrate-down-all
migrate-down-all: _migrate-check ## Roll back ALL migrations (destructive — use in CI only)
	$(call warn,Rolling back ALL migrations. Ctrl-C to abort.)
	@sleep 3
	migrate -path $(MIGRATIONS_DIR) -database "$(_DB_URL)" down -all
	$(call success,All migrations rolled back)

.PHONY: migrate-status
migrate-status: _migrate-check ## Show current migration version and dirty flag
	$(call log,migrate-status,Checking schema version)
	migrate -path $(MIGRATIONS_DIR) -database "$(_DB_URL)" version

.PHONY: migrate-force
migrate-force: _migrate-check ## Force schema version (usage: make migrate-force V=3)
	$(call log,migrate-force,Forcing version to $(V))
	@[ -n "$(V)" ] || { printf "$(RED)Usage: make migrate-force V=<version>$(RESET)\n"; exit 1; }
	migrate -path $(MIGRATIONS_DIR) -database "$(_DB_URL)" force $(V)
	$(call warn,Forced to version $(V). Review dirty state before resuming migrations.)

.PHONY: migrate-create
migrate-create: ## Create a new migration file pair (usage: make migrate-create N=add_sessions_table)
	$(call log,migrate-create,Scaffolding migration)
	@[ -n "$(N)" ] || { printf "$(RED)Usage: make migrate-create N=<migration_name>$(RESET)\n"; exit 1; }
	@last=$$(ls $(MIGRATIONS_DIR)/*.sql 2>/dev/null \
		| grep -oE '/[0-9]+_' | tr -d '/_ ' | sort -n | tail -1); \
	n=$$(printf '%d' "$${last:-0}"); \
	next=$$(printf '%04d' "$$((n + 1))"); \
	up="$(MIGRATIONS_DIR)/$${next}_$(N).up.sql"; \
	down="$(MIGRATIONS_DIR)/$${next}_$(N).down.sql"; \
	{ printf '%s\n%s\n' "-- $(N) (up)" "-- Write your UP migration here"; } > "$$up"; \
	{ printf '%s\n%s\n' "-- $(N) (down)" "-- Write your DOWN migration here"; } > "$$down"; \
	printf "  $(CYAN)created$(RESET) $$up\n"; \
	printf "  $(CYAN)created$(RESET) $$down\n"
	$(call success,Migration files created in $(MIGRATIONS_DIR))

.PHONY: migrate-docker
migrate-docker: ## Apply migrations against the Docker Compose DB container
	$(call log,migrate-docker,Applying migrations via Docker)
	$(DOCKER_COMPOSE) exec db sh -c \
	  'for f in /docker-entrypoint-initdb.d/*.up.sql; do \
	       echo "  -> $$f"; \
	       mariadb -u $${MYSQL_USER} -p$${MYSQL_PASSWORD} $${MYSQL_DATABASE} < "$$f"; \
	   done'
	$(call success,Docker migrations applied)


# =============================================================================
#  JWT KEY MANAGEMENT
# =============================================================================

# Minimum secret length in bytes (64 = 512-bit, ideal for HS256).
_SECRET_BYTES := 64

.PHONY: jwt-gen-secret
jwt-gen-secret: ## Generate a single cryptographically-secure JWT secret (hex)
	$(call log,jwt-gen-secret,Generating $(_SECRET_BYTES)-byte secret)
	@openssl rand -hex $(_SECRET_BYTES)

.PHONY: jwt-gen-keyset
jwt-gen-keyset: ## Generate a fresh JWT_KEYS JSON value ready to paste into .env
	$(call log,jwt-gen-keyset,Generating JWT_KEYS with id=v1)
	@secret=$$(openssl rand -hex $(_SECRET_BYTES)); \
	printf 'JWT_KEYS=[{"id":"v1","secret":"%s","active":true}]\n' "$$secret"
	$(call success,Paste the line above into your .env)

.PHONY: jwt-rotate
jwt-rotate: ## Add a NEW active key v<N> while keeping the old key for validation
	$(call log,jwt-rotate,Rotating JWT signing key)
	@existing=$$(grep -s '^JWT_KEYS=' .env | cut -d= -f2-); \
	[ -n "$$existing" ] || { printf "$(RED)JWT_KEYS not found in .env$(RESET)\n"; exit 1; }; \
	last_id=$$(printf '%s' "$$existing" | grep -o '"id":"[^"]*"' | tail -1 | cut -d'"' -f4); \
	n=$$(printf '%s' "$$last_id" | tr -d 'v'); \
	next=$$((n + 1)); \
	new_id="v$$next"; \
	new_secret=$$(openssl rand -hex $(_SECRET_BYTES)); \
	updated=$$(JWTR_KEYS="$$existing" JWTR_NEW_ID="$$new_id" JWTR_SECRET="$$new_secret" \
		python3 -c "import os,json; k=json.loads(os.environ['JWTR_KEYS']); [x.update({'active':False}) for x in k]; k.append({'id':os.environ['JWTR_NEW_ID'],'secret':os.environ['JWTR_SECRET'],'active':True}); print(json.dumps(k,separators=(',',':')))"); \
	[ -n "$$updated" ] || { printf "$(RED)jwt-rotate: python3 failed — check JWT_KEYS format in .env$(RESET)\n"; exit 1; }; \
	printf "\n$(YELLOW)New JWT_KEYS value (update your .env / secrets manager):$(RESET)\n"; \
	printf "JWT_KEYS=%s\n\n" "$$updated"; \
	printf "$(CYAN)Rotation checklist:$(RESET)\n"; \
	printf "  1. Update JWT_KEYS in .env / secrets manager with the value above.\n"; \
	printf "  2. Deploy — old tokens (signed with previous kid) remain valid.\n"; \
	printf "  3. After old AccessTTL+RefreshTTL has elapsed, remove the old key.\n"

.PHONY: jwt-verify
jwt-verify: ## Verify JWT_KEYS in .env is valid JSON with exactly one active key
	$(call log,jwt-verify,Validating JWT_KEYS)
	@val=$$(grep -s '^JWT_KEYS=' .env | cut -d= -f2-); \
	[ -n "$$val" ] || { printf "$(RED)JWT_KEYS not found in .env$(RESET)\n"; exit 1; }; \
	JWTV_KEYS="$$val" python3 -c "\
import os, json, sys; \
keys = json.loads(os.environ['JWTV_KEYS']); \
assert len(keys) > 0, 'key set is empty'; \
ids = [k['id'] for k in keys]; \
assert len(ids) == len(set(ids)), 'duplicate key ids: ' + str(ids); \
active = [k for k in keys if k.get('active')]; \
assert len(active) == 1, 'expected 1 active key, got ' + str(len(active)); \
[sys.stdout.write('  id={id}  active={active}  secret_len={slen} chars\n'.format(id=k['id'], active=k.get('active', False), slen=len(k['secret']))) for k in keys]; \
print('OK -- JWT_KEYS is valid'); \
" || { printf "$(RED)JWT_KEYS validation failed$(RESET)\n"; exit 1; }


# =============================================================================
#  CODE GENERATION
# =============================================================================

.PHONY: sqlc
sqlc: ## Regenerate sqlc query code from SQL definitions
	$(call log,sqlc,Running sqlc generate)
	@which sqlc > /dev/null 2>&1 || \
		(printf "$(RED)sqlc not found. Install: go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest$(RESET)\n" && exit 1)
	sqlc generate
	$(call success,sqlc generation complete)

.PHONY: mock
mock: ## Regenerate all mocks (requires mockgen)
	$(call log,mock,Running go generate)
	@which mockgen > /dev/null 2>&1 || \
		(printf "$(RED)mockgen not found. Install: go install go.uber.org/mock/mockgen@latest$(RESET)\n" && exit 1)
	go generate ./...
	$(call success,Mocks regenerated)

.PHONY: gen-project
gen-project: ## Run the project scaffold generator
	$(call log,gen-project,Running scaffold generator)
	go run scripts/gen/main.go

.PHONY: gen-md
gen-md: ## Generate project documentation markdown (ARGS=... for extra flags)
	$(call log,gen-md,Generating project documentation)
	go run scripts/genMD/main.go $(ARGS)

.PHONY: swagger
swagger:
	@which swag > /dev/null 2>&1 || go install github.com/swaggo/swag/cmd/swag@latest
	swag init -g cmd/api/swagger.go -o docs --parseDependency --parseInternal
# =============================================================================
#  QUALITY
# =============================================================================

.PHONY: test
test: ## Run all unit tests with race detector
	$(call log,test,Running unit tests)
	go test -v -race -count=1 ./...

.PHONY: test-short
test-short: ## Run tests skipping slow cases (-short flag)
	go test -short -race -count=1 ./...

.PHONY: test-cover
test-cover: ## Run tests and open HTML coverage report
	$(call log,test-cover,Running tests with coverage)
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	$(call success,Report written to coverage.html)
	@which open > /dev/null 2>&1 && open coverage.html || xdg-open coverage.html 2>/dev/null || true

.PHONY: test-cover-pct
test-cover-pct: ## Print total coverage percentage (CI-friendly, no browser)
	go test -race -coverprofile=coverage.out -covermode=atomic ./... 2>&1 | tail -1
	@go tool cover -func=coverage.out | grep ^total | awk '{print "Coverage: "$$3}'

.PHONY: test-integration
test-integration: ## Run integration tests (requires running Docker Compose DB)
	$(call log,test-integration,Running integration tests)
	go test -v -race -count=1 -tags=integration ./tests/integration/...

.PHONY: test-bench
test-bench: ## Run benchmarks (usage: make test-bench PKG=./internal/platform/auth/...)
	$(call log,test-bench,Running benchmarks)
	go test -bench=. -benchmem -run='^$$' $(or $(PKG), ./...)

.PHONY: lint
lint: ## Run golangci-lint (full suite)
	$(call log,lint,Running golangci-lint)
	@which golangci-lint > /dev/null 2>&1 || \
		(printf "$(RED)golangci-lint not found. Install: https://golangci-lint.run/usage/install/$(RESET)\n" && exit 1)
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run golangci-lint and auto-fix where possible
	$(call log,lint-fix,Running golangci-lint --fix)
	golangci-lint run --fix ./...

.PHONY: vet
vet: ## Run go vet
	$(call log,vet,Running go vet)
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	$(call log,tidy,Tidying modules)
	go mod tidy
	$(call success,go.mod and go.sum are tidy)

.PHONY: sec
sec: ## Run gosec security scanner
	$(call log,sec,Running gosec)
	@which gosec > /dev/null 2>&1 || \
		(printf "$(RED)gosec not found. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest$(RESET)\n" && exit 1)
	gosec -fmt=sarif -out=gosec.sarif ./... || gosec ./...

.PHONY: vuln
vuln: ## Run govulncheck for known CVEs in dependencies
	$(call log,vuln,Running govulncheck)
	@which govulncheck > /dev/null 2>&1 || \
		(printf "$(RED)govulncheck not found. Install: go install golang.org/x/vuln/cmd/govulncheck@latest$(RESET)\n" && exit 1)
	govulncheck ./...

.PHONY: ci
ci: tidy vet lint test test-cover-pct vuln ## Full CI gate: tidy → vet → lint → test → vuln


# =============================================================================
#  DOCKER
# =============================================================================

.PHONY: docker-up
docker-up: ## Build images and start all services
	$(call log,docker-up,Starting services)
	$(DOCKER_COMPOSE) up --build -d
	$(call success,Services running. Logs: make docker-logs)

.PHONY: docker-down
docker-down: ## Stop and remove containers (preserves volumes)
	$(call log,docker-down,Stopping services)
	$(DOCKER_COMPOSE) down

.PHONY: docker-down-v
docker-down-v: ## Stop and remove containers AND volumes (destructive)
	$(call warn,Removing containers and volumes)
	$(DOCKER_COMPOSE) down -v

.PHONY: docker-logs
docker-logs: ## Tail all Docker Compose logs
	$(DOCKER_COMPOSE) logs -f

.PHONY: docker-db
docker-db: ## Start only the database container
	$(call log,docker-db,Starting DB container)
	$(DOCKER_COMPOSE) up -d db

.PHONY: docker-shell
docker-shell: ## Open a shell in the running app container
	$(DOCKER_COMPOSE) exec app sh

.PHONY: docker-db-shell
docker-db-shell: ## Open a MySQL shell in the running db container
	$(DOCKER_COMPOSE) exec db mariadb \
	  -u$${MYSQL_USER:-root} -p$${MYSQL_PASSWORD:-rootpassword} $${MYSQL_DATABASE:-auth_db}


# =============================================================================
#  RELEASE
# =============================================================================

.PHONY: version
version: ## Print current version information
	@printf "Version:    $(GIT_TAG)\n"
	@printf "Commit:     $(GIT_COMMIT)\n"
	@printf "Build time: $(BUILD_TIME)\n"
	@printf "Module:     $(MODULE)\n"

.PHONY: release-tag
release-tag: ci ## Run CI gate then create and push an annotated git tag (usage: make release-tag V=v1.2.3)
	$(call log,release-tag,Tagging release)
	@[ -n "$(V)" ] || (printf "$(RED)Usage: make release-tag V=v1.2.3$(RESET)\n" && exit 1)
	@echo "Tagging $(V) …"
	git tag -a $(V) -m "Release $(V)"
	git push origin $(V)
	$(call success,Tag $(V) pushed)

.PHONY: release-build
release-build: ## Cross-compile release binaries for linux/amd64 and linux/arm64
	$(call log,release-build,Cross-compiling for linux/amd64 and linux/arm64)
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
	  go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-arm64 $(CMD)
	$(call success,Binaries in $(BINARY_DIR)/)

# ─── Tool installer (bootstrap a fresh dev machine) ───────────────────────────
.PHONY: install-tools
install-tools: ## Install all required dev tools (sqlc, mockgen, migrate, golangci-lint, gosec, govulncheck, air)
	$(call log,install-tools,Installing dev tools)
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install go.uber.org/mock/mockgen@latest
	go install -tags 'mysql' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/air-verse/air@latest
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
	  | sh -s -- -b $$(go env GOPATH)/bin latest
	$(call success,All tools installed)