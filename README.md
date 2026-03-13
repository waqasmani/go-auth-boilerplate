# Go Auth Boilerplate

Production-ready Go authentication boilerplate with JWT access + refresh tokens, token rotation, reuse detection, and a clean modules-first architecture.

## Stack

| Concern        | Library / Tool                             |
|----------------|---------------------------------------------|
| HTTP Router    | [gin-gonic/gin](https://github.com/gin-gonic/gin) |
| Database       | MariaDB / MySQL via `go-sql-driver/mysql`   |
| SQL Generation | [sqlc](https://sqlc.dev)                    |
| JWT            | `golang-jwt/jwt` v5                         |
| Password Hash  | bcrypt (`golang.org/x/crypto`)              |
| Logging        | [uber-go/zap](https://github.com/uber-go/zap) |
| Validation     | `go-playground/validator` v10               |
| Config         | `joho/godotenv` + environment variables     |

---

## Repository Structure

```
.
├── cmd/api/main.go               Entry point
├── internal/
│   ├── app/                      Application bootstrap
│   ├── config/                   Config loading
│   ├── db/                       sqlc-generated DB layer
│   ├── errors/                   Centralised AppError
│   ├── middleware/               RequestID, Auth, Logger, Recovery
│   ├── modules/
│   │   ├── auth/                 Register, Login, Refresh, Logout
│   │   └── users/                /users/me
│   ├── platform/
│   │   ├── auth/                 JWT + bcrypt helpers
│   │   ├── database/             sql.DB pool setup
│   │   └── logger/               Zap logger factory
│   ├── response/                 Standard API envelope
│   └── router/                   Gin router wiring
├── sql/
│   ├── migrations/               Schema migrations
│   └── queries/                  sqlc SQL queries
└── tests/integration/            End-to-end auth flow test
```

---

## Quick Start

### Prerequisites

- Go 1.22+
- Docker + Docker Compose
- [sqlc](https://docs.sqlc.dev/en/latest/overview/install.html) (for regenerating DB code)
- [golangci-lint](https://golangci-lint.run/usage/install/) (for linting)

### 1. Clone & configure

```bash
git clone https://github.com/yourusername/go-auth-boilerplate
cd go-auth-boilerplate
cp .env.example .env
# Edit .env — at minimum set a strong JWT_SECRET
```

### 2. Run with Docker Compose (recommended)

```bash
docker compose up --build
# API available at http://localhost:8080
```

Migrations are applied automatically via `docker-entrypoint-initdb.d`.

### 3. Run locally (requires MariaDB/MySQL)

```bash
# Start only the DB
make docker-db

# Apply migrations
make migrate

# Install dependencies
go mod download

# Run
make run
```

---

## API Endpoints

| Method | Path                     | Auth   | Description                        |
|--------|--------------------------|--------|------------------------------------|
| POST   | /api/v1/auth/register    | Public | Register & get token pair          |
| POST   | /api/v1/auth/login       | Public | Login & get token pair             |
| POST   | /api/v1/auth/refresh     | Public | Rotate refresh token               |
| POST   | /api/v1/auth/logout      | Public | Revoke refresh token family        |
| GET    | /api/v1/users/me         | JWT    | Get current user profile           |
| GET    | /health                  | Public | Health check                       |

### Example: Register

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"securepass123"}' | jq
```

### Example: Login

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"securepass123"}' | jq
```

### Example: Authenticated request

```bash
ACCESS_TOKEN="<access_token_from_login>"
curl -s http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

### Example: Refresh token

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<your_refresh_token>"}' | jq
```

---

## Token Design

```
Login / Register
      │
      ▼
┌─────────────┐       ┌───────────────────────────────────┐
│ Access Token│       │ Refresh Token (opaque UUID)         │
│ JWT (15m)   │       │ SHA-256 hash stored in DB          │
│ Claims:     │       │ • token_family (for reuse detection)│
│  user_id    │       │ • expires_at                       │
│  email      │       │ • used_at   (set on rotation)      │
│  roles      │       │ • revoked_at (set on logout/reuse) │
└─────────────┘       └───────────────────────────────────┘

Refresh flow:
  1. Look up token by SHA-256 hash
  2. If used_at is set → REUSE DETECTED → revoke entire family → 401
  3. If revoked_at is set → 401
  4. If expired → 401
  5. Mark token as used
  6. Issue new access + refresh token (same family)
  7. Store new hashed refresh token
```

---

## Makefile Commands

```bash
make run              # Run API locally
make build            # Compile binary to bin/
make test             # Unit tests (go test -race ./...)
make test-cover       # Tests with HTML coverage report
make test-integration # Integration tests (needs running DB)
make lint             # golangci-lint
make sqlc             # Regenerate DB code from SQL
make mock             # Regenerate mocks (needs mockgen)
make migrate          # Apply SQL migrations
make docker-up        # docker compose up --build
make docker-down      # docker compose down
make tidy             # go mod tidy
```

---

## Regenerating DB Code

After modifying `sql/queries/` or `sql/migrations/`:

```bash
make sqlc
```

This regenerates `internal/db/` from your SQL queries using [sqlc](https://sqlc.dev).

---

## Testing

### Unit tests

```bash
go test -v -race ./internal/...
```

### Integration tests

Requires a running MariaDB (use `make docker-db` to start one):

```bash
# Start DB
make docker-db

# Apply migrations
make migrate

# Run
DB_DSN="root:rootpassword@tcp(localhost:3306)/auth_db?parseTime=true&charset=utf8mb4" \
  go test -v -race -tags=integration ./tests/integration/...
```

Or via Make:

```bash
make docker-db && sleep 5 && make migrate && make test-integration
```

---

## Environment Variables

| Variable          | Default                       | Description                     |
|-------------------|-------------------------------|---------------------------------|
| `APP_ENV`         | `development`                 | `development` or `production`   |
| `APP_PORT`        | `8080`                        | HTTP listen port                |
| `DB_DSN`          | *(required)*                  | MariaDB DSN with `parseTime=true`|
| `JWT_SECRET`      | *(required)*                  | HMAC signing secret (≥32 chars) |
| `JWT_ISSUER`      | `go-auth-boilerplate`         | JWT `iss` claim                 |
| `JWT_AUDIENCE`    | `go-auth-boilerplate-users`   | JWT `aud` claim                 |
| `JWT_ACCESS_TTL`  | `15m`                         | Access token TTL                |
| `JWT_REFRESH_TTL` | `720h`                        | Refresh token TTL (30 days)     |

---

## Security Notes

- Passwords hashed with bcrypt (cost 10)
- Refresh tokens are opaque random UUIDs — only the SHA-256 hash is persisted
- Token rotation: each refresh token is single-use; reuse triggers family revocation
- JWT validated for `iss`, `aud`, `exp`, and `sub`
- All DB queries go through sqlc — no raw string interpolation

---

## License

MIT
