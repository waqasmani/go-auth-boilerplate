# AI-Friendly Development Guide

This guide is designed for AI agents assisting in the development, maintenance, and extension of the `go-auth-boilerplate` project. It outlines architectural patterns, conventions, and security constraints essential for maintaining code integrity.

## 1. Project Overview
- **Name:** `go-auth-boilerplate`
- **Module Path:** `github.com/waqasmani/go-auth-boilerplate`
- **Language:** Go (Golang)
- **Framework:** Gin (`github.com/gin-gonic/gin`)
- **Database:** MySQL (`github.com/go-sql-driver/mysql`)
- **ORM/Query Layer:** `sqlc` (Generated queries in `internal/db`)
- **Logging:** `zap` (`go.uber.org/zap`)
- **Configuration:** Environment variables (loaded via `internal/config`)

## 2. Architecture & Directory Structure
The project follows a **Modular Monolith** architecture with clear separation of concerns.

```text
cmd/api/              # Binary entry points (main.go, swagger.go)
internal/
  app/                # Application wiring, lifecycle, startup logic
  config/             # Configuration loading and validation
  errors/             # Standardized application error types (AppError)
  middleware/         # Gin middleware (Auth, CORS, RateLimit, etc.)
  modules/            # Feature modules (auth, auth_email, users)
    <module>/
      handler.go      # HTTP layer (binds request, calls service)
      service.go      # Business logic layer
      repository.go   # Data access layer (uses sqlc queries)
      routes.go       # Route registration
      module.go       # Dependency wiring for the module
      dto.go          # Request/Response structs
  platform/           # Shared infrastructure (auth, db, email, logger, audit)
  response/           # Standardized JSON response helpers
  router/             # Gin engine setup and middleware stack
sql/migrations/       # SQL migration files (embedded via go:embed)
```

## 3. Core Conventions

### 3.1. Logging
- **Never** use `fmt.Println` or standard `log`.
- **Always** use `zap.Logger`.
- **Context Propagation:** Retrieve the request-scoped logger from context to ensure `request_id` is included automatically.
  ```go
  log := logger.FromContext(ctx)
  // Or in handlers where context is available via request:
  log := logger.FromContext(c.Request.Context())
  ```
- **Audit Logs:** Use `internal/platform/audit` for security-critical events (login, password reset, etc.). Do not log sensitive data (passwords, tokens) in audit logs.

### 3.2. Error Handling
- **Standard Errors:** Use `internal/errors` for all API errors.
  ```go
  apperrors.ErrUnauthorized
  apperrors.ErrInternalServer
  ```
- **Custom Errors:** Create new errors using `apperrors.New(code, message, status, err)`.
- **Wrapping:** Use `apperrors.Wrap(existingAppError, underlyingErr)` to preserve context.
- **Response:** Use `internal/response.Error(c, err)` in handlers to send standardized JSON error responses.

### 3.3. Configuration
- **Location:** `internal/config/config.go`.
- **Environment Variables:** All config must be loadable via environment variables.
- **Validation:** Config loading (`config.Load()`) must validate required fields and types at startup (fail fast).
- **Secrets:** Never hardcode secrets. Use `JWT_KEYS`, `DB_DSN`, `OTP_HMAC_SECRET`, etc.

### 3.4. HTTP Handlers
- **Validation:** Use `response.BindAndValidate(c, &req, validator)` for JSON binding and validation.
- **Responses:** Use `response.OK(c, data)`, `response.Created(c, data)`, or `response.NoContent(c)`.
- **Middleware:** Apply middleware (Auth, RateLimit) in `routes.go`, not inside handlers.

## 4. Module Pattern (Adding Features)
When adding a new feature (e.g., `profiles`), follow the existing module structure in `internal/modules/`.

1.  **Create Directory:** `internal/modules/profiles/`
2.  **Files:**
    -   `dto.go`: Request/Response structs.
    -   `repository.go`: DB interactions (interface + impl using `db.Queries`).
    -   `service.go`: Business logic.
    -   `handler.go`: HTTP handling.
    -   `routes.go`: Gin route registration.
    -   `module.go`: Wiring (NewModule function).
3.  **Wiring:** Update `internal/app/app.go` to initialize the new module and `internal/router/router.go` to register routes.
4.  **Database:** Add SQL queries to `sql/queries.sql` (if using sqlc directly) or relevant migration files in `sql/migrations/`.

## 5. Security Guidelines (Critical)
**AI Agents must strictly adhere to these security patterns:**

-   **Password Hashing:** Use `platform/auth.HashPassword` and `VerifyPassword`. These implement **SHA-256 pre-hashing** before bcrypt to handle long passwords correctly. **Do not** call `bcrypt` directly on raw passwords.
-   **JWT:**
    -   Use `platform/auth.JWT` helper.
    -   Support key rotation (check `JWTKeys` config).
    -   Validate algorithm (must be HMAC) before checking keys.
-   **Tokens:**
    -   **Access Tokens:** Short-lived (default 5m).
    -   **Refresh Tokens:** Long-lived, stored hashed in DB, support rotation and revocation.
    -   **OTP/Email Tokens:** Hashed before storage (use `platform/auth.HMACToken` for low-entropy secrets like 6-digit codes).
-   **CSRF:**
    -   Use `middleware.CookieCSRF` for endpoints consuming `refresh_token` cookies (`/auth/refresh`, `/auth/logout`).
    -   Validate `Origin`/`Referer` headers against `FrontEndDomain`.
-   **Rate Limiting:**
    -   Apply per-IP limits globally (`middleware.RateLimit`).
    -   Apply per-account limits for sensitive actions (login, password reset) using `middleware.Limiter` inside handlers.
-   **Headers:** Ensure `SecureHeaders` middleware is active (HSTS, X-Frame-Options, CSP, etc.).

## 6. Database & Migrations
- **Migrations:** Use `golang-migrate`. Files live in `sql/migrations/`.
    -   Naming: `VERSION_description.up.sql` / `VERSION_description.down.sql`.
    -   Embedded via `sql/migrations/embed.go`.
- **Queries:** Managed via `sqlc` (implied by `internal/db/queries.go` usage).
    -   Repositories should depend on `*db.Queries`, not raw `*sql.DB` (except for transactions).
    -   Use `repository.WithTx` for atomic operations.
- **Connections:** Configured in `internal/platform/database`. Do not create new `sql.DB` instances; pass the existing one from `app.go`.

## 7. Testing & Mocks
- **Mocking:** Use `mockgen` for interfaces (Service, Repository).
    -   Directive: `//go:generate mockgen -source=interface.go -destination=mocks/interface_mock.go -package=mocks`
- **Unit Tests:** Test Services and Handlers independently.
- **Integration Tests:** Use `internal/app` to spin up the full server with a test database.
- **Config:** Use test-specific environment variables or override `config.Load` behavior in tests.

## 8. AI Agent Specific Instructions
1.  **Context Awareness:** Always check `internal/app/app.go` to understand how dependencies are wired before suggesting changes to initialization.
2.  **Import Paths:** Always use the full module path `github.com/waqasmani/go-auth-boilerplate/...`.
3.  **Code Generation:** If suggesting changes to `internal/db`, remind the user to regenerate sqlc queries.
4.  **Security First:** If a suggestion weakens security (e.g., removing CSRF, logging tokens, disabling HTTPS headers), **reject it** and explain the risk based on `internal/middleware` and `internal/platform/auth` implementations.
5.  **Error Consistency:** When creating new errors, ensure they map to correct HTTP status codes in `internal/errors/errors.go`.
6.  **Concurrency:** Respect the shutdown logic in `internal/app/app.go`. Long-running goroutines must listen to `ctx.Done()`.

## 9. Common Tasks Cheat Sheet

| Task | Location | Notes |
| :--- | :--- | :--- |
| **Add Config Var** | `internal/config/config.go` | Add field, env var parsing, and validation. |
| **Add Route** | `internal/modules/<name>/routes.go` | Register on `gin.RouterGroup`. |
| **Add DB Column** | `sql/migrations/*.sql` | Create migration, then update `sqlc` queries. |
| **Log Event** | `internal/platform/audit/audit.go` | Use `auditLog.Log(ctx, eventType, userID, fields...)`. |
| **Send Email** | `internal/platform/email/mailer.go` | Use `mailer.Send` or `mailer.Enqueue`. |
| **Auth Check** | `internal/middleware/auth.go` | Use `middleware.Auth(jwt, log)` middleware. |
| **Get User ID** | `internal/middleware/auth.go` | `claims, ok := middleware.GetClaims(c)` |

---
*Generated for AI Agents to ensure consistency with `go-auth-boilerplate` architecture.*