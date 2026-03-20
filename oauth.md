# OAuth 2.0 Social Login

This document describes the `go-auth-boilerplate` OAuth 2.0 module.  It covers
environment variables, the allowed-redirect allowlist, running migrations,
regenerating sqlc queries, and the complete login/linking flows.

---

## Quick-start

```bash
# 1. Run the new migration
migrate -path sql/migrations -database "$DB_DSN" up

# 2. Regenerate sqlc queries (adds user_oauth_accounts queries)
sqlc generate

# 3. Set provider credentials (Google example)
export OAUTH_GOOGLE_ENABLED=true
export OAUTH_GOOGLE_CLIENT_ID=12345-abc.apps.googleusercontent.com
export OAUTH_GOOGLE_CLIENT_SECRET=GOCSPX-…
export OAUTH_GOOGLE_REDIRECT_URL=https://api.example.com/api/v1/oauth/google/callback
export OAUTH_GOOGLE_ALLOWED_REDIRECTS=https://app.example.com/dashboard,https://app.example.com/settings

# 4. Set the OAuth token encryption key
export OAUTH_TOKEN_KEYS='[{"id":"v1","key":"<openssl rand -base64 32>","active":true}]'
```

---

## Environment Variables

### Google Provider

| Variable | Required | Default | Description |
|---|---|---|---|
| `OAUTH_GOOGLE_ENABLED` | — | `false` | Set `true` to enable Google login. |
| `OAUTH_GOOGLE_CLIENT_ID` | when enabled | — | Google OAuth 2.0 client ID. |
| `OAUTH_GOOGLE_CLIENT_SECRET` | when enabled | — | Google OAuth 2.0 client secret. **Never log.** |
| `OAUTH_GOOGLE_REDIRECT_URL` | when enabled | — | Full callback URL registered in Google Console, e.g. `https://api.example.com/api/v1/oauth/google/callback`. |
| `OAUTH_GOOGLE_ALLOWED_REDIRECTS` | when enabled | — | Comma-separated list of frontend post-login destinations (see [Allowed Redirects](#allowed-redirects)). |
| `OAUTH_GOOGLE_SCOPES` | — | _(email + profile)_ | Additional scopes, comma-separated. |

### Facebook Provider

| Variable | Required | Default | Description |
|---|---|---|---|
| `OAUTH_FACEBOOK_ENABLED` | — | `false` | Set `true` to enable Facebook login. |
| `OAUTH_FACEBOOK_CLIENT_ID` | when enabled | — | Facebook App ID. |
| `OAUTH_FACEBOOK_CLIENT_SECRET` | when enabled | — | Facebook App Secret. **Never log.** |
| `OAUTH_FACEBOOK_REDIRECT_URL` | when enabled | — | Full callback URL registered in the Facebook developer console. |
| `OAUTH_FACEBOOK_ALLOWED_REDIRECTS` | when enabled | — | Comma-separated post-login frontend URLs. |
| `OAUTH_FACEBOOK_SCOPES` | — | _(email, public_profile)_ | Additional scopes. |

> **Facebook email verification note:** Facebook's public API does not guarantee
> that the returned email is verified. The module sets `Verified = false` for all
> Facebook users. As a result, Facebook email is used for display purposes only —
> it **cannot** be used to auto-link a Facebook identity to a local account that
> was registered with a password. Explicit user-initiated linking is required (see
> [Email Collision and Account Linking](#email-collision-and-account-linking)).

### OAuth Token Encryption

| Variable | Required | Default | Description |
|---|---|---|---|
| `OAUTH_TOKEN_KEYS` | **recommended** | — | JSON array of AES-256 keys (see format below). |
| `OAUTH_TOKEN_SECRET` | legacy fallback | — | Single 32 + byte key treated as `id = "v1"`. |

If neither is set, the module falls back to encrypting with the OTP secret and
logs a startup warning. **Set this before production use.**

#### Key format

```json
[
  {"id": "v1", "key": "<32+ byte string>", "active": true}
]
```

Generate a key:

```bash
openssl rand -base64 32
```

For key rotation, add the new key with `"active": true` and set the old key to
`"active": false` — do not remove the old key until all rows encrypted with it
have been re-encrypted. The key ID embedded in every ciphertext blob allows the
service to locate the correct decryption key automatically.

### Rate Limits (optional)

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_OAUTH_LOGIN` | `0.5` | Tokens/s for `GET /oauth/:provider/login`. |
| `RATE_LIMIT_OAUTH_CALLBACK` | `0.5` | Tokens/s for `GET /oauth/:provider/callback`. |

Both endpoints enforce a burst of 5 on top of the configured rate.

---

## Allowed Redirects

`OAUTH_<PROVIDER>_ALLOWED_REDIRECTS` is a **strict, server-side allowlist** of
frontend URLs that the OAuth flow is permitted to redirect the user to after a
successful login.

### Why this matters

Without an allowlist, an attacker can craft a login URL with an arbitrary
`redirect_url` parameter and use the OAuth callback to deliver a session token
to any page they control — an open-redirect attack that turns into a session
token theft.

### Rules

* Each entry must be a valid URL with a scheme and hostname.
* Matching is case-insensitive and ignores trailing slashes.
* An empty `redirect_url` query param is always accepted — the service falls
  back to the provider's `RedirectURL` in that case.
* Non-empty values not in the list are rejected with
  `OAUTH_REDIRECT_NOT_ALLOWED` (HTTP 400) **before** the authorisation URL is
  built — no redirect to the provider occurs.

### Example

```
OAUTH_GOOGLE_ALLOWED_REDIRECTS=https://app.example.com/dashboard,https://app.example.com/settings
```

The client calls:

```
GET /api/v1/oauth/google/login?redirect_url=https://app.example.com/dashboard
```

After a successful login the access/refresh tokens are returned in the JSON
body (and the refresh token is set as an HttpOnly cookie). The client is
responsible for routing the user to the `redirect_url` it supplied.

---

## HTTP Endpoints

All routes are under `/api/v1/oauth`.

### `GET /oauth/:provider/login`

Initiates the OAuth flow.

**Query parameters:**
* `redirect_url` _(optional)_ — post-login destination, must be in the
  `ALLOWED_REDIRECTS` allowlist.

**Response:** `307 Temporary Redirect` to the provider's authorisation URL.

**Side effects:**
* Sets an `_oauth_state` HttpOnly cookie (SameSite=Lax) containing the signed
  state parameter. This is part of the double-submit CSRF defence.

---

### `GET /oauth/:provider/callback`

Handles the provider's redirect after the user grants (or denies) authorisation.

**Query parameters (set by provider):**
* `code` — authorisation code.
* `state` — must match the `_oauth_state` cookie exactly (CSRF double-submit
  check) and must pass HMAC signature verification.
* `error` / `error_description` — present when the user denied access.

**Success (new user or returning user):** `200 OK` with:
```json
{
  "success": true,
  "data": {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "access_token_expires_at": "...",
    "refresh_token_expires_at": "..."
  }
}
```
The refresh token is also set as an HttpOnly `refresh_token` cookie.

**Email collision:** `409 Conflict` with:
```json
{
  "success": false,
  "error": {"code": "OAUTH_EMAIL_CONFLICT", "message": "..."},
  "data": {"linking_token": "<short-lived signed token>"}
}
```
The client must route the user to a "connect account" UI and then call
`POST /oauth/:provider/link` after the user confirms.

---

### `POST /oauth/:provider/link`

Links a provider identity to an already-authenticated user's account.

**Authentication:** `Authorization: Bearer <access_token>` (required).

**Request body:**
```json
{"linking_token": "<value from 409 collision response>"}
```

**Success:** `200 OK` with a new token pair (same shape as callback success).

**Error responses:**
* `403` — linking token expired or tampered.
* `409` — the provider account is already linked to a different user.

---

## Security Design Decisions

### PKCE (RFC 7636)

Every authorisation request includes a server-generated PKCE `code_verifier`
and S256 `code_challenge`. The verifier is stored inside the signed `state`
cookie; it is sent to the provider on code exchange. This prevents an
authorisation code interception attack where an attacker who intercepts the
callback URL can exchange the code themselves.

### State parameter (CSRF)

The `state` parameter is an HMAC-SHA256 signed envelope containing:

* A cryptographically random nonce (16 bytes).
* The provider slug.
* The post-login `redirect_url`.
* The PKCE verifier.
* An expiry timestamp (15 minutes).

The callback additionally performs a **double-submit cookie check**: the
`state` query parameter must exactly match the `_oauth_state` HttpOnly cookie
set during `/login`. A cross-site request cannot read or set this cookie, so
an attacker cannot complete a CSRF attack even if they somehow bypass the
signature check.

### Email collision — no auto-linking

When the provider returns an email address that already belongs to a local
account (created via password registration or a different OAuth provider), the
module **does not automatically link** the accounts. Auto-linking on email
alone is unsafe:

> An attacker who controls `alice@gmail.com` on Facebook could silently hijack
> the local account `alice@gmail.com` that was registered with a password.

Instead, a short-lived (15-minute), HMAC-signed `linking_token` is returned.
The user must authenticate with their existing credentials and explicitly
confirm the link at `POST /oauth/:provider/link`. The token encodes the
provider identity and encrypted provider tokens so the link endpoint can
complete the operation without a second provider round-trip.

### Token encryption at rest

Provider access and refresh tokens are encrypted with AES-256-GCM before
storage. Each ciphertext blob embeds the key ID so the correct decryption key
is located without ambiguity after a rotation. The `enc_key_id` column in
`user_oauth_accounts` mirrors the embedded ID for SQL-level key-rotation
visibility (`SELECT ... WHERE enc_key_id = 'v1'`).

---

## Migrations

```bash
# Apply migration 0006
migrate -path sql/migrations -database "$DB_DSN" up

# Rollback if needed
migrate -path sql/migrations -database "$DB_DSN" down 1
```

The migration creates `user_oauth_accounts` with:

* `(provider, provider_id)` unique index — one local user per provider account.
* `user_id` index — fast lookup of all providers linked to a user.
* `(user_id, provider)` index — fast "is this provider already linked?" check.
* `access_token_encrypted` / `refresh_token_encrypted` — `VARBINARY` columns for
  AES-GCM blobs. `NULL` means no token was stored or it was cleared.
* `enc_key_id` — the key ID at write time for rotation visibility.

---

## Regenerating sqlc Queries

After any change to `sql/queries/oauth.sql` or `sql/migrations/0006_*.sql`:

```bash
sqlc generate
```

This regenerates `internal/db/` from the SQL files. The `oauth` module
currently uses raw SQL in its repository while the generated code stabilises;
once `sqlc generate` is integrated into CI, switch `repository.go` to use
`*db.Queries` methods directly.

---

## Adding a New Provider

1. Implement the `oauth.Provider` interface in a new file, e.g.
   `internal/modules/oauth/provider_github.go`.
2. Add `"github"` to the `buildProviders` switch in `module.go`.
3. Add `OAUTH_GITHUB_*` env var loading to `config/config.go`
   (`loadOAuthProviders` iterates a static provider list; add `"github"` there).
4. Register the callback URL in the GitHub developer console.
5. Update this document.