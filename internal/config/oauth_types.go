// ── OAuth additions for internal/config/config.go ────────────────────────────
//
// Add the following to the Config struct and Load() function.
// This file shows ONLY the new fields and loading code; merge into config.go.

// ── New Config struct fields ──────────────────────────────────────────────────
//
// OAuthProviders is keyed by provider slug ("google", "facebook").
// Each entry is loaded from env vars prefixed OAUTH_<PROVIDER>_*.
//
// OAuthTokenKeys is the AES-256 key set used to encrypt provider access/refresh
// tokens before storing them in user_oauth_accounts. Loaded from OAUTH_TOKEN_KEYS
// (JSON array) or legacy OAUTH_TOKEN_SECRET (single key).

// ── OAuthProviderConfig ───────────────────────────────────────────────────────

// OAuthProviderConfig holds per-provider OAuth 2.0 client credentials and policy.
//
// Env vars (replace <PROVIDER> with GOOGLE or FACEBOOK):
//
//	OAUTH_<PROVIDER>_ENABLED          "true" | "false"   (default: false)
//	OAUTH_<PROVIDER>_CLIENT_ID        required when enabled
//	OAUTH_<PROVIDER>_CLIENT_SECRET    required when enabled
//	OAUTH_<PROVIDER>_REDIRECT_URL     required when enabled; must be a full URL
//	OAUTH_<PROVIDER>_ALLOWED_REDIRECTS comma-separated list of allowed frontend
//	                                  post-login destinations (required when enabled)
//	OAUTH_<PROVIDER>_SCOPES           optional comma-separated extra scopes
//
// Example .env snippet:
//
//	OAUTH_GOOGLE_ENABLED=true
//	OAUTH_GOOGLE_CLIENT_ID=12345.apps.googleusercontent.com
//	OAUTH_GOOGLE_CLIENT_SECRET=GOCSPX-…
//	OAUTH_GOOGLE_REDIRECT_URL=https://api.example.com/api/v1/oauth/google/callback
//	OAUTH_GOOGLE_ALLOWED_REDIRECTS=https://app.example.com/dashboard,https://app.example.com/settings

package config

// OAuthProviderConfig holds per-provider OAuth 2.0 configuration.
type OAuthProviderConfig struct {
	// Enabled gates the provider at startup. An enabled provider with missing
	// credentials fails fast in config.Load().
	Enabled bool

	// ClientID is the application's OAuth 2.0 client identifier.
	ClientID string

	// ClientSecret is the application's OAuth 2.0 client secret.
	// Sourced exclusively from environment variables; never log this value.
	ClientSecret string

	// RedirectURL is the full URL the provider will send the authorisation code
	// to. Must be registered in the provider's developer console.
	// Example: "https://api.example.com/api/v1/oauth/google/callback"
	RedirectURL string

	// AllowedRedirects is the strict allowlist of frontend URLs the user may be
	// sent to after a successful login. redirect_url query params not in this
	// list are rejected with ErrRedirectNotAllowed. An empty list means no
	// custom redirect_url is accepted and the default RedirectURL is always used.
	AllowedRedirects []string

	// Scopes is the list of additional OAuth scopes to request beyond the
	// provider-specific defaults (email + profile). Append here; do not
	// remove defaults.
	Scopes []string
}

// OAuthTokenKeyConfig is an AES-256 key entry for encrypting provider tokens.
// Identical in structure to TOTPKeyConfig; kept separate for independent key
// rotation of OAuth vs TOTP keys.
type OAuthTokenKeyConfig struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Active bool   `json:"active"`
}
