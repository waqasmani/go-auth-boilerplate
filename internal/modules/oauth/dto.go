// Package oauth provides OAuth 2.0 social login for Google and Facebook.
package oauth

import "time"

// ── HTTP Request / Response types ─────────────────────────────────────────────

// LoginRequest is optionally accepted on GET /oauth/:provider/login.
// Clients may send redirect_url as a query parameter.
type LoginRequest struct {
	// RedirectURL is the frontend URL to send the user to after a successful
	// login. Must be present in the provider's AllowedRedirects allowlist.
	// Defaults to the provider's configured RedirectURL when absent.
	RedirectURL string `form:"redirect_url"`
}

// CallbackQuery holds the values the provider appends to the callback URL.
type CallbackQuery struct {
	Code  string `form:"code"  binding:"required"`
	State string `form:"state" binding:"required"`
	// Error fields returned by the provider on denial.
	Error            string `form:"error"`
	ErrorDescription string `form:"error_description"`
}

// LinkRequest is sent by an authenticated user to explicitly link a provider
// account that shares their email with an existing local account.
// A short-lived linking_token is issued during the callback's email-collision
// path; the authenticated user must present it here to prove inbox ownership.
type LinkRequest struct {
	LinkingToken string `json:"linking_token" validate:"required"`
}

// TokenResponse mirrors auth.TokenResponse; reused verbatim to keep the API
// surface consistent.
type TokenResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	TokenType             string    `json:"token_type"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

// CallbackResponse is returned by Service.HandleCallback.
type CallbackResponse struct {
	RequiresLinking bool   `json:"requires_linking,omitempty"`
	LinkingToken    string `json:"linking_token,omitempty"`
	// Tokens is set for web/legacy paths. Nil for mobile (one-time code path).
	Tokens *TokenResponse `json:"tokens,omitempty"`

	// Internal routing — never serialised.
	UserID      string `json:"-"` // used by handler to generate one-time code
	RedirectURL string `json:"-"` // from verified OAuth state
	// OneTimeCode is the pre-issued plaintext code for the mobile path.
	// Non-empty only when RedirectURL has a custom scheme. The handler must
	// use this value directly; it must NOT call IssueOneTimeCode separately.
	OneTimeCode string `json:"-"`
}

// ExchangeRequest is the body for POST /oauth/exchange.
// Mobile apps call this after intercepting the deep-link with ?code=<64hex>.
type ExchangeRequest struct {
	// Code is the 64-hex-char one-time code from the deep-link redirect.
	// The backend stores only its SHA-256 hash; the plaintext is never persisted.
	Code string `json:"code" validate:"required,len=64"`
}

// ProviderUserInfo is the normalised user profile returned by any provider.
// Fields are normalised from provider-specific JSON shapes by the adapter.
type ProviderUserInfo struct {
	// ProviderID is the provider's opaque, stable user identifier
	// (Google: "sub" claim; Facebook: "id" field). This is the authoritative
	// key — never use Email for identity matching.
	ProviderID string
	Email      string
	Name       string
	// Verified reports whether the provider has verified this email address.
	// When false the email MUST NOT be trusted for any identity matching.
	Verified bool
}

// ── Repository / domain types ─────────────────────────────────────────────────

// OAuthAccount is the domain model for a row in user_oauth_accounts.
// Encrypted token fields are []byte (the raw AES-GCM blob including key-id
// prefix); the service layer decrypts them when needed and never exposes
// plaintext tokens in structs that might be logged.
type OAuthAccount struct {
	ID            string
	UserID        string
	Provider      string
	ProviderID    string
	ProviderEmail string
	ProviderName  string
	// AccessTokenEncrypted is the AES-GCM ciphertext with embedded key-id prefix.
	// nil means no token was stored or it was intentionally cleared.
	AccessTokenEncrypted []byte
	// RefreshTokenEncrypted is the AES-GCM ciphertext of the refresh token.
	RefreshTokenEncrypted []byte
	TokenExpiresAt        *time.Time
	// EncKeyID is the active-key ID at write time; stored for operational
	// visibility without requiring blob decryption.
	EncKeyID  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateOAuthAccountParams carries all columns needed for an INSERT.
type CreateOAuthAccountParams struct {
	ID                    string
	UserID                string
	Provider              string
	ProviderID            string
	ProviderEmail         string
	ProviderName          string
	AccessTokenEncrypted  []byte
	RefreshTokenEncrypted []byte
	TokenExpiresAt        *time.Time
	EncKeyID              string
}

// UpdateOAuthTokensParams carries the fields updated on every successful
// token refresh / re-authorisation.
type UpdateOAuthTokensParams struct {
	Provider              string
	ProviderID            string
	AccessTokenEncrypted  []byte
	RefreshTokenEncrypted []byte
	TokenExpiresAt        *time.Time
	EncKeyID              string
}

// LinkingClaims is the signed payload inside a linking_token JWT.
// It is a short-lived (15 min) opaque value that proves the bearer has just
// completed a valid OAuth exchange with the provider and that the provider's
// email collided with an existing local account.
type LinkingClaims struct {
	// Provider is "google" or "facebook".
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	// EncryptedAccessToken and EncryptedRefreshToken are the base64-encoded
	// AES-GCM blobs to store once linking is confirmed. Not exposed to client.
	ExpiresAt time.Time `json:"exp"`
}
