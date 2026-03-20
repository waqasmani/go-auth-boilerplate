package auth

import (
	"time"
)

// SessionTokens is the token-pair shape shared between the auth and auth_email
// modules. Defined here — the one package both modules already import — so
// neither module ever needs to import the other.
type SessionTokens struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	TokenType             string    `json:"token_type"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}
