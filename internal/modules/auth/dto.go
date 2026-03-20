// Package auth provides data transfer objects for user authentication and registration operations.
package auth

import "time"

type RegisterRequest struct {
	Name     string `json:"name"     validate:"required,min=2,max=100"`
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=12,max=128"`
}

type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type TokenResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	TokenType             string    `json:"token_type"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

// MFAChallengeResponse is returned by Login when two_fa_enabled is true.
// The client must POST { code, mfa_token } to /auth/otp/verify to complete
// the login and receive a full token pair.
type MFAChallengeResponse struct {
	RequiresMFA bool      `json:"requires_mfa"`
	MFAToken    string    `json:"mfa_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// LoginResult is the discriminated union returned by Service.Login.
// Exactly one of Token or Challenge is non-nil.
type LoginResult struct {
	Token     *TokenResponse        // set when two_fa_enabled == false
	Challenge *MFAChallengeResponse // set when two_fa_enabled == true
}

// UserWithRoles extends the base user with role names and the two security
// flags that Login must read on every authentication attempt.
type UserWithRoles struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	Roles         []string  `json:"roles"`
	PasswordHash  string    `json:"password_hash"`
	TwoFAEnabled  bool      `json:"two_fa_enabled"`
	EmailVerified bool      `json:"email_verified"` // derived from email_verified_at IS NOT NULL
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
