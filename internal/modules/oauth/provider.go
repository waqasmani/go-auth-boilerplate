package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

// Provider is the interface that every OAuth 2.0 provider adapter must satisfy.
// Adding a new provider (e.g. GitHub, Apple) requires only a new implementation
// of this interface; no changes to the service or handler are needed.
type Provider interface {
	// Name returns the canonical provider slug ("google", "facebook").
	Name() string
	// Config returns the oauth2.Config used to build the authorisation URL and
	// exchange the code for tokens.
	Config() *oauth2.Config
	// FetchUser exchanges the token for a normalised ProviderUserInfo.
	// Implementations must only return Verified=true when the provider
	// explicitly confirms email ownership (Google: email_verified; Facebook:
	// always unverified for public apps → returns Verified=false).
	FetchUser(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error)
	// VerifiesEmail reports whether this provider guarantees that the email
	// address returned by FetchUser has been confirmed to belong to the user.
	//
	// When true (e.g. Google), the service enforces Verified=true and uses
	// email for collision detection.
	//
	// When false (e.g. Facebook public apps), the service skips the email
	// verification gate and all email-based identity matching — only the
	// stable ProviderID is used for lookups. This prevents an attacker from
	// linking an unverified provider email to a victim's local account.
	VerifiesEmail() bool
}

// ── Google ─────────────────────────────────────────────────────────────────────

type googleProvider struct {
	cfg *oauth2.Config
}

func newGoogleProvider(clientID, clientSecret, redirectURL string, extraScopes []string) Provider {
	scopes := []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}
	scopes = append(scopes, extraScopes...)
	return &googleProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
	}
}

func (g *googleProvider) Name() string           { return "google" }
func (g *googleProvider) Config() *oauth2.Config { return g.cfg }

// VerifiesEmail returns true: Google's userinfo endpoint includes an
// email_verified claim and the service enforces it before any identity
// matching.
func (g *googleProvider) VerifiesEmail() bool { return true }

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (g *googleProvider) FetchUser(ctx context.Context, tok *oauth2.Token) (*ProviderUserInfo, error) {
	client := g.cfg.Client(ctx, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google: fetch user: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: userinfo returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("google: read userinfo: %w", err)
	}
	var u googleUserInfo
	if err = json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("google: parse userinfo: %w", err)
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("google: missing sub claim")
	}
	return &ProviderUserInfo{
		ProviderID: u.Sub,
		Email:      strings.ToLower(strings.TrimSpace(u.Email)),
		Name:       u.Name,
		Verified:   u.EmailVerified,
	}, nil
}

// ── Facebook ───────────────────────────────────────────────────────────────────

type facebookProvider struct {
	cfg *oauth2.Config
}

func newFacebookProvider(clientID, clientSecret, redirectURL string, extraScopes []string) Provider {
	scopes := []string{"email", "public_profile"}
	scopes = append(scopes, extraScopes...)
	return &facebookProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     facebook.Endpoint,
		},
	}
}

func (f *facebookProvider) Name() string           { return "facebook" }
func (f *facebookProvider) Config() *oauth2.Config { return f.cfg }

// VerifiesEmail returns false: Facebook's public Graph API does NOT guarantee
// that the email address has been confirmed by the user. The service therefore
// skips the email verification gate and all email-based identity matching for
// this provider, using only the stable Facebook user ID (ProviderID) for
// lookups.
//
// If your use-case requires verified emails, gate Facebook login on a
// server-side Business Verification check and introduce a new Provider
// implementation that returns true here only after passing that check.
func (f *facebookProvider) VerifiesEmail() bool { return false }

type facebookUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// FetchUser retrieves the Facebook Graph API profile.
//
// Security note: Facebook does NOT guarantee that the returned email is
// verified for apps using the public "email" permission. Verified is therefore
// always set to false for Facebook users. The service enforces this by checking
// p.VerifiesEmail() before using the email for any identity matching.
func (f *facebookProvider) FetchUser(ctx context.Context, tok *oauth2.Token) (*ProviderUserInfo, error) {
	client := f.cfg.Client(ctx, tok)
	resp, err := client.Get("https://graph.facebook.com/me?fields=id,name,email")
	if err != nil {
		return nil, fmt.Errorf("facebook: fetch user: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook: graph API returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("facebook: read user: %w", err)
	}
	var u facebookUserInfo
	if err = json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("facebook: parse user: %w", err)
	}
	if u.ID == "" {
		return nil, fmt.Errorf("facebook: missing id field")
	}
	return &ProviderUserInfo{
		ProviderID: u.ID,
		Email:      strings.ToLower(strings.TrimSpace(u.Email)),
		Name:       u.Name,
		// Facebook does not verify emails for public apps — the service uses
		// VerifiesEmail() to gate email-based operations rather than this field.
		Verified: false,
	}, nil
}
