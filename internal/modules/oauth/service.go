package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ── Audit event types ──────────────────────────────────────────────────────────

const (
	eventLoginAttempt  audit.EventType = "oauth.login_attempt"
	eventLoginSuccess  audit.EventType = "oauth.login_success"
	eventLoginFailed   audit.EventType = "oauth.login_failed"
	eventAccountLinked audit.EventType = "oauth.account_linked"
	eventLinkConflict  audit.EventType = "oauth.account_link_attempt_conflict"
)

const (
	// linkingTokenTTL is the window a user has to complete explicit linking
	// after a collision is detected. 15 min mirrors the OAuth state TTL.
	linkingTokenTTL = 15 * time.Minute

	// oneTimeCodeTTL is the lifetime of a single-use mobile exchange code.
	// Short window limits exposure; rate-limiting on /exchange reinforces this.
	oneTimeCodeTTL = 90 * time.Second
)

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// TokenIssuer is the subset of auth.Service needed to issue a session pair.
type TokenIssuer interface {
	IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error)
}

// Service defines the OAuth business-logic contract.
type Service interface {
	BuildAuthURL(ctx context.Context, provider, redirectURL string) (authURL, signedState string, err error)
	HandleCallback(ctx context.Context, provider, code, rawState string) (*CallbackResponse, error)
	LinkAccount(ctx context.Context, authenticatedUserID, linkingToken string) (*CallbackResponse, error)
	IssueOneTimeCode(ctx context.Context, userID string) (plaintext string, err error)
	ExchangeOneTimeCode(ctx context.Context, plaintext string) (*CallbackResponse, error)
}

type service struct {
	db            *sql.DB
	repo          Repository
	providers     map[string]Provider
	tokenIssuer   TokenIssuer
	tokenKeySet   *platformauth.SymmetricKeySet
	stateSecret   string
	log           *zap.Logger
	auditLog      *audit.Logger
	linkingSecret string
}

// NewService constructs the OAuth service.
func NewService(
	db *sql.DB,
	repo Repository,
	providers map[string]Provider,
	tokenIssuer TokenIssuer,
	tokenKeySet *platformauth.SymmetricKeySet,
	stateSecret string,
	log *zap.Logger,
	auditLog *audit.Logger,
) Service {
	return &service{
		db:            db,
		repo:          repo,
		providers:     providers,
		tokenIssuer:   tokenIssuer,
		tokenKeySet:   tokenKeySet,
		stateSecret:   stateSecret,
		log:           log,
		auditLog:      auditLog,
		linkingSecret: stateSecret + ":linking",
	}
}

// ── BuildAuthURL ───────────────────────────────────────────────────────────────

func (s *service) BuildAuthURL(ctx context.Context, provider, redirectURL string) (string, string, error) {
	p, err := s.getProvider(provider)
	if err != nil {
		return "", "", err
	}

	verifier, challenge, err := platformauth.GeneratePKCEPair()
	if err != nil {
		return "", "", apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	state := platformauth.OAuthState{
		Provider:     provider,
		RedirectURL:  redirectURL,
		PKCEVerifier: verifier,
	}
	signedState, err := platformauth.SignOAuthState(state, s.stateSecret)
	if err != nil {
		return "", "", apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	cfg := p.Config()
	authURL := cfg.AuthCodeURL(
		signedState,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	s.log.Debug("oauth: built auth URL", zap.String("provider", provider))
	return authURL, signedState, nil
}

// ── HandleCallback ─────────────────────────────────────────────────────────────
//
// Gate order (must not be changed):
//
//  1. Validate state signature and expiry  — reject CSRF first, cheaply.
//  2. Exchange code for tokens             — only after state is valid.
//  3. Fetch user info                      — only after tokens are valid.
//  4. Verify email is confirmed            — for providers that guarantee it.
//  5. Look up existing OAuth account       — fast path (returning user).
//  6. Email-collision detection            — only for email-verifying providers.
//  7. Create new user + OAuth account      — atomically in a transaction.
//
// Step 7 — email verification flag:
//
//	emailVerified = p.VerifiesEmail() && userInfo.Verified
//
// This flag is passed to CreateOAuthOnlyUser, which selects between two SQL
// queries:
//
//   - true  → CreateOAuthUser:           stores the real email,
//     sets email_verified_at = NOW().
//   - false → CreateOAuthUserUnverified: stores a UUID placeholder
//     ("<newUserID>@oauth.invalid") as the email,
//     leaves email_verified_at = NULL.
//
// Without this distinction a Facebook user whose unverified email is not
// already in the database receives a pre-verified local account backed by an
// address they may not own.
func (s *service) HandleCallback(ctx context.Context, provider, code, rawState string) (*CallbackResponse, error) {
	s.auditLog.Log(ctx, eventLoginAttempt, "", zap.String("provider", provider))

	// ── 1. Validate state ──────────────────────────────────────────────────────
	oauthState, err := platformauth.ParseAndVerifyOAuthState(rawState, s.stateSecret)
	if err != nil {
		s.log.Debug("oauth: state validation failed", zap.String("provider", provider), zap.Error(err))
		return nil, ErrInvalidState
	}
	if !strings.EqualFold(oauthState.Provider, provider) {
		s.log.Warn("oauth: provider mismatch in state",
			zap.String("state_provider", oauthState.Provider),
			zap.String("url_provider", provider),
		)
		return nil, ErrInvalidState
	}

	p, err := s.getProvider(provider)
	if err != nil {
		return nil, err
	}

	redirectURL := oauthState.RedirectURL
	isMobile := isCustomScheme(redirectURL)

	// ── 2. Exchange code for tokens ────────────────────────────────────────────
	tok, err := p.Config().Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", oauthState.PKCEVerifier),
	)
	if err != nil {
		s.log.Warn("oauth: code exchange failed", zap.String("provider", provider))
		s.auditLog.Log(ctx, eventLoginFailed, "",
			zap.String("provider", provider),
			zap.String("reason", "code_exchange_failed"),
		)
		return nil, apperrors.New("OAUTH_CODE_EXCHANGE_FAILED",
			"could not exchange OAuth code — please try again", 400, err)
	}

	// ── 3. Fetch user info ─────────────────────────────────────────────────────
	userInfo, err := p.FetchUser(ctx, tok)
	if err != nil {
		s.auditLog.Log(ctx, eventLoginFailed, "",
			zap.String("provider", provider),
			zap.String("reason", "fetch_user_failed"),
		)
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	// ── 4. Email verification gate ─────────────────────────────────────────────
	// Only enforced when the provider guarantees email ownership (e.g. Google).
	// Facebook returns Verified=false for public apps and VerifiesEmail()=false,
	// so we skip both the gate and email-based identity matching for Facebook.
	if p.VerifiesEmail() && !userInfo.Verified {
		s.log.Info("oauth: provider returned unverified email",
			zap.String("provider", provider),
			zap.String("provider_id", userInfo.ProviderID),
		)
		s.auditLog.Log(ctx, eventLoginFailed, "",
			zap.String("provider", provider),
			zap.String("reason", "unverified_email"),
		)
		return nil, ErrUnverifiedEmail
	}

	encAccess, encRefresh, err := s.encryptTokens(tok)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	var tokenExpiry *time.Time
	if !tok.Expiry.IsZero() {
		t := tok.Expiry.UTC()
		tokenExpiry = &t
	}

	// ── 5. Returning user (fast path) ──────────────────────────────────────────
	existing, err := s.repo.GetOAuthAccountByProviderID(ctx, provider, userInfo.ProviderID)
	if err != nil && !isNotFound(err) {
		return nil, err
	}

	if existing != nil {
		if updateErr := s.repo.UpdateOAuthTokens(ctx, UpdateOAuthTokensParams{
			Provider:              provider,
			ProviderID:            userInfo.ProviderID,
			AccessTokenEncrypted:  encAccess,
			RefreshTokenEncrypted: encRefresh,
			TokenExpiresAt:        tokenExpiry,
			EncKeyID:              s.tokenKeySet.ActiveKeyID(),
		}); updateErr != nil {
			s.log.Warn("oauth: failed to update tokens — continuing with stale tokens",
				zap.String("provider", provider), zap.Error(updateErr))
		}

		if isMobile {
			s.auditLog.Log(ctx, eventLoginSuccess, existing.UserID,
				zap.String("provider", provider),
				zap.String("platform", "mobile"),
			)
			return &CallbackResponse{UserID: existing.UserID, RedirectURL: redirectURL}, nil
		}

		session, err := s.tokenIssuer.IssueTokensForUser(ctx, existing.UserID)
		if err != nil {
			s.auditLog.Log(ctx, eventLoginFailed, existing.UserID,
				zap.String("reason", "issue_tokens_failed"),
			)
			return nil, err
		}
		s.auditLog.Log(ctx, eventLoginSuccess, existing.UserID,
			zap.String("provider", provider),
		)
		return &CallbackResponse{
			Tokens:      sessionToTokenResponse(session),
			UserID:      existing.UserID,
			RedirectURL: redirectURL,
		}, nil
	}

	// ── 6. Email-collision detection ───────────────────────────────────────────
	// Only attempted for providers that verify email (VerifiesEmail()=true).
	// For Facebook (VerifiesEmail()=false) the email is not verified, so we
	// must not use it for identity matching — an attacker could register a
	// Facebook account with a victim's email to trigger a collision path and
	// probe account existence.
	if p.VerifiesEmail() && userInfo.Email != "" {
		existingUserID, emailExists, err := s.repo.GetUserByEmail(ctx, userInfo.Email)
		if err != nil {
			return nil, err
		}
		if emailExists {
			s.log.Info("oauth: email collision — explicit linking required",
				zap.String("provider", provider),
			)
			s.auditLog.Log(ctx, eventLinkConflict, existingUserID,
				zap.String("provider", provider),
				zap.String("reason", "email_collision"),
			)
			linkingToken, ltErr := s.issueLinkingToken(ctx, userInfo, provider,
				encAccess, encRefresh, tokenExpiry)
			if ltErr != nil {
				return nil, apperrors.Wrap(apperrors.ErrInternalServer, ltErr)
			}
			return &CallbackResponse{
				RequiresLinking: true,
				LinkingToken:    linkingToken,
				RedirectURL:     redirectURL,
			}, nil
		}
	}

	// ── 7. New user — create account + OAuth identity atomically ──────────────
	//
	// emailVerified is the single boolean that drives which SQL query is used
	// inside CreateOAuthOnlyUser:
	//
	//   true  → CreateOAuthUser (stores real email, stamps email_verified_at).
	//   false → CreateOAuthUserUnverified (stores UUID placeholder as email,
	//           leaves email_verified_at NULL).
	//
	// For Facebook (VerifiesEmail()=false), userInfo.Verified is always false,
	// so emailVerified is always false regardless of what the API returned.
	// For Google (VerifiesEmail()=true), we additionally check userInfo.Verified
	// — gate 4 above already rejected profiles where this is false, but we
	// evaluate it here defensively to make the invariant explicit.
	emailVerified := p.VerifiesEmail() && userInfo.Verified

	newUserID := uuid.NewString()
	err = s.repo.WithTx(ctx, func(tx Repository) error {
		if err := tx.CreateOAuthOnlyUser(ctx, newUserID, userInfo.Email, userInfo.Name, emailVerified); err != nil {
			return err
		}
		return tx.CreateOAuthAccount(ctx, CreateOAuthAccountParams{
			ID:                    uuid.NewString(),
			UserID:                newUserID,
			Provider:              provider,
			ProviderID:            userInfo.ProviderID,
			ProviderEmail:         userInfo.Email, // display only; not used for identity
			ProviderName:          userInfo.Name,
			AccessTokenEncrypted:  encAccess,
			RefreshTokenEncrypted: encRefresh,
			TokenExpiresAt:        tokenExpiry,
			EncKeyID:              s.tokenKeySet.ActiveKeyID(),
		})
	})
	if err != nil {
		if isEmailConflict(err) {
			linkingToken, ltErr := s.issueLinkingToken(ctx, userInfo, provider,
				encAccess, encRefresh, tokenExpiry)
			if ltErr != nil {
				s.log.Error("oauth: failed to issue linking token on email-conflict race",
					zap.String("provider", provider), zap.Error(ltErr))
				return nil, apperrors.Wrap(apperrors.ErrInternalServer, ltErr)
			}
			return &CallbackResponse{
				RequiresLinking: true,
				LinkingToken:    linkingToken,
				RedirectURL:     redirectURL,
			}, nil
		}
		return nil, err
	}

	if isMobile {
		s.auditLog.Log(ctx, eventLoginSuccess, newUserID,
			zap.String("provider", provider),
			zap.String("flow", "new_user_mobile"),
		)
		return &CallbackResponse{UserID: newUserID, RedirectURL: redirectURL}, nil
	}

	// For email-verified users (e.g. Google), IssueTokensForUser will find
	// email_verified_at = NOW() and grant a session immediately.
	//
	// For unverified users (e.g. Facebook), IssueTokensForUser will find
	// email_verified_at = NULL and return ErrEmailNotVerified. The handler
	// surfaces this as HTTP 403 with code EMAIL_NOT_VERIFIED, prompting the
	// client to guide the user to their inbox.
	session, err := s.tokenIssuer.IssueTokensForUser(ctx, newUserID)
	if err != nil {
		s.auditLog.Log(ctx, eventLoginFailed, newUserID,
			zap.String("reason", "issue_tokens_failed"),
		)
		return nil, err
	}
	s.auditLog.Log(ctx, eventLoginSuccess, newUserID,
		zap.String("provider", provider),
		zap.String("flow", "new_user"),
	)
	return &CallbackResponse{
		Tokens:      sessionToTokenResponse(session),
		UserID:      newUserID,
		RedirectURL: redirectURL,
	}, nil
}

// ── IssueOneTimeCode ───────────────────────────────────────────────────────────

func (s *service) IssueOneTimeCode(ctx context.Context, userID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", apperrors.Wrap(apperrors.ErrInternalServer,
			fmt.Errorf("oauth: generate one-time code: %w", err))
	}
	plaintext := hex.EncodeToString(raw)

	sum := sha256.Sum256([]byte(plaintext))
	codeHash := hex.EncodeToString(sum[:])

	if err := s.repo.StoreOneTimeCode(ctx, dbpkg.StoreOneTimeCodeParams{
		ID:        uuid.NewString(),
		UserID:    userID,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(oneTimeCodeTTL),
	}); err != nil {
		return "", err
	}

	s.log.Debug("oauth: one-time code issued", zap.String("user_id", userID))
	return plaintext, nil
}

// ── ExchangeOneTimeCode ────────────────────────────────────────────────────────

func (s *service) ExchangeOneTimeCode(ctx context.Context, plaintext string) (*CallbackResponse, error) {
	if strings.TrimSpace(plaintext) == "" {
		return nil, ErrInvalidOneTimeCode
	}

	sum := sha256.Sum256([]byte(plaintext))
	codeHash := hex.EncodeToString(sum[:])

	userID, err := s.repo.ConsumeOneTimeCode(ctx, codeHash)
	if err != nil {
		return nil, err
	}

	session, err := s.tokenIssuer.IssueTokensForUser(ctx, userID)
	if err != nil {
		s.auditLog.Log(ctx, eventLoginFailed, userID,
			zap.String("reason", "exchange_issue_tokens_failed"),
		)
		return nil, err
	}

	s.auditLog.Log(ctx, eventLoginSuccess, userID,
		zap.String("flow", "mobile_exchange"),
	)
	return &CallbackResponse{Tokens: sessionToTokenResponse(session)}, nil
}

// ── LinkAccount ────────────────────────────────────────────────────────────────

func (s *service) LinkAccount(ctx context.Context, authenticatedUserID, linkingToken string) (*CallbackResponse, error) {
	s.auditLog.Log(ctx, eventAccountLinked, authenticatedUserID, zap.String("step", "initiated"))

	state, err := s.verifyAndConsumeLinkingToken(ctx, linkingToken)
	if err != nil {
		s.log.Debug("oauth: invalid linking token", zap.Error(err))
		return nil, ErrInvalidLinkingToken
	}

	encAccess, err := base64.RawURLEncoding.DecodeString(state.AccessEnc)
	if err != nil {
		return nil, ErrInvalidLinkingToken
	}
	encRefresh, err := base64.RawURLEncoding.DecodeString(state.RefreshEnc)
	if err != nil {
		return nil, ErrInvalidLinkingToken
	}

	var tokenExpiry *time.Time
	if !state.TokenExpiry.IsZero() {
		t := state.TokenExpiry
		tokenExpiry = &t
	}

	if err = s.repo.LinkOAuthAccountToUser(ctx, CreateOAuthAccountParams{
		ID:                    uuid.NewString(),
		UserID:                authenticatedUserID,
		Provider:              state.Provider,
		ProviderID:            state.ProviderID,
		ProviderEmail:         state.Email,
		ProviderName:          state.Name,
		AccessTokenEncrypted:  encAccess,
		RefreshTokenEncrypted: encRefresh,
		TokenExpiresAt:        tokenExpiry,
		EncKeyID:              s.tokenKeySet.ActiveKeyID(),
	}); err != nil {
		if isOAuthConflict(err) {
			s.auditLog.Log(ctx, eventLinkConflict, authenticatedUserID,
				zap.String("provider", state.Provider),
				zap.String("reason", "provider_already_linked"),
			)
			return nil, ErrOAuthAccountExists
		}
		return nil, err
	}

	session, err := s.tokenIssuer.IssueTokensForUser(ctx, authenticatedUserID)
	if err != nil {
		return nil, err
	}

	name, email, err := s.repo.GetUserNameAndEmail(ctx, authenticatedUserID)
	if err != nil {
		return nil, err
	}
	s.auditLog.Log(ctx, eventAccountLinked, authenticatedUserID,
		zap.String("provider", state.Provider),
		zap.String("email", email),
		zap.String("name", name),
	)
	return &CallbackResponse{Tokens: sessionToTokenResponse(session)}, nil
}

// ── Internal helpers ───────────────────────────────────────────────────────────

func (s *service) getProvider(name string) (Provider, error) {
	p, ok := s.providers[strings.ToLower(name)]
	if !ok {
		return nil, ErrProviderNotEnabled
	}
	return p, nil
}

func (s *service) encryptTokens(tok *oauth2.Token) (encAccess, encRefresh []byte, err error) {
	if tok.AccessToken != "" {
		encAccess, err = s.tokenKeySet.Encrypt([]byte(tok.AccessToken))
		if err != nil {
			return nil, nil, fmt.Errorf("oauth: encrypt access token: %w", err)
		}
	}
	if rt := tok.RefreshToken; rt != "" {
		encRefresh, err = s.tokenKeySet.Encrypt([]byte(rt))
		if err != nil {
			return nil, nil, fmt.Errorf("oauth: encrypt refresh token: %w", err)
		}
	}
	return encAccess, encRefresh, nil
}

// ── Server-side linking state ─────────────────────────────────────────────────

type linkingState struct {
	Provider    string    `json:"p"`
	ProviderID  string    `json:"pid"`
	Email       string    `json:"e"`
	Name        string    `json:"n"`
	AccessEnc   string    `json:"at"`
	RefreshEnc  string    `json:"rt"`
	TokenExpiry time.Time `json:"te"`
}

func (s *service) issueLinkingToken(
	ctx context.Context,
	u *ProviderUserInfo,
	provider string,
	encAccess, encRefresh []byte,
	tokenExpiry *time.Time,
) (string, error) {
	var expiry time.Time
	if tokenExpiry != nil {
		expiry = *tokenExpiry
	}

	state := linkingState{
		Provider:    provider,
		ProviderID:  u.ProviderID,
		Email:       u.Email,
		Name:        u.Name,
		AccessEnc:   base64.RawURLEncoding.EncodeToString(encAccess),
		RefreshEnc:  base64.RawURLEncoding.EncodeToString(encRefresh),
		TokenExpiry: expiry,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("linking state: marshal: %w", err)
	}

	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("linking state: generate nonce: %w", err)
	}

	expiresAt := time.Now().UTC().Add(linkingTokenTTL)
	if err = s.repo.StoreLinkingState(ctx, nonce, payload, expiresAt); err != nil {
		return "", err
	}

	return signNonce(nonce, s.linkingSecret), nil
}

func (s *service) verifyAndConsumeLinkingToken(ctx context.Context, raw string) (*linkingState, error) {
	nonce, err := verifyNonceSignature(raw, s.linkingSecret)
	if err != nil {
		return nil, fmt.Errorf("linking token: %w", err)
	}

	payload, err := s.repo.ConsumeLinkingState(ctx, nonce)
	if err != nil {
		return nil, err
	}

	var state linkingState
	if err = json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("linking state: unmarshal: %w", err)
	}
	return &state, nil
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func signNonce(nonce, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonce))
	return nonce + "." + hex.EncodeToString(mac.Sum(nil))
}

func verifyNonceSignature(token, secret string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed token")
	}
	nonce, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonce))
	expected := hex.EncodeToString(mac.Sum(nil))

	ha := sha256.Sum256([]byte(sig))
	he := sha256.Sum256([]byte(expected))
	diff := 0
	for i := range ha {
		diff |= int(ha[i] ^ he[i])
	}
	if diff != 0 {
		return "", fmt.Errorf("invalid signature")
	}
	return nonce, nil
}

// ── Conversion helpers ─────────────────────────────────────────────────────────

func sessionToTokenResponse(s *platformauth.SessionTokens) *TokenResponse {
	return &TokenResponse{
		AccessToken:           s.AccessToken,
		RefreshToken:          s.RefreshToken,
		TokenType:             s.TokenType,
		AccessTokenExpiresAt:  s.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: s.RefreshTokenExpiresAt,
	}
}

// ── Error predicates ──────────────────────────────────────────────────────────

func isNotFound(err error) bool {
	ae, ok := apperrors.As(err)
	return ok && ae.Code == apperrors.ErrNotFound.Code
}

func isEmailConflict(err error) bool {
	ae, ok := apperrors.As(err)
	return ok && ae.Code == apperrors.ErrEmailAlreadyExists.Code
}

func isOAuthConflict(err error) bool {
	ae, ok := apperrors.As(err)
	return ok && ae.Code == ErrOAuthAccountExists.Code
}
