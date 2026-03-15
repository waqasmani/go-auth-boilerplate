package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ─── Stub Service ─────────────────────────────────────────────────────────────

// stubService implements auth.Service. Every field is a func so individual
// tests can inject behaviour without building a full mock. Methods whose func
// field is nil panic if called — a deliberate signal that the test exercised an
// unexpected code path.

type stubService struct {
	registerFn         func(ctx context.Context, req auth.RegisterRequest) (*auth.TokenResponse, error)
	loginFn            func(ctx context.Context, req auth.LoginRequest) (*auth.LoginResult, error)
	refreshFn          func(ctx context.Context, req auth.RefreshRequest) (*auth.TokenResponse, error)
	logoutFn           func(ctx context.Context, req auth.LogoutRequest) error
	setMFAChallengerFn func(c auth.MFAChallenger)
	issueTokensFn      func(ctx context.Context, userID string) (*platformauth.SessionTokens, error)
}

func (s *stubService) Register(ctx context.Context, req auth.RegisterRequest) (*auth.TokenResponse, error) {
	return s.registerFn(ctx, req)
}
func (s *stubService) Login(ctx context.Context, req auth.LoginRequest) (*auth.LoginResult, error) {
	return s.loginFn(ctx, req)
}
func (s *stubService) Refresh(ctx context.Context, req auth.RefreshRequest) (*auth.TokenResponse, error) {
	return s.refreshFn(ctx, req)
}
func (s *stubService) Logout(ctx context.Context, req auth.LogoutRequest) error {
	return s.logoutFn(ctx, req)
}
func (s *stubService) SetMFAChallenger(c auth.MFAChallenger) {
	if s.setMFAChallengerFn != nil {
		s.setMFAChallengerFn(c)
	}
}
func (s *stubService) IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error) {
	return s.issueTokensFn(ctx, userID)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// newRouter wires a handler onto a fresh gin engine in test mode.
func newRouter(svc auth.Service) (*gin.Engine, *auth.Handler) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := auth.NewHandler(svc, &config.Config{})
	return r, h
}

// post builds a POST request with a JSON body and the correct Content-Type.
func post(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewBuffer(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// serve runs a single request through the engine and returns the recorder.
func serve(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── Login: input validation ───────────────────────────────────────────────────

func TestLoginHandler_BadJSON(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/login", h.Login)

	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := serve(r, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestLoginHandler_MissingContentType(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/login", h.Login)

	body, _ := json.Marshal(auth.LoginRequest{Email: "user@example.com", Password: "password123"})
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	// Content-Type intentionally omitted
	w := serve(r, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestLoginHandler_ValidationError(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/login", h.Login)

	w := serve(r, post(t, "/login", map[string]string{
		"email":    "not-an-email",
		"password": "pw",
	}))

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestLoginHandler_MissingFields(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/login", h.Login)

	// Empty object — both required fields absent.
	w := serve(r, post(t, "/login", map[string]string{}))

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

// ─── Login: service error paths ───────────────────────────────────────────────

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	svc := &stubService{
		loginFn: func(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
			return nil, apperrors.ErrInvalidCredentials
		},
	}
	r, h := newRouter(svc)
	r.POST("/login", h.Login)

	w := serve(r, post(t, "/login", auth.LoginRequest{
		Email:    "user@example.com",
		Password: "wrongpassword1234",
	}))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginHandler_EmailNotVerified(t *testing.T) {
	// After the verification gate was added, Login returns ErrEmailNotVerified
	// (403) instead of issuing tokens. The handler must not set a cookie.
	svc := &stubService{
		loginFn: func(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
			return nil, apperrors.ErrEmailNotVerified
		},
	}
	r, h := newRouter(svc)
	r.POST("/login", h.Login)

	w := serve(r, post(t, "/login", auth.LoginRequest{
		Email:    "unverified@example.com",
		Password: "validpassword1234",
	}))

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	// No refresh cookie must be set.
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh_token" {
			t.Error("refresh_token cookie must not be set when email is unverified")
		}
	}
}

// ─── Login: success paths ─────────────────────────────────────────────────────

func TestLoginHandler_Success_NoMFA(t *testing.T) {
	// Standard login for a user with two_fa_enabled = false.
	// Handler must return 200 with a TokenResponse body and set the cookie.
	svc := &stubService{
		loginFn: func(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
			return &auth.LoginResult{
				Token: &auth.TokenResponse{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					TokenType:    "Bearer",
				},
			}, nil
		},
	}
	r, h := newRouter(svc)
	r.POST("/login", h.Login)

	w := serve(r, post(t, "/login", auth.LoginRequest{
		Email:    "user@example.com",
		Password: "validpassword1234",
	}))

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Response body must contain the token fields.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object in response, got: %v", resp)
	}
	if data["access_token"] != "access-token" {
		t.Errorf("unexpected access_token: %v", data["access_token"])
	}
	// requires_mfa must be absent (or false) for a non-MFA login.
	if _, hasMFA := data["requires_mfa"]; hasMFA {
		t.Error("requires_mfa must not be present in a non-MFA login response")
	}
}

func TestLoginHandler_Success_MFAChallenge(t *testing.T) {
	// Login for a user with two_fa_enabled = true.
	// Handler must return 200 with an MFAChallengeResponse and NO cookie.
	expiresAt := time.Now().Add(5 * time.Minute)
	svc := &stubService{
		loginFn: func(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
			return &auth.LoginResult{
				Challenge: &auth.MFAChallengeResponse{
					RequiresMFA: true,
					MFAToken:    "opaque-challenge-token",
					ExpiresAt:   expiresAt,
				},
			}, nil
		},
	}
	r, h := newRouter(svc)
	r.POST("/login", h.Login)

	w := serve(r, post(t, "/login", auth.LoginRequest{
		Email:    "mfa@example.com",
		Password: "validpassword1234",
	}))

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object in response, got: %v", resp)
	}
	if data["requires_mfa"] != true {
		t.Errorf("expected requires_mfa=true, got: %v", data["requires_mfa"])
	}
	if data["mfa_token"] != "opaque-challenge-token" {
		t.Errorf("unexpected mfa_token: %v", data["mfa_token"])
	}

	// No refresh cookie must be present — tokens are not issued until OTP is verified.
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh_token" {
			t.Error("refresh_token cookie must not be set when MFA challenge is returned")
		}
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func TestRegisterHandler_BadJSON(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/register", h.Register)

	req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	w := serve(r, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestRegisterHandler_ValidationError_ShortPassword(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/register", h.Register)

	w := serve(r, post(t, "/register", auth.RegisterRequest{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "short", // min is 12
	}))

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestRegisterHandler_Success(t *testing.T) {
	svc := &stubService{
		registerFn: func(_ context.Context, _ auth.RegisterRequest) (*auth.TokenResponse, error) {
			return &auth.TokenResponse{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				TokenType:    "Bearer",
			}, nil
		},
	}
	r, h := newRouter(svc)
	r.POST("/register", h.Register)

	w := serve(r, post(t, "/register", auth.RegisterRequest{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "strongpassword1234",
	}))

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestRegisterHandler_EmailConflict(t *testing.T) {
	svc := &stubService{
		registerFn: func(_ context.Context, _ auth.RegisterRequest) (*auth.TokenResponse, error) {
			return nil, apperrors.ErrEmailAlreadyExists
		},
	}
	r, h := newRouter(svc)
	r.POST("/register", h.Register)

	w := serve(r, post(t, "/register", auth.RegisterRequest{
		Name:     "Alice",
		Email:    "taken@example.com",
		Password: "strongpassword1234",
	}))

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

func TestRefreshHandler_MissingToken(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/refresh", h.Refresh)

	// No cookie, no body field — validation must reject with 422.
	w := serve(r, post(t, "/refresh", map[string]string{}))

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestRefreshHandler_TokenExpired(t *testing.T) {
	svc := &stubService{
		refreshFn: func(_ context.Context, _ auth.RefreshRequest) (*auth.TokenResponse, error) {
			return nil, apperrors.ErrTokenExpired
		},
	}
	r, h := newRouter(svc)
	r.POST("/refresh", h.Refresh)

	w := serve(r, post(t, "/refresh", auth.RefreshRequest{RefreshToken: "expired-token"}))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRefreshHandler_Success(t *testing.T) {
	svc := &stubService{
		refreshFn: func(_ context.Context, _ auth.RefreshRequest) (*auth.TokenResponse, error) {
			return &auth.TokenResponse{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
			}, nil
		},
	}
	r, h := newRouter(svc)
	r.POST("/refresh", h.Refresh)

	w := serve(r, post(t, "/refresh", auth.RefreshRequest{RefreshToken: "valid-token"}))

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func TestLogoutHandler_MissingToken(t *testing.T) {
	r, h := newRouter(&stubService{})
	r.POST("/logout", h.Logout)

	w := serve(r, post(t, "/logout", map[string]string{}))

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestLogoutHandler_Success(t *testing.T) {
	svc := &stubService{
		logoutFn: func(_ context.Context, _ auth.LogoutRequest) error {
			return nil
		},
	}
	r, h := newRouter(svc)
	r.POST("/logout", h.Logout)

	w := serve(r, post(t, "/logout", auth.LogoutRequest{RefreshToken: "valid-token"}))

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestLogoutHandler_AlreadyLoggedOut(t *testing.T) {
	// Logout is idempotent — a missing/revoked token still returns 204.
	svc := &stubService{
		logoutFn: func(_ context.Context, _ auth.LogoutRequest) error {
			return nil // service swallows ErrTokenInvalid for idempotency
		},
	}
	r, h := newRouter(svc)
	r.POST("/logout", h.Logout)

	w := serve(r, post(t, "/logout", auth.LogoutRequest{RefreshToken: "already-gone"}))

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}
