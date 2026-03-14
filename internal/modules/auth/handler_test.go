package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
)

// ─── Stub Service ─────────────────────────────────────────────────────────────

type stubService struct {
	registerFn func(ctx context.Context, req auth.RegisterRequest) (*auth.TokenResponse, error)
	loginFn    func(ctx context.Context, req auth.LoginRequest) (*auth.TokenResponse, error)
	refreshFn  func(ctx context.Context, req auth.RefreshRequest) (*auth.TokenResponse, error)
	logoutFn   func(ctx context.Context, req auth.LogoutRequest) error
}

func (s *stubService) Register(ctx context.Context, req auth.RegisterRequest) (*auth.TokenResponse, error) {
	return s.registerFn(ctx, req)
}
func (s *stubService) Login(ctx context.Context, req auth.LoginRequest) (*auth.TokenResponse, error) {
	return s.loginFn(ctx, req)
}
func (s *stubService) Refresh(ctx context.Context, req auth.RefreshRequest) (*auth.TokenResponse, error) {
	return s.refreshFn(ctx, req)
}
func (s *stubService) Logout(ctx context.Context, req auth.LogoutRequest) error {
	return s.logoutFn(ctx, req)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestLoginHandler_BadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	h := auth.NewHandler(&stubService{}, &config.Config{})
	r.POST("/login", h.Login)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestLoginHandler_ValidationError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	h := auth.NewHandler(&stubService{}, &config.Config{})
	r.POST("/login", h.Login)

	body, _ := json.Marshal(map[string]string{"email": "not-an-email", "password": "pw"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}
}

func TestLoginHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	svc := &stubService{
		loginFn: func(_ context.Context, _ auth.LoginRequest) (*auth.TokenResponse, error) {
			return &auth.TokenResponse{
				AccessToken:  "access",
				RefreshToken: "refresh",
				TokenType:    "Bearer",
			}, nil
		},
	}
	h := auth.NewHandler(svc, &config.Config{})
	r.POST("/login", h.Login)

	body, _ := json.Marshal(auth.LoginRequest{Email: "user@example.com", Password: "password123"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d body: %s", w.Code, w.Body.String())
	}
}
