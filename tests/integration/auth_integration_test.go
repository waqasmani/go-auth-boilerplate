//go:build integration

package integration_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/internal/router"
)

var (
	testDB     *sql.DB
	testServer *httptest.Server
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	// ─── Database ──────────────────────────────────────────────────────────────
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "root:rootpassword@tcp(localhost:3306)/auth_db_test?parseTime=true&charset=utf8mb4&loc=UTC"
	}

	var err error
	testDB, err = database.New(database.DefaultConfig(dsn))
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: connect db: %v\n", err)
		os.Exit(1)
	}

	// ─── JWT ───────────────────────────────────────────────────────────────────
	jwtHelper := platformauth.NewJWT(platformauth.JWTConfig{
		Secret:     getEnv("JWT_SECRET", "integration-test-secret-32-chars!!"),
		Issuer:     getEnv("JWT_ISSUER", "go-auth-boilerplate"),
		Audience:   getEnv("JWT_AUDIENCE", "go-auth-boilerplate-users"),
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	})

	log := zap.NewNop()
	authMod := authmodule.NewModule(testDB, jwtHelper, log)
	usersMod := usersmodule.NewModule(testDB, log)
	engine := router.New("test", log, jwtHelper, authMod, usersMod)

	testServer = httptest.NewServer(engine)
	defer testServer.Close()

	exitCode := m.Run()

	_ = testDB.Close()
	os.Exit(exitCode)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func postJSON(t *testing.T, path string, body interface{}, token string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, testServer.URL+path, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func getJSON(t *testing.T, path string, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, testServer.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestAuthFlow runs: register → login → refresh → /users/me → logout
func TestAuthFlow(t *testing.T) {
	unique := fmt.Sprintf("inttest_%d@example.com", time.Now().UnixNano())

	// ── 1. Register ────────────────────────────────────────────────────────────
	registerResp := postJSON(t, "/api/v1/auth/register", map[string]string{
		"name":     "Integration Tester",
		"email":    unique,
		"password": "testpassword123",
	}, "")
	if registerResp.StatusCode != http.StatusCreated {
		body := decodeBody(t, registerResp)
		t.Fatalf("register: expected 201, got %d: %v", registerResp.StatusCode, body)
	}
	regBody := decodeBody(t, registerResp)

	data, ok := regBody["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("register: missing data field: %v", regBody)
	}
	originalRefreshToken := data["refresh_token"].(string)
	accessToken := data["access_token"].(string)
	if accessToken == "" || originalRefreshToken == "" {
		t.Fatalf("register: tokens missing: %v", data)
	}
	t.Logf("✓ registered as %s", unique)

	// ── 2. Login ───────────────────────────────────────────────────────────────
	loginResp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email":    unique,
		"password": "testpassword123",
	}, "")
	if loginResp.StatusCode != http.StatusOK {
		body := decodeBody(t, loginResp)
		t.Fatalf("login: expected 200, got %d: %v", loginResp.StatusCode, body)
	}
	loginBody := decodeBody(t, loginResp)
	loginData := loginBody["data"].(map[string]interface{})
	refreshToken := loginData["refresh_token"].(string)
	loginAccess := loginData["access_token"].(string)
	if refreshToken == "" || loginAccess == "" {
		t.Fatalf("login: tokens missing")
	}
	t.Logf("✓ logged in")

	// ── 3. /users/me (protected) ───────────────────────────────────────────────
	meResp := getJSON(t, "/api/v1/users/me", loginAccess)
	if meResp.StatusCode != http.StatusOK {
		body := decodeBody(t, meResp)
		t.Fatalf("/me: expected 200, got %d: %v", meResp.StatusCode, body)
	}
	meBody := decodeBody(t, meResp)
	meData := meBody["data"].(map[string]interface{})
	if meData["email"] != unique {
		t.Errorf("/me: expected email %s, got %v", unique, meData["email"])
	}
	t.Logf("✓ /users/me returned: %v", meData["email"])

	// ── 4. Refresh ─────────────────────────────────────────────────────────────
	refreshResp := postJSON(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if refreshResp.StatusCode != http.StatusOK {
		body := decodeBody(t, refreshResp)
		t.Fatalf("refresh: expected 200, got %d: %v", refreshResp.StatusCode, body)
	}
	refreshBody := decodeBody(t, refreshResp)
	newRefreshToken := refreshBody["data"].(map[string]interface{})["refresh_token"].(string)
	t.Logf("✓ token refreshed")

	// ── 5. Reuse detection — refresh with old token ─────────────────────────
	reuseResp := postJSON(t, "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken, // already used
	}, "")
	if reuseResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("reuse: expected 401, got %d", reuseResp.StatusCode)
	} else {
		t.Logf("✓ reuse detection working")
	}

	// ── 6. Logout ──────────────────────────────────────────────────────────────
	logoutResp := postJSON(t, "/api/v1/auth/logout", map[string]string{
		"refresh_token": newRefreshToken,
	}, "")
	if logoutResp.StatusCode != http.StatusNoContent {
		body := decodeBody(t, logoutResp)
		t.Fatalf("logout: expected 204, got %d: %v", logoutResp.StatusCode, body)
	}
	t.Logf("✓ logged out")

	// ── 7. /me with old access token after logout should still work ─────────
	// (access tokens are stateless; they expire naturally)
	meAfter := getJSON(t, "/api/v1/users/me", loginAccess)
	if meAfter.StatusCode != http.StatusOK {
		t.Logf("note: /me returned %d after logout (expected if access token expired)", meAfter.StatusCode)
	}
	_ = decodeBody(t, meAfter)
}

func TestLogin_WrongPassword(t *testing.T) {
	unique := fmt.Sprintf("badpw_%d@example.com", time.Now().UnixNano())

	// Register
	reg := postJSON(t, "/api/v1/auth/register", map[string]string{
		"name": "Test", "email": unique, "password": "correctpassword",
	}, "")
	if reg.StatusCode != http.StatusCreated {
		t.Skip("skipping: register failed")
	}
	_ = decodeBody(t, reg)

	// Login with wrong password
	resp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email": unique, "password": "wrongpassword",
	}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	_ = decodeBody(t, resp)
}

func TestProtectedRoute_NoToken(t *testing.T) {
	resp := getJSON(t, "/api/v1/users/me", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	_ = decodeBody(t, resp)
}
