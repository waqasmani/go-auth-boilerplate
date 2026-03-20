package oauth

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/cookieutil"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

const (
	oauthStateCookie    = "_oauth_state"
	oauthStateCookieTTL = 15 * 60

	// maxStateParamBytes is the per-parameter cap on the OAuth `state` value.
	//
	// A legitimate signed state produced by SignOAuthState is:
	//   base64url(JSON{nonce,provider,redirect_url,pkce_verifier,exp})
	//   + "." + hex(SHA-256 HMAC)
	//
	// Measured maximum with the longest plausible redirect_url (~100 chars):
	//   ~320 bytes total. 512 is ~1.6× that ceiling.
	//
	// This check is belt-and-suspenders behind the global QuerySizeLimit
	// middleware. It catches the case where a future refactor routes the
	// callback differently and the global middleware is inadvertently bypassed.
	maxStateParamBytes = 512

	// maxCodeParamBytes caps the OAuth authorisation code. Provider codes are
	// typically 20–200 chars; 512 is generous for any legitimate provider.
	maxCodeParamBytes = 512

	// maxRedirectURLBytes caps the redirect_url query parameter on the login
	// initiation endpoint. Standard URL length budget; well above any
	// legitimate deep-link or HTTPS redirect destination in practice.
	maxRedirectURLBytes = 2048
)

// errParamTooLong is returned when an individual query parameter exceeds its
// per-parameter cap. Reuses ErrBadRequest so the response is 400 (not 414)
// since the total URI was already within bounds — the issue is a single
// oversized value, not the overall URI length.
var errParamTooLong = apperrors.New(
	"PARAM_TOO_LONG",
	"one or more query parameters exceed the maximum allowed length",
	http.StatusBadRequest,
	nil,
)

// Handler exposes the OAuth HTTP endpoints.
type Handler struct {
	svc      Service
	cfg      *config.Config
	validate *validator.Validate
}

// NewHandler constructs an OAuth handler.
func NewHandler(svc Service, cfg *config.Config) *Handler {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})
	return &Handler{svc: svc, cfg: cfg, validate: v}
}

// Login godoc
// @Summary      Initiate OAuth login
// @Tags         oauth
// @Param        provider     path   string true  "Provider slug: google | facebook"
// @Param        redirect_url query  string false "Post-login destination (https:// or custom-scheme; must be in allowlist)"
// @Success      302
// @Failure      400 {object} response.Response
// @Router       /oauth/{provider}/login [get]
func (h *Handler) Login(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))

	redirectURL := strings.TrimSpace(c.Query("redirect_url"))

	// Belt-and-suspenders per-parameter cap. The global QuerySizeLimit
	// middleware already rejected requests whose entire query string exceeds
	// 4 KiB, so this catches the edge case of a single parameter consuming
	// most of that budget.
	if len(redirectURL) > maxRedirectURLBytes {
		response.Error(c, errParamTooLong)
		return
	}

	if err := h.validateRedirectURL(provider, redirectURL); err != nil {
		response.Error(c, err)
		return
	}

	log := logger.FromContext(c.Request.Context())
	log.Debug("oauth: login initiated", zap.String("provider", provider))

	authURL, signedState, err := h.svc.BuildAuthURL(c.Request.Context(), provider, redirectURL)
	if err != nil {
		response.Error(c, err)
		return
	}

	// State cookie is scoped via cookieutil.ResolveCookieDomain so it is
	// consistent with every other cookie in the codebase and works correctly
	// in reverse-proxy setups where the API hostname differs from the frontend.
	// SameSite=Lax is intentional: the OAuth redirect is a top-level navigation,
	// so Strict would prevent the cookie from being sent on the callback.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		oauthStateCookie,
		signedState,
		oauthStateCookieTTL,
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure,
		true, // HttpOnly
	)

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback godoc
// @Summary      OAuth provider callback
// @Tags         oauth
// @Param        provider path  string true  "Provider slug"
// @Param        code     query string true  "Authorisation code from provider"
// @Param        state    query string true  "State parameter (must match cookie)"
// @Success      200 {object} response.Response{data=CallbackResponse}
// @Success      303 "Web redirect"
// @Success      302 "Mobile redirect"
// @Failure      400 {object} response.Response
// @Failure      403 {object} response.Response
// @Failure      409 {object} response.Response
// @Router       /oauth/{provider}/callback [get]
func (h *Handler) Callback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	log := logger.FromContext(c.Request.Context())

	if errParam := c.Query("error"); errParam != "" {
		log.Info("oauth: provider returned error",
			zap.String("provider", provider),
			zap.String("error", errParam),
			zap.String("error_description", c.Query("error_description")),
		)
		response.Error(c, apperrors.New(
			"OAUTH_PROVIDER_ERROR",
			"authorisation was denied or an error occurred with the provider",
			400, nil,
		))
		return
	}

	code, stateParam := c.Query("code"), c.Query("state")
	if code == "" || stateParam == "" {
		response.Error(c, apperrors.ErrBadRequest)
		return
	}

	// Per-parameter length caps — defence-in-depth behind the global
	// QuerySizeLimit middleware. ParseAndVerifyOAuthState performs base64
	// decoding, JSON unmarshalling, and HMAC comparison; capping state here
	// ensures none of those operations ever process an attacker-controlled
	// megabyte-scale input regardless of how the route is mounted in future.
	if len(stateParam) > maxStateParamBytes || len(code) > maxCodeParamBytes {
		log.Warn("oauth: oversized query parameter rejected",
			zap.String("provider", provider),
			zap.Int("state_len", len(stateParam)),
			zap.Int("code_len", len(code)),
		)
		response.Error(c, errParamTooLong)
		return
	}

	// CSRF gate: the cookie's mere existence proves this request originated
	// from a tab that went through Login on the same origin. An attacker on a
	// foreign origin cannot read or set our cookies, so absence is a hard CSRF
	// signal. We do not compare the cookie value to stateParam here — that
	// comparison would be a non-constant-time string equality on a
	// cryptographic value, creating a timing side-channel. The real
	// verification (HMAC signature + expiry) is done atomically and in
	// constant time inside ParseAndVerifyOAuthState below.
	if _, err := c.Cookie(oauthStateCookie); err != nil {
		log.Warn("oauth: missing state cookie — possible CSRF", zap.String("provider", provider))
		response.Error(c, ErrInvalidState)
		return
	}

	// Clear the state cookie before any further processing so it cannot be
	// replayed even if the handler returns an error after this point.
	// Domain must match the domain used in Login; cookieutil.ResolveCookieDomain
	// guarantees byte-identical Domain attributes so browsers honour the clear.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		oauthStateCookie,
		"",
		-1,
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure,
		true,
	)

	resp, err := h.svc.HandleCallback(c.Request.Context(), provider, code, stateParam)
	if err != nil {
		response.Error(c, err)
		return
	}

	if resp.RequiresLinking {
		c.JSON(http.StatusConflict, response.Response{
			Success: false,
			Error: &response.ErrorBody{
				Code:    ErrOAuthEmailConflict.Code,
				Message: ErrOAuthEmailConflict.Message,
			},
			Data: gin.H{"linking_token": resp.LinkingToken},
		})
		return
	}

	switch classifyRedirect(resp.RedirectURL) {

	case redirectKindWeb:
		h.setRefreshCookie(c, resp.Tokens.RefreshToken)
		c.Redirect(http.StatusSeeOther, resp.RedirectURL)

	case redirectKindMobile:
		// The code was pre-issued inside HandleCallback, atomically with account
		// creation for new users. Never call IssueOneTimeCode separately here.
		if resp.OneTimeCode == "" {
			response.Error(c, apperrors.ErrInternalServer)
			return
		}
		c.Redirect(http.StatusFound, appendQueryParam(resp.RedirectURL, "code", resp.OneTimeCode))

	default:
		h.setRefreshCookie(c, resp.Tokens.RefreshToken)
		response.OK(c, resp.Tokens)
	}
}

// Exchange godoc
// @Summary      Redeem one-time code for session tokens (mobile)
// @Tags         oauth
// @Accept       json
// @Produce      json
// @Param        body body ExchangeRequest true "One-time code payload"
// @Success      200 {object} response.Response{data=TokenResponse}
// @Failure      400 {object} response.Response
// @Failure      403 {object} response.Response
// @Router       /oauth/exchange [post]
func (h *Handler) Exchange(c *gin.Context) {
	var req ExchangeRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	resp, err := h.svc.ExchangeOneTimeCode(c.Request.Context(), req.Code)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, resp.Tokens)
}

// Link godoc
// @Summary      Explicitly link OAuth account to authenticated user
// @Tags         oauth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        provider path  string      true "Provider slug"
// @Param        body     body  LinkRequest true "Linking token"
// @Success      200 {object} response.Response{data=TokenResponse}
// @Failure      400 {object} response.Response
// @Failure      403 {object} response.Response
// @Failure      409 {object} response.Response
// @Router       /oauth/{provider}/link [post]
func (h *Handler) Link(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}

	var req LinkRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	resp, err := h.svc.LinkAccount(c.Request.Context(), claims.UserID, req.LinkingToken)
	if err != nil {
		response.Error(c, err)
		return
	}

	h.setRefreshCookie(c, resp.Tokens.RefreshToken)
	response.OK(c, resp.Tokens)
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

func (h *Handler) setRefreshCookie(c *gin.Context, token string) {
	c.SetSameSite(cookieutil.ParseSameSite(h.cfg.CookieSameSite))
	c.SetCookie(
		"refresh_token",
		token,
		int(h.cfg.RefreshTTL.Seconds()),
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure, // config-driven
		true,               // HttpOnly — always
	)
}

// validateRedirectURL checks the redirect_url against the provider's allowlist.
func (h *Handler) validateRedirectURL(provider, redirectURL string) error {
	if redirectURL == "" {
		return nil
	}
	pc, ok := h.cfg.OAuthProviders[provider]
	if !ok || !pc.Enabled {
		return ErrProviderNotEnabled
	}

	u, err := url.Parse(redirectURL)
	if err == nil && strings.EqualFold(u.Scheme, "http") {
		return ErrRedirectNotAllowed
	}

	norm := normaliseRedirect(redirectURL)
	for _, allowed := range pc.AllowedRedirects {
		if norm == normaliseRedirect(allowed) {
			return nil
		}
	}
	return ErrRedirectNotAllowed
}

func normaliseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(strings.TrimRight(raw, "/"))
	}
	return strings.ToLower(u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"))
}
