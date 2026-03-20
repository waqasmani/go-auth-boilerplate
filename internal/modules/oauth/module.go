package oauth

import (
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

const (
	rateLimitTTL     = 10 * time.Minute
	rateLimitMaxKeys = 10_000
)

// Module wires together all OAuth dependencies.
type Module struct {
	Handler *Handler
	Service Service
}

// ModuleConfig carries every dependency needed to construct the OAuth module.
type ModuleConfig struct {
	SqlDB       *sql.DB
	Queries     *dbpkg.Queries // sqlc-generated prepared statements
	Cfg         *config.Config
	Log         *zap.Logger
	AuditLog    *audit.Logger
	TokenIssuer TokenIssuer
	// TokenKeySet is the SymmetricKeySet used to encrypt provider access/refresh
	// tokens at rest. Built from config.OAuthTokenKeys in app.go.
	TokenKeySet *platformauth.SymmetricKeySet
	// StateSecret is the dedicated HMAC signing key for OAuth state parameters
	// and linking-token nonces. Must be sourced from config.OAuthStateSecret —
	// never from OTPSecret. Keeping these secrets separate ensures a compromise
	// of one does not compromise the other.
	//
	// Required when any OAuth provider is enabled. NewModule returns an error
	// when this is empty so misconfiguration surfaces at startup with a clear
	// message rather than silently issuing forgeable state tokens.
	StateSecret string
}

// NewModule constructs the OAuth module. Returns an error on any
// misconfiguration so that app.New can surface a structured startup message
// rather than crashing with a raw stack trace. Failure modes:
//   - An unknown provider name in config.OAuthProviders (e.g. a typo like
//     "goggle").
//   - StateSecret is empty while at least one provider is enabled — an empty
//     secret means all OAuth state HMACs use key "", allowing any attacker to
//     forge a valid state token and bypass CSRF protection entirely.
func NewModule(m ModuleConfig) (*Module, error) {
	providers, err := buildProviders(m.Cfg)
	if err != nil {
		return nil, fmt.Errorf("oauth: module init: %w", err)
	}

	if len(providers) > 0 && m.StateSecret == "" {
		return nil, fmt.Errorf(
			"oauth: StateSecret must not be empty when OAuth providers are enabled — " +
				"set OAUTH_STATE_SECRET (≥32 bytes) and wire cfg.OAuthStateSecret into ModuleConfig.StateSecret",
		)
	}

	if len(providers) == 0 {
		m.Log.Warn("oauth: no providers are enabled — OAuth login endpoints are registered but will return 400")
	}

	repo := NewRepository(m.SqlDB, m.Queries)
	svc := NewService(
		m.SqlDB,
		repo,
		providers,
		m.TokenIssuer,
		m.TokenKeySet,
		m.StateSecret,
		m.Log,
		m.AuditLog,
	)
	h := NewHandler(svc, m.Cfg)

	return &Module{Handler: h, Service: svc}, nil
}

// buildProviders constructs the Provider map from configuration. Only enabled
// providers are included.
func buildProviders(cfg *config.Config) (map[string]Provider, error) {
	providers := make(map[string]Provider)
	for name, pc := range cfg.OAuthProviders {
		if !pc.Enabled {
			continue
		}
		switch name {
		case "google":
			providers["google"] = newGoogleProvider(pc.ClientID, pc.ClientSecret, pc.RedirectURL, pc.Scopes)
		case "facebook":
			providers["facebook"] = newFacebookProvider(pc.ClientID, pc.ClientSecret, pc.RedirectURL, pc.Scopes)
		default:
			return nil, fmt.Errorf("unknown OAuth provider %q — only 'google' and 'facebook' are supported", name)
		}
	}
	return providers, nil
}
