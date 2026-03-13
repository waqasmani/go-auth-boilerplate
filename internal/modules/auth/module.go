package auth

import (
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// Module wires together all auth dependencies.
type Module struct {
	Handler *Handler
	Service Service
}

// NewModule constructs the auth module with its dependencies.
//
// queries must be the prepared-statement *db.Queries returned by db.Prepare —
// not the unprepared version from db.New.  Accepting the prepared instance
// here (rather than a *sql.DB) means:
//
//  1. Statements are prepared once at startup and reused across all requests.
//  2. The module cannot accidentally call db.New and silently discard the
//     prepared statements the caller spent a round-trip creating.
//  3. Ownership of the *db.Queries lifetime stays in app.go, which calls
//     queries.Close() during graceful shutdown in the right order.
func NewModule(queries *db.Queries, jwt *platformauth.JWT, log *zap.Logger) *Module {
	repo := NewRepository(queries)
	svc := NewService(repo, jwt, log)
	h := NewHandler(svc)

	return &Module{
		Handler: h,
		Service: svc,
	}
}
