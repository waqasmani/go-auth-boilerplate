package auth

import (
	"database/sql"

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
// Both sqlDB and queries are required:
//
//   - queries must be the prepared-statement *db.Queries returned by db.Prepare.
//     All normal queries reuse these handles — one parse/plan round-trip at
//     startup, not per-request.
//
//   - sqlDB is required by the repository's WithTx implementation to open
//     transactions.  It is used only for BeginTx; every statement inside the
//     transaction still goes through the prepared handles via queries.WithTx(tx).
//
// Ownership of both sqlDB and queries stays in app.go, which calls
// queries.Close() and db.Close() during graceful shutdown in the correct order.
func NewModule(sqlDB *sql.DB, queries *db.Queries, jwt *platformauth.JWT, log *zap.Logger) *Module {
	repo := NewRepository(sqlDB, queries)
	svc := NewService(repo, jwt, log)
	h := NewHandler(svc)

	return &Module{
		Handler: h,
		Service: svc,
	}
}
