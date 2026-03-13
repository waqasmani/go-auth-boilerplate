package users

import (
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
)

// Module wires together all users dependencies.
type Module struct {
	Handler *Handler
	Service Service
}

// NewModule constructs the users module.
//
// queries must be the prepared-statement *db.Queries returned by db.Prepare.
// See authmodule.NewModule for the rationale.
func NewModule(queries *db.Queries, log *zap.Logger) *Module {
	repo := NewRepository(queries)
	svc := NewService(repo, log)
	h := NewHandler(svc)

	return &Module{
		Handler: h,
		Service: svc,
	}
}
