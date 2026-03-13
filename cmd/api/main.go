// Command api is the entry-point for the go-auth-boilerplate HTTP server.
//
// It is intentionally thin: configuration, wiring, and lifecycle management
// all live in internal/app so they are testable.  main() only handles the
// two concerns that must be at the binary boundary:
//
//  1. Embedding the migration files — Go's embed package forbids ".." paths,
//     so the embed directive must be in a file whose directory is at or below
//     sql/migrations.  That file (sql/migrations/embed.go) exports an FS that
//     is imported and passed down here.
//
//  2. Translating a fatal startup error into a non-zero exit code so process
//     supervisors (systemd, Kubernetes, Docker) restart or alert correctly.
package main

import (
	"fmt"
	"os"

	"github.com/waqasmani/go-auth-boilerplate/internal/app"
	"github.com/waqasmani/go-auth-boilerplate/sql/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// migrations.FS is the embed.FS defined in sql/migrations/embed.go.
	// Passing it to app.New ensures migrations run before the first query,
	// without embedding from a path that uses "..".
	a, err := app.New(migrations.FS)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	return a.Run()
}
