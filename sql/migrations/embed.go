// Package migrations embeds the SQL migration files so they are compiled into
// the binary and available at runtime without depending on a filesystem path.
//
// This file MUST live inside the sql/migrations/ directory — Go's embed
// package forbids ".." in embed paths, so the only file that can embed these
// *.sql files is one that sits alongside them.
//
// Usage: import this package and pass FS to database.RunMigrations.
//
//	import "github.com/waqasmani/go-auth-boilerplate/sql/migrations"
//	database.RunMigrations(sqlDB, migrations.FS, log)
package migrations

import "embed"

// FS holds every *.sql file in this directory at compile time.
// golang-migrate's iofs source driver reads the files directly from this FS,
// so no migration file can be accidentally left off a production binary.
//
//go:embed *.sql
var FS embed.FS
