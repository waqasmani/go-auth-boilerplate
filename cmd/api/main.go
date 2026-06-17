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
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/waqasmani/go-auth-boilerplate/internal/app"
	"github.com/waqasmani/go-auth-boilerplate/sql/migrations"
)

// Build metadata, injected at link time via -ldflags "-X main.Version=…".
// See the Makefile's LDFLAGS and the Dockerfile build stage. The defaults below
// are what an un-stamped `go run`/`go build` produces.
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func main() {
	versionFlag := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("go-auth-boilerplate %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		return
	}

	// `api healthcheck [path]` performs an in-container HTTP probe and exits 0/1.
	// It exists so the scratch-based runtime image (no shell, no curl/wget) can
	// still declare a Docker HEALTHCHECK. Defaults to /livez (liveness); pass
	// /readyz for a dependency-aware readiness probe.
	if flag.Arg(0) == "healthcheck" {
		os.Exit(healthcheck(flag.Arg(1)))
	}

	// `api migrate` applies all pending schema migrations once and exits 0/1.
	// Run it as a Kubernetes init-container / Job or a CI step so a single
	// process owns DDL, and run the API replicas with SKIP_MIGRATIONS=true so
	// they never contend for the migration advisory lock on boot.
	if flag.Arg(0) == "migrate" {
		os.Exit(runMigrate())
	}

	// `api outbox-worker` is the long-running process that drains the
	// email_outbox table and sends mail over SMTP. Run it as its own Deployment
	// (scalable) — not inside the API pods.
	if flag.Arg(0) == "outbox-worker" {
		os.Exit(runOutboxWorker())
	}

	// `api cleanup` purges expired token rows and old outbox rows once, then
	// exits. Run it as a CronJob. The same logic also ships as cmd/cleanup for
	// non-container schedulers.
	if flag.Arg(0) == "cleanup" {
		os.Exit(runCleanup())
	}

	// Hand the link-time build metadata to the app so it is emitted on the
	// structured startup log line for incident triage.
	app.Build = app.BuildInfo{Version: Version, Commit: Commit, BuildTime: BuildTime}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// healthcheck probes the local server and returns a process exit code.
func healthcheck(path string) int {
	if path == "" {
		path = "/livez"
	}
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + path) // #nosec G704 -- localhost-only liveness probe; host is the hardcoded loopback, only port/path come from operator config (APP_ENV / CLI arg), never request input

	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", path, resp.StatusCode)
		return 1
	}
	return 0
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
