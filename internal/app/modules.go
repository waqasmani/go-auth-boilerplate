package app

// modules.go documents module wiring.
// All module constructors are called in app.go → app.New().
// Each module follows the pattern:
//
//	NewModule(db, deps...) → { Handler, Service }
//
// Modules are kept independent — cross-module calls go through service
// interfaces, never directly between module-internal types.
