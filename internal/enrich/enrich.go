// Package enrich optionally augments audit records with structured git data
// (parsed status, diff stat) from libgit2.
//
// The libgit2/git2go backend is additive and build-tagged: the default build
// is cgo-free and returns nil enrichment. Building with `-tags libgit2` (and a
// libgit2 C library available to cgo) activates the real implementation. Audit
// logging and passthrough never depend on this package succeeding.
package enrich

import (
	"context"
	"encoding/json"
)

// Enricher produces an optional structured JSON blob describing the state of
// the repository at cwd after a git invocation. A nil result (with nil error)
// means "no enrichment available", which is the normal cgo-free case.
type Enricher interface {
	// Enrich returns a JSON blob or nil. Implementations must never fail the
	// overall invocation; they should degrade to (nil, nil) on any error.
	Enrich(ctx context.Context, cwd string) (json.RawMessage, error)
}
