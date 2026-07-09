//go:build libgit2

package enrich

import (
	"context"
	"encoding/json"
)

// Default returns the libgit2-backed enricher when built with `-tags libgit2`.
//
// TODO(enrich): wire github.com/libgit2/git2go here to parse repo status and
// diff stat into the returned blob. Kept as a nil-returning placeholder so the
// libgit2 build tag compiles before git2go is added as a dependency; adding
// the real binding is a tracked follow-up (see docs design spec). The contract
// is unchanged: return (nil, nil) on any failure so enrichment never breaks a
// git invocation.
func Default() Enricher { return libgit2Enricher{} }

type libgit2Enricher struct{}

func (libgit2Enricher) Enrich(context.Context, string) (json.RawMessage, error) {
	return nil, nil
}
