//go:build !libgit2

package enrich

import (
	"context"
	"encoding/json"
)

// Default returns the no-op enricher used by the standard cgo-free build.
func Default() Enricher { return noop{} }

type noop struct{}

func (noop) Enrich(context.Context, string) (json.RawMessage, error) { return nil, nil }
