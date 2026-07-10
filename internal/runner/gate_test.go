package runner

import (
	"context"
	"io"
	"testing"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/shortcut"
)

// TestGuardBlocksPassthrough verifies the enforcement gate runs before a
// passthrough git vector and blocks it (git is never reached).
func TestGuardBlocksPassthrough(t *testing.T) {
	r := New(backend.Backend{}, nil, nil, io.Discard)

	var seen [][]string

	r.Guard(func(_ context.Context, args []string) (int, bool) {
		seen = append(seen, args)
		return 7, true // block everything
	})

	if code := r.Passthrough(context.Background(), []string{"push", "origin"}); code != 7 {
		t.Fatalf("blocked passthrough should return the gate's code 7, got %d", code)
	}

	if len(seen) != 1 || seen[0][0] != "push" {
		t.Fatalf("gate should see exactly the push vector, got %v", seen)
	}
}

// TestGuardGatesShortcutSteps is the SEC-1/H-25 regression: a built-in
// shortcut's push step must funnel through the same gate as passthrough, so a
// shortcut cannot bypass the policy. The step is blocked before any backend run.
func TestGuardGatesShortcutSteps(t *testing.T) {
	push := shortcut.Shortcut{
		Name:  "danger",
		Steps: func([]string) [][]string { return [][]string{{"push", "origin", "main"}} },
	}

	r := New(backend.Backend{}, nil, nil, io.Discard)

	var seen [][]string

	r.Guard(func(_ context.Context, args []string) (int, bool) {
		seen = append(seen, args)
		return 9, true
	})

	if code := r.Shortcut(context.Background(), push, nil); code != 9 {
		t.Fatalf("blocked shortcut push step should return the gate's code 9, got %d", code)
	}

	if len(seen) != 1 || seen[0][0] != "push" {
		t.Fatalf("gate should see the shortcut's push step, got %v", seen)
	}
}

// TestUnguardedRunnerStillWorks confirms a runner without Guard does not panic
// on the gate path (nil gate is skipped). It cannot reach a real backend here,
// so we only assert the gate is optional by constructing and inspecting it.
func TestUnguardedRunnerHasNoGate(t *testing.T) {
	r := New(backend.Backend{}, nil, nil, io.Discard)
	if r.gate != nil {
		t.Error("a freshly constructed runner must be unguarded until Guard is called")
	}
}
