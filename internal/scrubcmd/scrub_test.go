package scrubcmd

import (
	"context"
	"testing"

	"github.com/inovacc/gitc/internal/filterrepo"
)

func TestParseScrubFlags(t *testing.T) {
	fl, err := parseScrubFlags([]string{flagPath, "a", flagPath, "b", "--invert-paths", "--force"})
	if err != nil {
		t.Fatal(err)
	}

	if len(fl.paths) != 2 || fl.paths[0] != "a" || fl.paths[1] != "b" {
		t.Errorf("paths = %v, want [a b]", fl.paths)
	}

	if !fl.invertPaths || !fl.force {
		t.Error("invertPaths and force should be set")
	}

	if fl.prune != "auto" {
		t.Errorf("default prune = %q, want auto", fl.prune)
	}
}

func TestParseScrubFlagsErrors(t *testing.T) {
	if _, err := parseScrubFlags([]string{"--unknown"}); err == nil {
		t.Error("unknown flag should error")
	}

	if _, err := parseScrubFlags([]string{"--path"}); err == nil {
		t.Error("a value flag without a value should error")
	}
}

func TestParsePruneMode(t *testing.T) {
	cases := map[string]filterrepo.PruneMode{
		"":       filterrepo.PruneAuto,
		"auto":   filterrepo.PruneAuto,
		"always": filterrepo.PruneAlways,
		"never":  filterrepo.PruneNever,
	}

	for in, want := range cases {
		got, err := parsePruneMode(in)
		if err != nil || got != want {
			t.Errorf("parsePruneMode(%q) = (%v,%v), want (%v,nil)", in, got, err, want)
		}
	}

	if _, err := parsePruneMode("bogus"); err == nil {
		t.Error("an invalid prune value should error")
	}
}

func TestRunFlagErrors(t *testing.T) {
	// Flag-parse failures exit 2 before any backend resolution.
	if code := Run(context.Background(), []string{"--unknown"}); code != 2 {
		t.Errorf("unknown flag exit = %d, want 2", code)
	}

	if code := Run(context.Background(), []string{"--prune", "bogus"}); code != 2 {
		t.Errorf("bad --prune exit = %d, want 2", code)
	}
}
