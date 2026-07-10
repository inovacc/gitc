package shortcut

import (
	"reflect"
	"testing"
)

func byName(t *testing.T) map[string]Shortcut {
	t.Helper()

	m := map[string]Shortcut{}
	for _, s := range All() {
		m[s.Name] = s
	}

	return m
}

func TestShortcutSteps(t *testing.T) {
	t.Parallel()

	sc := byName(t)

	cases := []struct {
		name string
		args []string
		want [][]string
	}{
		{"sync", nil, [][]string{{"fetch", "--prune"}, {"rebase"}, {"push"}}},
		{"undo", nil, [][]string{{"reset", "--soft", "HEAD~1"}}},
		{"quick-commit", []string{"hello"}, [][]string{{"add", "-A"}, {"commit", "-m", "hello"}}},
	}

	for _, c := range cases {
		s, ok := sc[c.name]
		if !ok {
			t.Fatalf("shortcut %q missing", c.name)
		}

		if got := s.Steps(c.args); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s steps = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLogGraphAppendsArgs(t *testing.T) {
	t.Parallel()

	steps := byName(t)["log-graph"].Steps([]string{"-n", "5"})
	if len(steps) != 1 {
		t.Fatalf("log-graph should be one step, got %v", steps)
	}

	last := steps[0]
	if last[len(last)-1] != "5" || last[0] != "log" {
		t.Errorf("log-graph did not build the expected vector: %v", last)
	}
}

func TestQuickCommitRequiresMessage(t *testing.T) {
	t.Parallel()

	if byName(t)["quick-commit"].MinArgs != 1 {
		t.Error("quick-commit should require a message argument")
	}
}
