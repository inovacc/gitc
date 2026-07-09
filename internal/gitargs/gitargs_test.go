package gitargs

import "testing"

func TestSubcommandIndex(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"empty", nil, -1},
		{"plain subcommand", []string{"status"}, 0},
		{"value global -c", []string{"-c", "x=y", "status"}, 2},
		{"value global -C", []string{"-C", "dir", "init"}, 2},
		{"boolean global --paginate", []string{"--paginate", "log"}, 1},
		{"stacked globals", []string{"-c", "a=b", "-C", "dir", "commit"}, 4},
		{"only globals, no subcommand", []string{"-c", "x=y"}, -1},
		{"double dash then token", []string{"--", "weird"}, 1},
		{"double dash at end", []string{"-c", "x=y", "--"}, -1},
		{"long value global --git-dir", []string{"--git-dir", "/g", "status"}, 2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got := SubcommandIndex(c.args); got != c.want {
				t.Errorf("SubcommandIndex(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}
