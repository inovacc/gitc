package cmdtree

import "testing"

// TestRunModes exercises the command-tree renderer in its output modes; each
// must render without error (exit 0).
func TestRunModes(t *testing.T) {
	cases := [][]string{
		nil,             // default tree
		{"-b"},          // verbose
		{"--json"},      // JSON
		{"-c", "scan"},  // single-node lookup
		{"-c", "audit"}, // another node
	}

	for _, args := range cases {
		if code := Run(args); code != 0 {
			t.Errorf("Run(%v) = %d, want 0", args, code)
		}
	}
}

func TestRunUnknownFlag(t *testing.T) {
	if code := Run([]string{"--bogus"}); code == 0 {
		t.Error("an unknown flag should be a non-zero exit")
	}
}

func TestRunUnknownNode(t *testing.T) {
	// -c on a command that does not exist should not render a node as success.
	if code := Run([]string{"-c", "definitely-not-a-command"}); code == 0 {
		t.Error("an unknown node lookup should be non-zero")
	}
}
