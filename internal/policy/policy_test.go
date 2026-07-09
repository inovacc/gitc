package policy

import (
	"strings"
	"testing"
)

func TestInitNeedsBranch(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantOK  bool
		wantIdx int
	}{
		{"plain init", []string{"init"}, true, 0},
		{"init with path", []string{"init", "myrepo"}, true, 0},
		{"init bare", []string{"init", "--bare"}, true, 0},
		{"global -C before init", []string{"-C", "/tmp/x", "init"}, true, 2},
		{"global -c before init", []string{"-c", "core.x=1", "init"}, true, 2},
		{"double dash then init", []string{"--", "init"}, true, 1},
		{"explicit -b skips", []string{"init", "-b", "trunk"}, false, 0},
		{"explicit --initial-branch skips", []string{"init", "--initial-branch", "dev"}, false, 0},
		{"explicit --initial-branch= skips", []string{"init", "--initial-branch=dev"}, false, 0},
		{"not init", []string{"status"}, false, 0},
		{"clone is not init", []string{"clone", "url"}, false, 0},
		{"empty", nil, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, ok := InitNeedsBranch(tt.args)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}

			if ok && idx != tt.wantIdx {
				t.Fatalf("idx = %d, want %d", idx, tt.wantIdx)
			}
		})
	}
}

func TestInjectInitialBranch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		idx  int
		want string
	}{
		{"plain", []string{"init"}, 0, "init --initial-branch=main"},
		{"with path", []string{"init", "repo"}, 0, "init --initial-branch=main repo"},
		{"with global", []string{"-C", "/x", "init"}, 2, "-C /x init --initial-branch=main"},
		{"bare preserved", []string{"init", "--bare"}, 0, "init --initial-branch=main --bare"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(InjectInitialBranch(tt.args, tt.idx, "main"), " ")
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
