package installer

import "testing"

func TestPrependPathValue(t *testing.T) {
	cases := []struct {
		name        string
		userPath    string
		dir         string
		wantResult  string
		wantChanged bool
	}{
		{"empty", "", `C:\gitc\shim`, `C:\gitc\shim`, true},
		{"prepend", `C:\other`, `C:\gitc\shim`, `C:\gitc\shim;C:\other`, true},
		{"already first", `C:\gitc\shim;C:\other`, `C:\gitc\shim`, `C:\gitc\shim;C:\other`, false},
		{"already later", `C:\other;C:\gitc\shim`, `C:\gitc\shim`, `C:\other;C:\gitc\shim`, false},
		{"substring not matched", `C:\gitc\shimX`, `C:\gitc\shim`, `C:\gitc\shim;C:\gitc\shimX`, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, changed := prependPathValue(c.userPath, c.dir)
			if got != c.wantResult || changed != c.wantChanged {
				t.Errorf("prependPathValue(%q,%q) = (%q,%v), want (%q,%v)",
					c.userPath, c.dir, got, changed, c.wantResult, c.wantChanged)
			}
		})
	}
}
