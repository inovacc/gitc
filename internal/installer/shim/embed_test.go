package shim

import (
	"bytes"
	"testing"
)

func TestBinaryForArch(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		b := Binary(arch)
		if len(b) == 0 {
			t.Errorf("Binary(%q) is empty; the launcher must be embedded", arch)
		}

		// The vendored shim is a PE executable — sanity-check the MZ magic so a
		// truncated or wrong-format embed is caught.
		if !bytes.HasPrefix(b, []byte("MZ")) {
			t.Errorf("Binary(%q) is not a PE executable (missing MZ header)", arch)
		}
	}

	if Binary("mips") != nil {
		t.Error("Binary should return nil for an arch with no prebuilt launcher")
	}
}
