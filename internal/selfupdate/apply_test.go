package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestSwapReplacesBinary verifies the atomic swap replaces the target's bytes.
func TestSwapReplacesBinary(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "gitc.exe")
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := swap(dest, []byte("NEW")); err != nil {
		t.Fatalf("swap: %v", err)
	}

	if got, _ := os.ReadFile(dest); string(got) != "NEW" {
		t.Errorf("dest = %q after swap, want NEW", got)
	}
}

// TestApplyVerifiesBeforeSwap (H-34/COV-3): Apply installs only verified bytes —
// a matching checksum swaps the binary; a mismatch fails and leaves dest intact.
func TestApplyVerifiesBeforeSwap(t *testing.T) {
	newBin := []byte("the new gitc binary bytes")
	sum := sha256.Sum256(newBin)
	name := "gitc_test_amd64"

	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newBin) })
	mux.HandleFunc("/good", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + name + "\n"))
	})
	mux.HandleFunc("/bad", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("deadbeef00000000000000000000000000000000000000000000000000000000  " + name + "\n"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "gitc.exe")

	// Matching checksum -> the binary is installed.
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}

	good := Asset{Name: name, URL: srv.URL + "/bin", Size: int64(len(newBin)), ChecksumsURL: srv.URL + "/good"}
	if err := Apply(context.Background(), good, dest); err != nil {
		t.Fatalf("Apply with a valid checksum: %v", err)
	}

	if got, _ := os.ReadFile(dest); string(got) != string(newBin) {
		t.Errorf("dest not updated to the verified binary: %q", got)
	}

	// Mismatched checksum -> Apply fails and the swap never happens.
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}

	bad := Asset{Name: name, URL: srv.URL + "/bin", Size: int64(len(newBin)), ChecksumsURL: srv.URL + "/bad"}
	if err := Apply(context.Background(), bad, dest); err == nil {
		t.Fatal("Apply must fail on a checksum mismatch")
	}

	if got, _ := os.ReadFile(dest); string(got) != "OLD" {
		t.Errorf("dest was overwritten despite the checksum mismatch: %q", got)
	}
}

// TestApplyRefusesWithoutChecksums confirms Apply fails closed when the release
// has no checksums manifest to verify against.
func TestApplyRefusesWithoutChecksums(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "gitc.exe")
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}

	a := Asset{Name: "gitc_test", URL: srv.URL, Size: int64(len("payload"))}
	if err := Apply(context.Background(), a, dest); err == nil {
		t.Fatal("Apply must refuse when there is no checksums manifest")
	}

	if got, _ := os.ReadFile(dest); string(got) != "OLD" {
		t.Errorf("dest overwritten without verification: %q", got)
	}
}
