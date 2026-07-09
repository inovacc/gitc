package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsNewer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.3.0", "0.2.0", true},
		{"v0.2.0", "0.3.0-dev", false}, // older tag must not update a newer dev build
		{"v0.2.0", "0.2.0", false},     // equal
		{"v1.0.0", "0.9.9", true},
		{"v0.2.1", "v0.2.0", true},
		{"0.2.0", "0.2.0-rc1", false}, // same triple: pre-release is not "newer"
	}

	for _, c := range cases {
		if got := isNewer(c.latest, c.current); got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestExpectedSHA(t *testing.T) {
	t.Parallel()

	manifest := []byte("abc123  gitc_linux_amd64\ndef456  gitc_windows_amd64.exe\n")

	if sum, ok := expectedSHA(manifest, "gitc_windows_amd64.exe"); !ok || sum != "def456" {
		t.Errorf("expectedSHA hit = %q,%v; want def456,true", sum, ok)
	}

	if _, ok := expectedSHA(manifest, "gitc_darwin_arm64"); ok {
		t.Error("expectedSHA should miss on an unlisted asset")
	}
}

func TestGetBodyRetriesThenSucceeds(t *testing.T) {
	t.Parallel()

	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++

		if calls < maxAttempts {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	body, err := getBody(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("getBody after transient 5xx: %v", err)
	}

	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}

	if calls != maxAttempts {
		t.Errorf("expected %d attempts, got %d", maxAttempts, calls)
	}
}

func TestGetBodyTerminalOn4xx(t *testing.T) {
	t.Parallel()

	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := getBody(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected an error on 404")
	}

	if calls != 1 {
		t.Errorf("4xx must not retry: got %d calls, want 1", calls)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	data := []byte("fake gitc binary contents")
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])

	serve := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, body)
		}))
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		srv := serve(good + "  gitc_test\n")
		defer srv.Close()

		a := Asset{Name: "gitc_test", Size: int64(len(data)), ChecksumsURL: srv.URL}
		if err := verify(context.Background(), a, data); err != nil {
			t.Fatalf("verify valid asset: %v", err)
		}
	})

	t.Run("sha mismatch", func(t *testing.T) {
		t.Parallel()

		srv := serve("deadbeef  gitc_test\n")
		defer srv.Close()

		a := Asset{Name: "gitc_test", Size: int64(len(data)), ChecksumsURL: srv.URL}
		if err := verify(context.Background(), a, data); err == nil {
			t.Fatal("verify should reject a digest mismatch")
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		t.Parallel()

		a := Asset{Name: "gitc_test", Size: 999, ChecksumsURL: "http://unused"}
		if err := verify(context.Background(), a, data); err == nil {
			t.Fatal("verify should reject a size mismatch")
		}
	})

	t.Run("no checksums manifest", func(t *testing.T) {
		t.Parallel()

		a := Asset{Name: "gitc_test", Size: int64(len(data))}
		if err := verify(context.Background(), a, data); err == nil {
			t.Fatal("verify should refuse when no checksums.txt is available")
		}
	})

	t.Run("asset not listed", func(t *testing.T) {
		t.Parallel()

		srv := serve(good + "  some_other_file\n")
		defer srv.Close()

		a := Asset{Name: "gitc_test", Size: int64(len(data)), ChecksumsURL: srv.URL}
		if err := verify(context.Background(), a, data); err == nil {
			t.Fatal("verify should refuse when the asset is absent from checksums.txt")
		}
	})
}
