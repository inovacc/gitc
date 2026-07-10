package gitwin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPDoRetriesThenSucceeds(t *testing.T) {
	t.Parallel()

	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < maxAttempts {
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	resp, err := httpDo(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("httpDo after transient 5xx: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if calls != maxAttempts {
		t.Errorf("expected %d attempts, got %d", maxAttempts, calls)
	}
}

func TestHTTPDoDoesNotRetry4xx(t *testing.T) {
	t.Parallel()

	var calls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resp, err := httpDo(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("a 4xx should return the response, not an error: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound || calls != 1 {
		t.Errorf("4xx must be handled in one call: status=%d calls=%d", resp.StatusCode, calls)
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "zipbytes")
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "sub", "f.zip")
	if err := Download(context.Background(), srv.URL, dest); err != nil {
		t.Fatalf("Download: %v", err)
	}

	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != "zipbytes" {
		t.Errorf("downloaded content = %q", b)
	}
}
