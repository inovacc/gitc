// Package selfupdate checks the gitc GitHub releases for a newer version and
// replaces the running binary in place. It downloads the release asset matching
// the current GOOS/GOARCH (the goreleaser naming gitc_<os>_<arch>[.exe]) and
// swaps it over the current executable using the rename-then-write trick, which
// works even on Windows where a running .exe cannot be overwritten directly.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/gitc/internal/origin"
)

// checksumsName is the goreleaser checksums manifest published alongside the
// release binaries; Apply verifies the downloaded binary against it.
const checksumsName = "checksums.txt"

// httpTimeout bounds both the metadata query and the asset download.
const httpTimeout = 2 * time.Minute

// maxAttempts and retryBackoff bound the retry of transient network failures.
const (
	maxAttempts  = 3
	retryBackoff = 300 * time.Millisecond
)

// Asset is a downloadable release binary for one platform.
type Asset struct {
	Name string
	URL  string
	Size int64
	// ChecksumsURL is the release's checksums.txt asset, used by Apply to
	// verify the downloaded binary's SHA-256 before installing it.
	ChecksumsURL string
}

// Info is the result of a version check.
type Info struct {
	Current   string
	Latest    string
	HasUpdate bool
	Asset     Asset // the asset for this GOOS/GOARCH; zero if none matched
}

// ghRelease is the subset of the GitHub release payload we consume.
type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// AssetName is the goreleaser asset name for this platform.
func AssetName() string {
	name := fmt.Sprintf("gitc_%s_%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	return name
}

// Check queries the latest release and reports whether it is newer than current.
func Check(ctx context.Context, current string) (Info, error) {
	info := Info{Current: current}

	rel, err := latestRelease(ctx)
	if err != nil {
		return info, err
	}

	info.Latest = rel.TagName

	want := AssetName()

	var checksumsURL string

	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			info.Asset = Asset{Name: a.Name, URL: a.URL, Size: a.Size}
		case checksumsName:
			checksumsURL = a.URL
		}
	}

	info.Asset.ChecksumsURL = checksumsURL
	info.HasUpdate = current != "dev" && isNewer(info.Latest, current)

	return info, nil
}

// Apply downloads asset, verifies its SHA-256 (and size) against the release
// checksums manifest, then replaces the executable at dest with it. A binary
// that cannot be verified is never installed — a compromised or truncated asset
// must not become the user's git.
func Apply(ctx context.Context, asset Asset, dest string) error {
	if asset.URL == "" {
		return fmt.Errorf("no release asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	data, err := download(ctx, asset.URL)
	if err != nil {
		return err
	}

	if err := verify(ctx, asset, data); err != nil {
		return err
	}

	return swap(dest, data)
}

// verify checks the downloaded bytes against the expected size and the SHA-256
// recorded in the release checksums.txt. It refuses (never installs) when the
// checksums manifest is missing or the digest does not match.
func verify(ctx context.Context, asset Asset, data []byte) error {
	if asset.Size > 0 && int64(len(data)) != asset.Size {
		return fmt.Errorf("size mismatch: got %d bytes, release lists %d", len(data), asset.Size)
	}

	if asset.ChecksumsURL == "" {
		return fmt.Errorf("cannot verify %s: release has no %s", asset.Name, checksumsName)
	}

	manifest, err := download(ctx, asset.ChecksumsURL)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}

	want, ok := expectedSHA(manifest, asset.Name)
	if !ok {
		return fmt.Errorf("%s not listed in %s", asset.Name, checksumsName)
	}

	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", asset.Name, got, want)
	}

	return nil
}

// expectedSHA parses a goreleaser checksums.txt ("<hex>  <name>" per line) and
// returns the digest recorded for name.
func expectedSHA(manifest []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == name {
			return fields[0], true
		}
	}

	return "", false
}

// latestRelease fetches and decodes the latest release metadata. The endpoint
// derives from the sha256-pinned gitc repository URL (origin), which is verified
// before any request is made.
func latestRelease(ctx context.Context) (ghRelease, error) {
	var rel ghRelease

	base, err := origin.APIBase(origin.GitcRepo)
	if err != nil {
		return rel, err
	}

	body, err := getBody(ctx, base+"/releases/latest", "application/vnd.github+json")
	if err != nil {
		return rel, fmt.Errorf("query releases: %w", err)
	}

	if err := json.Unmarshal(body, &rel); err != nil {
		return rel, fmt.Errorf("decode release: %w", err)
	}

	return rel, nil
}

// download fetches url (following redirects) and returns its bytes.
func download(ctx context.Context, url string) ([]byte, error) {
	return getBody(ctx, url, "")
}

// getBody performs a GET (bounded by httpTimeout) with a small retry/backoff on
// transient failures — network errors and 5xx responses — so a single dropped
// connection or hiccup during a release query or download does not fail the
// whole operation. 4xx responses and read errors are terminal.
func getBody(ctx context.Context, url, accept string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, retryable, err := getBodyOnce(ctx, url, accept)
		if err == nil {
			return body, nil
		}

		lastErr = err
		if !retryable || attempt == maxAttempts {
			return nil, lastErr
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * retryBackoff):
		}
	}

	return nil, lastErr
}

// getBodyOnce performs a single GET. retryable reports whether a failure is
// worth retrying (network error or 5xx); 4xx and read/build errors are terminal.
func getBodyOnce(ctx context.Context, url, accept string) (body []byte, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("User-Agent", "gitc-selfupdate")

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("http get: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= http.StatusInternalServerError, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, fmt.Errorf("read body: %w", err)
	}

	return body, false, nil
}

// swap replaces dest with data via rename-then-write, so it works while dest is
// the running executable (a running .exe can be renamed but not overwritten).
func swap(dest string, data []byte) error {
	dir := filepath.Dir(dest)

	tmp, err := os.CreateTemp(dir, ".gitc-update-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return fmt.Errorf("write temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp: %w", err)
	}

	old := dest + ".old"
	_ = os.Remove(old)

	// Move the running binary aside so its path is free, then move the new one in.
	if err := os.Rename(dest, old); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("move current binary aside: %w", err)
	}

	if err := os.Rename(tmpName, dest); err != nil {
		// Best-effort rollback so the tool is not left without a binary.
		_ = os.Rename(old, dest)
		_ = os.Remove(tmpName)

		return fmt.Errorf("install new binary: %w", err)
	}

	// The old binary is still running (Windows keeps it locked); remove best-effort.
	_ = os.Remove(old)

	return nil
}

// isNewer reports whether latest is a strictly higher release than current,
// comparing MAJOR.MINOR.PATCH numerically. A pre-release suffix (e.g. -dev) is
// ignored, so a dev build of the same version is never offered an "update" to an
// equal or older tagged release.
func isNewer(latest, current string) bool {
	lt := parseTriple(latest)
	ct := parseTriple(current)

	for i := range lt {
		if lt[i] != ct[i] {
			return lt[i] > ct[i]
		}
	}

	return false
}

// parseTriple extracts [major, minor, patch] from a version string like
// "v0.3.0" or "0.3.0-dev"; missing or non-numeric fields default to 0.
func parseTriple(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")

	// Drop any pre-release/build metadata after the numeric core.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}

	var out [3]int

	for i, part := range strings.SplitN(v, ".", 3) {
		if i >= len(out) {
			break
		}

		n, err := strconv.Atoi(part)
		if err != nil {
			return out
		}

		out[i] = n
	}

	return out
}
