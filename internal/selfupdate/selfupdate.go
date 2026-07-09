// Package selfupdate checks the gitc GitHub releases for a newer version and
// replaces the running binary in place. It downloads the release asset matching
// the current GOOS/GOARCH (the goreleaser naming gitc_<os>_<arch>[.exe]) and
// swaps it over the current executable using the rename-then-write trick, which
// works even on Windows where a running .exe cannot be overwritten directly.
package selfupdate

import (
	"context"
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
)

// releasesAPI is the GitHub "latest release" endpoint for the gitc repo.
const releasesAPI = "https://api.github.com/repos/inovacc/gitc/releases/latest"

// httpTimeout bounds both the metadata query and the asset download.
const httpTimeout = 2 * time.Minute

// Asset is a downloadable release binary for one platform.
type Asset struct {
	Name string
	URL  string
	Size int64
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
	for _, a := range rel.Assets {
		if a.Name == want {
			info.Asset = Asset{Name: a.Name, URL: a.URL, Size: a.Size}
			break
		}
	}

	info.HasUpdate = current != "dev" && isNewer(info.Latest, current)

	return info, nil
}

// Apply downloads asset and replaces the executable at dest with it.
func Apply(ctx context.Context, asset Asset, dest string) error {
	if asset.URL == "" {
		return fmt.Errorf("no release asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	data, err := download(ctx, asset.URL)
	if err != nil {
		return err
	}

	return swap(dest, data)
}

// latestRelease fetches and decodes the latest release metadata.
func latestRelease(ctx context.Context) (ghRelease, error) {
	var rel ghRelease

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI, nil)
	if err != nil {
		return rel, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("User-Agent", "gitc-selfupdate")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rel, fmt.Errorf("query releases: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("query releases: unexpected status %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return rel, fmt.Errorf("decode release: %w", err)
	}

	return rel, nil
}

// download fetches url (following redirects) and returns its bytes.
func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("User-Agent", "gitc-selfupdate")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: unexpected status %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return data, nil
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
