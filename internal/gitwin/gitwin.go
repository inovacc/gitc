// Package gitwin provisions a git backend on Windows by downloading a prebuilt
// MinGit distribution from the git-for-windows/git GitHub releases and
// unpacking it — instead of building git from source.
//
// MinGit is git-for-windows' minimal, redistributable git as a plain .zip,
// intended for applications to bundle. gitwin queries a release, selects the
// MinGit asset matching the CPU architecture, downloads it, and extracts it to
// a cache directory, returning the path to the resulting git executable.
//
// It targets Windows (git-for-windows is Windows-only); other platforms use the
// system git.
package gitwin

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/gitc/internal/origin"
)

// releasesBase returns the git-for-windows/git releases endpoint, derived from
// the sha256-pinned repository URL (origin) and verified before every use.
func releasesBase() (string, error) {
	base, err := origin.APIBase(origin.GitForWindowsRepo)
	if err != nil {
		return "", err
	}

	return base + "/releases", nil
}

// Asset is a downloadable release asset.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is a git-for-windows release.
type Release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

func httpDo(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// GitHub requires a User-Agent; an optional token raises the rate limit.
	req.Header.Set("User-Agent", "gitc")
	req.Header.Set("Accept", "application/vnd.github+json")

	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	return client.Do(req)
}

// Latest returns the latest non-prerelease git-for-windows release.
func Latest(ctx context.Context) (Release, error) {
	base, err := releasesBase()
	if err != nil {
		return Release{}, err
	}

	resp, err := httpDo(ctx, base+"/latest")
	if err != nil {
		return Release{}, fmt.Errorf("query latest release: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("query latest release: HTTP %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, fmt.Errorf("decode release: %w", err)
	}

	return rel, nil
}

// List returns up to n recent releases (newest first).
func List(ctx context.Context, n int) ([]Release, error) {
	if n <= 0 {
		n = 10
	}

	base, err := releasesBase()
	if err != nil {
		return nil, err
	}

	resp, err := httpDo(ctx, fmt.Sprintf("%s?per_page=%d", base, n))
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list releases: HTTP %d", resp.StatusCode)
	}

	var rels []Release
	if err := json.NewDecoder(resp.Body).Decode(&rels); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}

	return rels, nil
}

// archTag maps a Go GOARCH to the git-for-windows asset architecture token.
func archTag(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "64-bit", nil
	case "386":
		return "32-bit", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q for git-for-windows MinGit", goarch)
	}
}

// SelectMinGit picks the MinGit .zip asset matching goarch, preferring the
// standard build over the busybox variant.
func SelectMinGit(assets []Asset, goarch string) (Asset, error) {
	tag, err := archTag(goarch)
	if err != nil {
		return Asset{}, err
	}

	suffix := "-" + strings.ToLower(tag) + ".zip"

	var busybox Asset

	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if !strings.HasPrefix(n, "mingit-") || !strings.HasSuffix(n, suffix) {
			continue
		}

		if strings.Contains(n, "busybox") {
			busybox = a
			continue
		}

		return a, nil
	}

	if busybox.Name != "" {
		return busybox, nil
	}

	return Asset{}, fmt.Errorf("no MinGit .zip asset for %s (%s) in the release", goarch, tag)
}

// Download streams the asset URL to destFile.
func Download(ctx context.Context, url, destFile string) error {
	if err := os.MkdirAll(filepath.Dir(destFile), 0o755); err != nil {
		return err
	}

	resp, err := httpDo(ctx, url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destFile)
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return fmt.Errorf("write download: %w", err)
	}

	return f.Close()
}

// Unzip extracts the zip at src into destDir, guarding against path traversal.
func Unzip(src, destDir string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	cleanDest := filepath.Clean(destDir)
	for _, zf := range zr.File {
		target := filepath.Join(cleanDest, zf.Name)
		// Zip-slip guard: the target must stay within destDir.
		if !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) && target != cleanDest {
			return fmt.Errorf("unsafe path in zip: %q", zf.Name)
		}

		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}

			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		if err := extractFile(zf, target); err != nil {
			return err
		}
	}

	return nil
}

func extractFile(zf *zip.File, target string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, zf.Mode()|0o200)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, rc); err != nil { //nolint:gosec // release asset, bounded by disk
		_ = out.Close()
		return err
	}

	return out.Close()
}

// Ensure downloads and unpacks the MinGit build for goarch from rel into
// baseDir/<tag>/, and returns the path to the extracted git executable. If a
// git executable already exists there, it is returned without re-downloading.
func Ensure(ctx context.Context, rel Release, goarch, baseDir string) (string, error) {
	dest := filepath.Join(baseDir, sanitizeTag(rel.Tag))

	gitExe := filepath.Join(dest, "cmd", "git.exe")
	if _, err := os.Stat(gitExe); err == nil {
		return gitExe, nil
	}

	asset, err := SelectMinGit(rel.Assets, goarch)
	if err != nil {
		return "", err
	}

	tmp := dest + ".download.zip"
	if err := Download(ctx, asset.URL, tmp); err != nil {
		return "", err
	}

	defer func() { _ = os.Remove(tmp) }()

	if err := Unzip(tmp, dest); err != nil {
		return "", err
	}

	if _, err := os.Stat(gitExe); err != nil {
		return "", fmt.Errorf("unpacked MinGit but %s is missing: %w", gitExe, err)
	}

	return gitExe, nil
}

// sanitizeTag makes a release tag safe as a directory name.
func sanitizeTag(tag string) string {
	repl := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")

	s := repl.Replace(strings.TrimSpace(tag))
	if s == "" {
		return "latest"
	}

	return s
}
