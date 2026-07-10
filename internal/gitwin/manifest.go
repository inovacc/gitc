package gitwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ManifestAsset is a pinned, hash-verified git distribution for one platform.
type ManifestAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the pinned git-for-windows release recorded in git_release.json:
// per-platform asset URLs + sha256 hashes for a fixed version.
type Manifest struct {
	Version string                   `json:"version"`
	Source  string                   `json:"source"`
	Flavor  string                   `json:"flavor"`
	Assets  map[string]ManifestAsset `json:"assets"` // key = "GOOS/GOARCH"
}

// ParseManifest decodes git_release.json.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse git_release.json: %w", err)
	}

	return m, nil
}

// For returns the pinned asset for the given GOOS/GOARCH.
func (m Manifest) For(goos, goarch string) (ManifestAsset, bool) {
	a, ok := m.Assets[goos+"/"+goarch]
	return a, ok
}

// EnsurePinned downloads the pinned asset into baseDir/<version>/, verifies its
// sha256, unpacks it, and returns the git executable path. If a git executable
// is already present there, it is returned without re-downloading.
func (m Manifest) EnsurePinned(ctx context.Context, a ManifestAsset, baseDir string) (string, error) {
	dest := filepath.Join(baseDir, sanitizeTag(m.Version))

	gitExe := filepath.Join(dest, "cmd", "git.exe")
	if _, err := os.Stat(gitExe); err == nil {
		return gitExe, nil
	}

	tmp := dest + ".download"
	if err := Download(ctx, a.URL, tmp); err != nil {
		return "", err
	}

	defer func() { _ = os.Remove(tmp) }()

	if err := verifySHA256(tmp, a.SHA256); err != nil {
		return "", err
	}

	if err := extractArchive(a.Name, tmp, dest); err != nil {
		return "", err
	}

	if _, err := os.Stat(gitExe); err != nil {
		return "", fmt.Errorf("unpacked git but %s is missing: %w", gitExe, err)
	}

	return gitExe, nil
}

// extractArchive unpacks src into destDir, dispatching on the asset filename: a
// full-git .tar.bz2 tarball vs a MinGit .zip.
func extractArchive(name, src, destDir string) error {
	if strings.HasSuffix(strings.ToLower(name), ".tar.bz2") {
		return ExtractTarBz2(src, destDir)
	}

	return Unzip(src, destDir)
}

// verifySHA256 checks that file hashes to the expected hex digest.
func verifySHA256(file, want string) error {
	if want == "" {
		return fmt.Errorf("no sha256 pinned for asset")
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, want)
	}

	return nil
}
