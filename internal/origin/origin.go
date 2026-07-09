// Package origin pins the upstream repository URLs gitc is allowed to talk to
// and guards each with a sha256 of its URL string.
//
// The URLs are compile-time constants (no runtime override, no env var, no
// config) and every network path derives its GitHub API endpoint from them and
// nowhere else. Verify recomputes each URL's digest and refuses to proceed on a
// mismatch, so a supply-chain edit that redirects a URL cannot pass silently: an
// attacker must change the URL, its pinned digest here, AND the independent
// expectation asserted in origin_test.go — each edit more evident than the last,
// and CI fails on the test. This is tamper-evidence and fail-closed behavior,
// not a claim that source cannot be edited.
package origin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// GitcRepo is the canonical gitc repository. Self-update endpoints derive
	// from this constant only.
	GitcRepo = "https://github.com/inovacc/gitc"
	// GitcRepoSHA256 is sha256(GitcRepo), enforced by Verify.
	GitcRepoSHA256 = "73f5c1a10b1e134ff8b44857a065e51e5cec7af976ce157c155daf124ed1eab7"

	// GitForWindowsRepo is the upstream MinGit source repository.
	GitForWindowsRepo = "https://github.com/git-for-windows/git"
	// GitForWindowsRepoSHA256 is sha256(GitForWindowsRepo), enforced by Verify.
	GitForWindowsRepoSHA256 = "e83ef8ed2fa5ca9e95eb11db22eea2ffcfce65cdde1f92ee5b552dd9c9dc05c9"
)

// githubPrefix is the only host gitc's pinned repositories may live under.
const githubPrefix = "https://github.com/"

// ErrTampered is returned when a pinned URL does not match its recorded digest.
var ErrTampered = errors.New("origin: pinned repository URL failed its sha256 integrity check")

// pin pairs a URL constant with its expected digest.
type pin struct {
	url    string
	sha256 string
}

var pins = []pin{
	{GitcRepo, GitcRepoSHA256},
	{GitForWindowsRepo, GitForWindowsRepoSHA256},
}

// Verify recomputes every pinned URL's sha256 and returns ErrTampered on any
// mismatch. Call it before any network operation that uses a pinned URL.
func Verify() error {
	return verify(pins)
}

// verify checks an explicit pin set (kept separate so tests can exercise a
// tampered set without mutating the package global).
func verify(ps []pin) error {
	for _, p := range ps {
		sum := sha256.Sum256([]byte(p.url))
		if got := hex.EncodeToString(sum[:]); got != p.sha256 {
			return fmt.Errorf("%w: %s (got %s, want %s)", ErrTampered, p.url, got, p.sha256)
		}
	}

	return nil
}

// APIBase verifies all pins and returns the GitHub REST base for repoURL,
// "https://api.github.com/repos/<owner>/<repo>". repoURL must be one of the
// pinned constants; anything else is rejected.
func APIBase(repoURL string) (string, error) {
	if err := Verify(); err != nil {
		return "", err
	}

	if !isPinned(repoURL) {
		return "", fmt.Errorf("origin: %q is not a pinned repository", repoURL)
	}

	return "https://api.github.com/repos/" + strings.TrimPrefix(repoURL, githubPrefix), nil
}

// isPinned reports whether repoURL is exactly one of the pinned constants.
func isPinned(repoURL string) bool {
	for _, p := range pins {
		if p.url == repoURL {
			return true
		}
	}

	return false
}
