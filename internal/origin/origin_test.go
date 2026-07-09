package origin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// wantHashes is an INDEPENDENT record of the expected digests. It duplicates the
// package constants on purpose: tampering with a pinned URL now requires editing
// the constant, its sha256 constant, AND this table — CI fails otherwise.
var wantHashes = map[string]string{
	"https://github.com/inovacc/gitc":        "73f5c1a10b1e134ff8b44857a065e51e5cec7af976ce157c155daf124ed1eab7",
	"https://github.com/git-for-windows/git": "e83ef8ed2fa5ca9e95eb11db22eea2ffcfce65cdde1f92ee5b552dd9c9dc05c9",
}

func TestPinsMatchIndependentRecord(t *testing.T) {
	t.Parallel()

	if GitcRepoSHA256 != wantHashes[GitcRepo] {
		t.Errorf("GitcRepoSHA256 drifted from the independent record")
	}

	if GitForWindowsRepoSHA256 != wantHashes[GitForWindowsRepo] {
		t.Errorf("GitForWindowsRepoSHA256 drifted from the independent record")
	}

	for url, want := range wantHashes {
		sum := sha256.Sum256([]byte(url))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("sha256(%q) = %s, want %s", url, got, want)
		}
	}
}

func TestVerifyPasses(t *testing.T) {
	t.Parallel()

	if err := Verify(); err != nil {
		t.Fatalf("Verify on unmodified pins: %v", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	t.Parallel()

	// A swapped URL kept against the old digest — exactly the supply-chain edit
	// the pin exists to catch. Uses the internal verify() so no global is mutated.
	tampered := []pin{{"https://github.com/evil/redirect", GitcRepoSHA256}}

	if err := verify(tampered); !errors.Is(err, ErrTampered) {
		t.Fatalf("verify should return ErrTampered on a swapped URL, got %v", err)
	}
}

func TestAPIBase(t *testing.T) {
	t.Parallel()

	got, err := APIBase(GitcRepo)
	if err != nil {
		t.Fatalf("APIBase: %v", err)
	}

	if got != "https://api.github.com/repos/inovacc/gitc" {
		t.Errorf("APIBase(GitcRepo) = %q", got)
	}

	if _, err := APIBase("https://github.com/someone/else"); err == nil {
		t.Error("APIBase must reject a non-pinned repository")
	}
}
