package runner

import (
	"strings"
	"testing"
)

// TestCaptureEnvRedactsCredentials is the SEC-8/H-35 regression: a GIT_ var that
// carries an Authorization token (as GIT_CONFIG_PARAMETERS does for a
// `-c http.extraHeader=...` override) must be masked before it reaches the
// audit DB, not stored raw.
func TestCaptureEnvRedactsCredentials(t *testing.T) {
	t.Setenv("GIT_CONFIG_PARAMETERS", "'http.extraHeader=Authorization: Bearer SECRETTOKEN123'")

	v := captureEnv()["GIT_CONFIG_PARAMETERS"]
	if strings.Contains(v, "SECRETTOKEN123") {
		t.Errorf("Authorization token must be masked in captured env, got %q", v)
	}

	if !strings.Contains(v, "***") {
		t.Errorf("expected a mask marker in the captured value, got %q", v)
	}
}

// TestCaptureEnvRedactsURLUserinfo covers a credential embedded as URL userinfo.
func TestCaptureEnvRedactsURLUserinfo(t *testing.T) {
	t.Setenv("GIT_MIRROR", "https://user:hunter2@example.com/repo.git")

	v := captureEnv()["GIT_MIRROR"]
	if strings.Contains(v, "hunter2") {
		t.Errorf("URL password must be masked, got %q", v)
	}
}
