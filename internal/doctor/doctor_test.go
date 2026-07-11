package doctor

import (
	"strings"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	if exitCodeFor(statusFail) != 1 {
		t.Error("a failed worst status must exit 1")
	}

	if exitCodeFor(statusOK) != 0 || exitCodeFor(statusWarn) != 0 {
		t.Error("ok/warn must exit 0")
	}
}

func TestSummaryLineAndBadge(t *testing.T) {
	for _, s := range []checkStatus{statusOK, statusWarn, statusFail} {
		if summaryLine(s) == "" {
			t.Errorf("summaryLine(%d) is empty", s)
		}

		if s.badge() == "" {
			t.Errorf("badge(%d) is empty", s)
		}
	}
}

func TestSamePath(t *testing.T) {
	if !samePath(`C:\gitc\shim\git.exe`, `C:\gitc\shim\git.exe`) {
		t.Error("identical paths must match")
	}

	// Case-insensitive on Windows; EqualFold makes this hold cross-platform for
	// the identical-modulo-case comparison used here.
	if !samePath(`C:\GITC\git.exe`, `C:\gitc\git.exe`) {
		t.Error("case-differing paths should match (EqualFold)")
	}

	if samePath(`C:\a\git.exe`, `C:\b\git.exe`) {
		t.Error("distinct paths must not match")
	}
}

func TestExitCodeForString(t *testing.T) {
	// summaryLine content sanity: the fail line should read as a failure.
	if !strings.Contains(strings.ToLower(summaryLine(statusFail)), "fail") {
		t.Error("fail summary should mention failure")
	}
}
