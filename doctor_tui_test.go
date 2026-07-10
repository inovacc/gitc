package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func sampleResults() []checkResult {
	return []checkResult{
		{status: statusOK, label: "gitc version", detail: "v9.9.9"},
		{status: statusWarn, label: "shim installed", detail: "not found; run `git install --apply`"},
		{status: statusFail, label: "git backend", detail: "no git backend found"},
	}
}

func TestDoctorModelNavigationAndView(t *testing.T) {
	m := doctorModel{results: sampleResults(), worst: statusFail}

	// Give it a size so View renders the body rather than the loading string.
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	m = updated.(doctorModel)

	if strings.Contains(m.View(), "loading") {
		t.Fatal("View should render after a WindowSizeMsg")
	}

	// Down moves the cursor; up at top and down at bottom must clamp.
	for i := 0; i < 5; i++ {
		u, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = u.(doctorModel)
	}

	if m.cursor != len(m.results)-1 {
		t.Errorf("cursor should clamp at last item, got %d", m.cursor)
	}

	// The detail pane must show the selected (last) check's detail.
	if !strings.Contains(m.View(), "no git backend found") {
		t.Error("detail pane should show the selected check's detail")
	}

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyHome})
	m = u.(doctorModel)

	if m.cursor != 0 {
		t.Errorf("home should move cursor to 0, got %d", m.cursor)
	}
}

func TestDoctorModelQuit(t *testing.T) {
	m := doctorModel{results: sampleResults()}

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should return a command")
	}

	if msg := cmd(); msg != tea.Quit() {
		t.Error("q should issue tea.Quit")
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := map[checkStatus]int{statusOK: 0, statusWarn: 0, statusFail: 1}
	for s, want := range cases {
		if got := exitCodeFor(s); got != want {
			t.Errorf("exitCodeFor(%v) = %d, want %d", s, got, want)
		}
	}
}

func TestHasFlag(t *testing.T) {
	args := []string{"--wide", "--plain"}
	if !hasFlag(args, "--plain") {
		t.Error("--plain should be detected")
	}

	if hasFlag(args, "--json") {
		t.Error("--json is not present")
	}
}
