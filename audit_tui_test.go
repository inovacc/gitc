package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/inovacc/gitc/internal/store"
)

func auditRows() []store.AuditRow {
	return []store.AuditRow{
		{ID: 3, TS: "2026-07-10T06:00:00Z", OSUser: "dev", Mode: "passthrough", Argv: `["status"]`, Exit: 0},
		{ID: 2, TS: "2026-07-10T06:01:00Z", OSUser: "dev", Mode: "blocked", Argv: `["push","evil"]`, Exit: 1},
		{ID: 1, TS: "2026-07-10T06:02:00Z", OSUser: "dev", Mode: "passthrough", Argv: `["commit","-m","x"]`, Exit: 2},
	}
}

func TestAuditModelNavigateAndFilter(t *testing.T) {
	m := newAuditModel(auditRows())

	if len(m.visible) != 3 {
		t.Fatalf("all rows visible initially, got %d", len(m.visible))
	}

	u, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	m = u.(auditModel)

	if strings.Contains(m.View(), "loading") {
		t.Fatal("View should render after a size message")
	}

	// The blocked row's detail must show BLOCKED and its command.
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = u.(auditModel)

	if !strings.Contains(m.vp.View(), "push evil") {
		t.Errorf("detail pane should show the selected row's command, got %q", m.vp.View())
	}

	// Filtering narrows the visible set.
	m.search.SetValue("commit")
	m.applyFilter()

	if len(m.visible) != 1 {
		t.Errorf("filter \"commit\" should match one row, got %d", len(m.visible))
	}
}

func TestAuditStatus(t *testing.T) {
	rows := auditRows()

	if !strings.Contains(status(rows[1]), "BLOCKED") {
		t.Error("a blocked row must render BLOCKED")
	}

	if !strings.Contains(status(rows[2]), "exit=2") {
		t.Error("a failed row must render its exit code")
	}

	if !strings.Contains(status(rows[0]), "ok") {
		t.Error("a successful row must render ok")
	}
}

func TestAuditRowCommand(t *testing.T) {
	r := store.AuditRow{Argv: `["push","origin","main"]`}
	if got := r.Command(); got != "push origin main" {
		t.Errorf("Command() = %q, want \"push origin main\"", got)
	}

	if r.Blocked() {
		t.Error("a passthrough row must not report Blocked")
	}

	if !(store.AuditRow{Mode: "blocked"}).Blocked() {
		t.Error("a blocked-mode row must report Blocked")
	}
}
