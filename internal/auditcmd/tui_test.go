package auditcmd

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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

	// Selecting the blocked row (index 1) must show its command in the detail.
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = u.(auditModel)

	if !strings.Contains(m.detailView(), "push evil") {
		t.Errorf("detail pane should show the selected row's command:\n%s", m.detailView())
	}

	// The full view must not overflow the terminal — neither in height (rows) nor
	// width (each line ≤ terminal width). Overflow is what made the header and
	// detail pane scroll off in the original wrapping bug.
	view := m.View()
	if lines := strings.Count(view, "\n") + 1; lines > 24 {
		t.Errorf("rendered view is %d lines, exceeds terminal height 24 (wrapping?)", lines)
	}

	for _, ln := range strings.Split(view, "\n") {
		if w := lipgloss.Width(ln); w > 120 {
			t.Errorf("line width %d exceeds terminal width 120 (would wrap): %q", w, ln)
		}
	}

	// Filtering narrows the visible set.
	m.search.SetValue("commit")
	m.applyFilter()

	if len(m.visible) != 1 {
		t.Errorf("filter \"commit\" should match one row, got %d", len(m.visible))
	}
}

func TestAuditStatusText(t *testing.T) {
	rows := auditRows()

	if statusText(rows[1]) != "BLOCKED" {
		t.Errorf("a blocked row must render BLOCKED, got %q", statusText(rows[1]))
	}

	if !strings.Contains(statusText(rows[2]), "exit=2") {
		t.Error("a failed row must render its exit code")
	}

	if statusText(rows[0]) != "ok" {
		t.Errorf("a successful row must render ok, got %q", statusText(rows[0]))
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
