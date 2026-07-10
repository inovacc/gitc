package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/inovacc/gitc/internal/store"
)

// Audit TUI — an interactive browser over the forensic audit log (charmbracelet
// bubbletea): a navigable, filterable list of invocations on the left and the
// full record on the right. Blocked (policy-refused) rows are highlighted.
// `git audit --plain`, `--wide`, `--verify`, or any non-TTY use the text render.

const auditListW = 48

var (
	auTitle = lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#4C1D95")).Padding(0, 1)
	auList = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).
		BorderRight(true).BorderForeground(lipgloss.Color("#7C3AED")).Padding(0, 1)
	auSel     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	auItem    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E5E7EB"))
	auBlocked = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Bold(true)
	auFail    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B"))
	auHelp    = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	auLabel   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	auDetail  = lipgloss.NewStyle().Padding(0, 2)
)

type auditModel struct {
	rows      []store.AuditRow
	visible   []int
	cursor    int
	vp        viewport.Model
	search    textinput.Model
	searching bool
	ready     bool
	w, h      int
}

func newAuditModel(rows []store.AuditRow) auditModel {
	ti := textinput.New()
	ti.Placeholder = "filter command / user / mode…"
	ti.Prompt = "/ "

	m := auditModel{rows: rows, search: ti}

	m.visible = make([]int, len(rows))
	for i := range rows {
		m.visible[i] = i
	}

	return m
}

func (m auditModel) Init() tea.Cmd { return nil }

func (m auditModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		cw, ch := msg.Width-auditListW-3, msg.Height-4
		ch = max(ch, 3)

		if !m.ready {
			m.vp = viewport.New(cw, ch)
			m.ready = true
		} else {
			m.vp.Width, m.vp.Height = cw, ch
		}

		m.renderDetail()

		return m, nil

	case tea.KeyMsg:
		return m.onKey(msg)
	}

	var cmd tea.Cmd

	m.vp, cmd = m.vp.Update(msg)

	return m, cmd
}

func (m auditModel) View() string {
	if !m.ready {
		return "loading audit log…"
	}

	header := auTitle.Render("◆ gitc audit") + "  " +
		auHelp.Render(fmt.Sprintf("%d record(s)", len(m.rows)))
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.listView(), auDetail.Height(m.h-4).Render(m.vp.View()))

	var footer string

	switch {
	case m.searching:
		footer = m.search.View()
	default:
		footer = auHelp.Render(fmt.Sprintf(
			"↑/↓ move • / filter • pgup/pgdn scroll • q quit    %d/%d", m.pos(), len(m.visible)))
	}

	return header + "\n" + body + "\n" + footer
}

// onKey handles keyboard input in both browse and filter modes.
func (m auditModel) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searching {
		switch msg.String() {
		case "esc":
			m.searching = false
			m.search.SetValue("")
			m.search.Blur()
			m.applyFilter()
		case "enter":
			m.searching = false
			m.search.Blur()
		default:
			var cmd tea.Cmd

			m.search, cmd = m.search.Update(msg)
			m.applyFilter()

			return m, cmd
		}

		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c", "esc":
		return m, tea.Quit
	case "/":
		m.searching = true
		return m, m.search.Focus()
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.renderDetail()
		}
	case "down", "j":
		if m.cursor < len(m.visible)-1 {
			m.cursor++
			m.renderDetail()
		}
	case "home", "g":
		m.cursor = 0
		m.renderDetail()
	case "end", "G":
		m.cursor = len(m.visible) - 1
		m.renderDetail()
	}

	var cmd tea.Cmd

	m.vp, cmd = m.vp.Update(msg)

	return m, cmd
}

// applyFilter recomputes the visible set from the search query.
func (m *auditModel) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(m.search.Value()))
	m.visible = m.visible[:0]

	for i, r := range m.rows {
		if q == "" || strings.Contains(strings.ToLower(r.Command()+" "+r.OSUser+" "+r.Mode+" "+r.TS), q) {
			m.visible = append(m.visible, i)
		}
	}

	if m.cursor >= len(m.visible) {
		m.cursor = 0
	}

	m.renderDetail()
}

// listView renders the left-hand scrollable list of invocations.
func (m auditModel) listView() string {
	var b strings.Builder

	start, end := m.window()
	for vi := start; vi < end; vi++ {
		row := m.rows[m.visible[vi]]
		line := shortTS(row.TS) + "  " + status(row) + "  " + trunc(row.Command(), auditListW-20)

		if vi == m.cursor {
			b.WriteString(auSel.Render("▸ " + line))
		} else {
			b.WriteString("  " + auItem.Render(line))
		}

		b.WriteByte('\n')
	}

	return auList.Width(auditListW).Height(m.h - 4).Render(b.String())
}

// renderDetail sets the viewport to the selected row's full record.
func (m *auditModel) renderDetail() {
	if !m.ready || len(m.visible) == 0 {
		if m.ready {
			m.vp.SetContent(auHelp.Render("no matching records"))
		}

		return
	}

	r := m.rows[m.visible[m.cursor]]

	var b strings.Builder

	field := func(k, v string) {
		if v != "" {
			b.WriteString(auLabel.Render(fmt.Sprintf("%-10s", k)) + v + "\n")
		}
	}

	b.WriteString(status(r) + "  " + lipgloss.NewStyle().Bold(true).Render(r.Command()) + "\n\n")
	field("time", r.TS)
	field("user", strings.TrimSpace(r.OSUser+" "+r.Identity))
	field("cwd", r.Cwd)
	field("backend", strings.TrimSpace(r.Backend+" "+r.BackendPath))
	field("mode", strings.TrimSpace(r.Mode+" "+r.Shortcut))
	field("exit", fmt.Sprintf("%d", r.Exit))

	if r.DurationMS > 0 {
		field("duration", fmt.Sprintf("%d ms", r.DurationMS))
	}

	field("env", r.Env)
	field("enrichment", r.Enrichment)

	m.vp.SetContent(b.String())
	m.vp.GotoTop()
}

// window returns the slice of visible indices that fit the list viewport, kept
// scrolled so the cursor stays on screen.
func (m auditModel) window() (start, end int) {
	rowsShown := max(m.h-4, 1)

	start = 0
	if m.cursor >= rowsShown {
		start = m.cursor - rowsShown + 1
	}

	end = min(start+rowsShown, len(m.visible))

	return start, end
}

func (m auditModel) pos() int {
	if len(m.visible) == 0 {
		return 0
	}

	return m.cursor + 1
}

// status renders a colored status token for a row.
func status(r store.AuditRow) string {
	switch {
	case r.Blocked():
		return auBlocked.Render("BLOCKED")
	case r.Exit != 0:
		return auFail.Render(fmt.Sprintf("exit=%-2d", r.Exit))
	default:
		return "ok     "
	}
}

func shortTS(ts string) string {
	if i := strings.IndexByte(ts, 'T'); i >= 0 && len(ts) >= i+9 {
		return ts[i+1 : i+9]
	}

	if len(ts) > 8 {
		return ts[:8]
	}

	return ts
}

func trunc(s string, n int) string {
	if n < 1 {
		n = 1
	}

	if len(s) <= n {
		return s
	}

	return s[:n-1] + "…"
}

// runAuditTUI loads the most recent n rows and launches the interactive browser.
func runAuditTUI(st *store.Store, n int) int {
	rows, err := st.Records(n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	if len(rows) == 0 {
		fmt.Println("audit log is empty.")
		return 0
	}

	if _, err := tea.NewProgram(newAuditModel(rows), tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		// Fall back to the compact text render if the TUI cannot start.
		if terr := st.Tail(n, false, os.Stdout); terr != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", terr)
			return 1
		}
	}

	return 0
}
