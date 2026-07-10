package auditcmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/inovacc/gitc/internal/store"
)

// Audit TUI — an interactive browser over the forensic audit log (charmbracelet
// bubbletea): a navigable, filterable list of invocations on the left and the
// full record on the right. Blocked (policy-refused) rows are highlighted.
// `git audit --plain`, `--wide`, `--verify`, or any non-TTY use the text render.

const auditListW = 46

var (
	auTitle = lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#4C1D95")).Padding(0, 1)
	auList = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).
		BorderRight(true).BorderForeground(lipgloss.Color("#7C3AED")).Padding(0, 1)
	auSel     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#4C1D95")).Bold(true)
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
	search    textinput.Model
	searching bool
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
		return m, nil
	case tea.KeyMsg:
		return m.onKey(msg)
	}

	return m, nil
}

func (m auditModel) View() string {
	if m.w == 0 {
		return "loading audit log…"
	}

	header := auTitle.Render("◆ gitc audit") + "  " +
		auHelp.Render(fmt.Sprintf("%d record(s)", len(m.rows)))
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.listView(), m.detailView())

	footer := auHelp.Render(fmt.Sprintf(
		"↑/↓ move • / filter • q quit    %d/%d", m.pos(), len(m.visible)))
	if m.searching {
		footer = m.search.View()
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
		}
	case "down", "j":
		if m.cursor < len(m.visible)-1 {
			m.cursor++
		}
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(m.visible) - 1
	}

	return m, nil
}

// applyFilter recomputes the visible set from the search query.
func (m *auditModel) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(m.search.Value()))
	m.visible = m.visible[:0]

	for i, r := range m.rows {
		hay := strings.ToLower(r.Command() + " " + r.OSUser + " " + r.Mode + " " + r.TS)
		if q == "" || strings.Contains(hay, q) {
			m.visible = append(m.visible, i)
		}
	}

	if m.cursor >= len(m.visible) {
		m.cursor = 0
	}
}

// bodyHeight is the number of rows available to the list/detail panes.
func (m auditModel) bodyHeight() int {
	return max(m.h-3, 3)
}

// listView renders the left-hand list, hard-truncated so no row ever wraps.
func (m auditModel) listView() string {
	const inner = auditListW - 2 // padding
	// budget: "▸ "(2) + time(8) + " "(1) + status(7) + " "(1)
	cmdBudget := max(inner-19, 4)

	var b strings.Builder

	start, end := m.window()
	for vi := start; vi < end; vi++ {
		r := m.rows[m.visible[vi]]
		line := fmt.Sprintf("%-8s %-7s %s", shortTS(r.TS), statusText(r), trunc(r.Command(), cmdBudget))

		prefix := "  "
		if vi == m.cursor {
			prefix = "▸ "
		}

		b.WriteString(rowStyle(r, vi == m.cursor).Render(trunc(prefix+line, inner)))
		b.WriteByte('\n')
	}

	return auList.Width(auditListW).Height(m.bodyHeight()).MaxHeight(m.bodyHeight()).Render(b.String())
}

// detailView renders the selected row's full record, clipped to the pane.
func (m auditModel) detailView() string {
	dw := max(m.w-auditListW-4, 20)
	bh := m.bodyHeight()

	if len(m.visible) == 0 {
		return auDetail.Width(dw).Height(bh).MaxHeight(bh).Render(auHelp.Render("no matching records"))
	}

	r := m.rows[m.visible[m.cursor]]
	vw := max(dw-14, 10) // value column after a 12-wide label + padding

	var b strings.Builder

	b.WriteString(statusText(r) + "  " + lipgloss.NewStyle().Bold(true).Render(trunc(r.Command(), dw-12)) + "\n\n")

	field := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			b.WriteString(auLabel.Render(fmt.Sprintf("%-10s ", k)) + trunc(v, vw) + "\n")
		}
	}

	field("time", r.TS)
	field("user", r.OSUser+" "+r.Identity)
	field("cwd", r.Cwd)
	field("backend", r.Backend+" "+r.BackendPath)
	field("mode", r.Mode+" "+r.Shortcut)
	field("exit", fmt.Sprintf("%d", r.Exit))

	if r.DurationMS > 0 {
		field("duration", fmt.Sprintf("%d ms", r.DurationMS))
	}

	field("env", r.Env)
	field("enrichment", r.Enrichment)

	return auDetail.Width(dw).Height(bh).MaxHeight(bh).Render(b.String())
}

// window returns the visible-index slice that fits the list, scrolled to keep
// the cursor on screen.
func (m auditModel) window() (start, end int) {
	rows := m.bodyHeight()

	start = 0
	if m.cursor >= rows {
		start = m.cursor - rows + 1
	}

	return start, min(start+rows, len(m.visible))
}

func (m auditModel) pos() int {
	if len(m.visible) == 0 {
		return 0
	}

	return m.cursor + 1
}

// rowStyle picks the list-line style: selection wins, then blocked, then failed.
func rowStyle(r store.AuditRow, selected bool) lipgloss.Style {
	switch {
	case selected:
		return auSel
	case r.Blocked():
		return auBlocked
	case r.Exit != 0:
		return auFail
	default:
		return auItem
	}
}

// statusText is a fixed-width plain status token (no ANSI) for aligned columns.
func statusText(r store.AuditRow) string {
	switch {
	case r.Blocked():
		return "BLOCKED"
	case r.Exit != 0:
		return fmt.Sprintf("exit=%-2d", r.Exit)
	default:
		return "ok"
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

	if _, err := tea.NewProgram(newAuditModel(rows), tea.WithAltScreen()).Run(); err != nil {
		if terr := st.Tail(n, false, os.Stdout); terr != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", terr)
			return 1
		}
	}

	return 0
}
