package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Doctor TUI — an interactive rendering of the same checks the static checklist
// produces (charmbracelet bubbletea/lipgloss), modeled on the the-terminal
// layout: a navigable check list on the left, a detail pane on the right, a
// title header and a help/summary footer. It adds nothing to the checks
// themselves; `git doctor --plain` (or any non-TTY) renders them statically.

const doctorListW = 30

var (
	dcGreen  = lipgloss.Color("#22C55E")
	dcAmber  = lipgloss.Color("#F59E0B")
	dcRed    = lipgloss.Color("#EF4444")
	dcAccent = lipgloss.Color("#7C3AED")
	dcSubtle = lipgloss.Color("#6B7280")
	dcFg     = lipgloss.Color("#E5E7EB")
	dcWhite  = lipgloss.Color("#FFFFFF")

	dTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(dcWhite).Background(dcAccent).Padding(0, 1)
	dListStyle  = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).
			BorderRight(true).BorderForeground(dcAccent).Padding(0, 1)
	dItemStyle   = lipgloss.NewStyle().Foreground(dcFg)
	dSelStyle    = lipgloss.NewStyle().Foreground(dcWhite).Bold(true)
	dLabelStyle  = lipgloss.NewStyle().Foreground(dcSubtle)
	dHelpStyle   = lipgloss.NewStyle().Foreground(dcSubtle)
	dDetailStyle = lipgloss.NewStyle().Padding(0, 2)
)

// badge renders a colored status pill for a check.
func badge(s checkStatus) string {
	switch s {
	case statusOK:
		return lipgloss.NewStyle().Foreground(dcGreen).Render("[ ok ]")
	case statusWarn:
		return lipgloss.NewStyle().Foreground(dcAmber).Render("[warn]")
	default:
		return lipgloss.NewStyle().Foreground(dcRed).Render("[fail]")
	}
}

// statusWord returns the accent style for a status word in the detail pane.
func statusWord(s checkStatus) lipgloss.Style {
	switch s {
	case statusOK:
		return lipgloss.NewStyle().Foreground(dcGreen).Bold(true)
	case statusWarn:
		return lipgloss.NewStyle().Foreground(dcAmber).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(dcRed).Bold(true)
	}
}

type doctorModel struct {
	results []checkResult
	worst   checkStatus
	cursor  int
	w, h    int
}

func (m doctorModel) Init() tea.Cmd { return nil }

func (m doctorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.results)-1 {
				m.cursor++
			}
		case "home", "g":
			m.cursor = 0
		case "end", "G":
			m.cursor = len(m.results) - 1
		case "r":
			m.results, m.worst = collectChecks()
			if m.cursor >= len(m.results) {
				m.cursor = 0
			}
		}
	}

	return m, nil
}

func (m doctorModel) View() string {
	if m.w == 0 {
		return "loading gitc doctor…"
	}

	header := dTitleStyle.Render("◆ gitc doctor") + "  " +
		lipgloss.NewStyle().Foreground(dcAccent).Italic(true).Render(version)

	body := lipgloss.JoinHorizontal(lipgloss.Top, m.listView(), m.detailView())

	help := dHelpStyle.Render("↑/↓ navigate • r re-run • q quit")
	footer := m.summary() + "    " + help

	return header + "\n" + body + "\n" + footer
}

// listView renders the left-hand navigable check list.
func (m doctorModel) listView() string {
	var b strings.Builder

	for i, r := range m.results {
		row := badge(r.status) + " " + r.label
		if i == m.cursor {
			row = dSelStyle.Render("▸ ") + row
		} else {
			row = "  " + dItemStyle.Render(row)
		}

		b.WriteString(row)
		b.WriteByte('\n')
	}

	return dListStyle.Width(doctorListW).Height(m.bodyHeight()).Render(b.String())
}

// detailView renders the right-hand detail pane for the selected check.
func (m doctorModel) detailView() string {
	if len(m.results) == 0 {
		return ""
	}

	r := m.results[m.cursor]

	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(dcWhite).Render(r.label))
	b.WriteString("\n\n")
	b.WriteString(dLabelStyle.Render("status  "))
	b.WriteString(statusWord(r.status).Render(strings.TrimSpace(r.status.mark())))
	b.WriteString("\n\n")
	b.WriteString(dLabelStyle.Render("detail"))
	b.WriteString("\n")

	w := m.w - doctorListW - 8
	if w < 20 {
		w = 20
	}

	b.WriteString(lipgloss.NewStyle().Foreground(dcFg).Width(w).Render(r.detail))

	return dDetailStyle.Height(m.bodyHeight()).Render(b.String())
}

// bodyHeight is the height available to the list/detail row (minus chrome).
func (m doctorModel) bodyHeight() int {
	h := m.h - 4
	if h < 3 {
		h = 3
	}

	return h
}

// summary counts checks by status for the footer.
func (m doctorModel) summary() string {
	var ok, warn, fail int

	for _, r := range m.results {
		switch r.status {
		case statusOK:
			ok++
		case statusWarn:
			warn++
		default:
			fail++
		}
	}

	return fmt.Sprintf("%s %d   %s %d   %s %d",
		lipgloss.NewStyle().Foreground(dcGreen).Render("ok"), ok,
		lipgloss.NewStyle().Foreground(dcAmber).Render("warn"), warn,
		lipgloss.NewStyle().Foreground(dcRed).Render("fail"), fail)
}

// runDoctorTUI launches the interactive doctor and returns the process exit code
// derived from the worst check status at quit time. If the TUI cannot start
// (e.g. no real terminal after all), it falls back to the static checklist.
func runDoctorTUI(results []checkResult, worst checkStatus) int {
	m := doctorModel{results: results, worst: worst}

	fm, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return renderDoctorPlain(results, worst)
	}

	if final, ok := fm.(doctorModel); ok {
		return exitCodeFor(final.worst)
	}

	return exitCodeFor(worst)
}
