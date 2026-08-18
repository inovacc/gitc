//! `gitc audit`: render the forensic audit log as a compact/wide text table,
//! verify the tamper-evident hash chain, or browse it interactively.
//!
//! Faithful 1:1 port of Go `internal/auditcmd` (`audit.go` + `tui.go`). The
//! original TUI is a charmbracelet **bubbletea** (Elm-architecture) program;
//! `tui_test.go` asserts the Model/Update state machine (cursor navigation,
//! filter toggle, status text, per-row command) — NOT the terminal rendering.
//!
//! So the port keeps the whole Model + `update` + `view`/`detail_view` as PURE,
//! terminal-free Rust (plain strings, no `ratatui`/`crossterm` types in any
//! tested transition). `ratatui` + `crossterm` are used ONLY in the untested
//! live event loop ([`run_audit_tui`] → `run_tui_loop`): the loop reads a
//! `crossterm` key, maps it to our own [`Msg`]/[`Key`] enum, feeds `update`,
//! and paints `view()` via `ratatui`. lipgloss styling (ANSI colours, borders)
//! is dropped — the layout/width is reproduced as plain text (like `doctor`).

use std::cmp::{max, min};
use std::io::IsTerminal;

use crate::store::{AuditRow, Store};

/// Left-hand list-pane width (Go `auditListW`).
const AUDIT_LIST_W: usize = 46;

// ── audit.go: text render / verify / dispatch ───────────────────────────────

/// Render the audit log: a compact one-line summary by default, or the full
/// record with `--wide`/`-w`. An optional numeric argument limits the row count.
/// Go `Run`.
///
/// Go took a nilable `*store.Store` and printed `gitc: audit log unavailable`
/// when nil; the Rust signature takes a non-null `&Store`, so that guard is
/// dropped (the caller only reaches here with a live store).
pub fn run(args: &[String], store: &Store) -> i32 {
    let mut n: i64 = 0;
    let mut wide = false;
    let mut verify = false;
    let mut plain = false;

    for a in args {
        match a.as_str() {
            "--wide" | "-w" => wide = true,
            "--verify" => verify = true,
            "--plain" => plain = true,
            _ => {
                if let Ok(v) = a.parse::<i64>() {
                    n = v;
                }
            }
        }
    }

    if verify {
        return run_audit_verify(store);
    }

    // On a terminal, browse interactively; a pipe/redirect, --plain, or --wide
    // gets the scriptable text render. The TUI loads the most recent rows
    // (default 500) so a big log stays responsive.
    if !wide && !plain && stdout_is_tty() {
        return run_audit_tui(store, audit_limit(n, 500));
    }

    let mut out = std::io::stdout();
    if let Err(e) = store.tail(audit_limit(n, 20), wide, &mut out) {
        eprintln!("gitc: {e}");
        return 1;
    }

    0
}

/// Return `n` when the user gave a positive count, else the default. Go `auditLimit`.
fn audit_limit(n: i64, def: i64) -> i64 {
    if n > 0 {
        n
    } else {
        def
    }
}

/// Whether stdout is an interactive terminal (not a pipe or file). Go
/// `stdoutIsTTY` used `os.ModeCharDevice`; std's `IsTerminal` is the direct
/// equivalent (no isatty crate).
fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Check the tamper-evident hash chain and report whether the log is intact.
/// Go `runAuditVerify`.
fn run_audit_verify(store: &Store) -> i32 {
    let res = match store.verify() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc: {e}");
            return 1;
        }
    };

    if res.intact {
        print!("audit chain intact: {} row(s) verified", res.checked);

        if res.legacy > 0 {
            print!(", {} legacy (pre-hash) row(s)", res.legacy);
        }

        println!();

        return 0;
    }

    eprintln!(
        "audit chain BROKEN at row id {} ({} verified before the break): a row was deleted or edited",
        res.broken_id, res.checked
    );

    1
}

/// Load the most recent `n` rows and launch the interactive browser. Go
/// `runAuditTUI`. On a TUI error, fall back to the scriptable tail render.
fn run_audit_tui(store: &Store, n: i64) -> i32 {
    let rows = match store.records(n) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc: {e}");
            return 1;
        }
    };

    if rows.is_empty() {
        println!("audit log is empty.");
        return 0;
    }

    if run_tui_loop(AuditModel::new(rows)).is_err() {
        let mut out = std::io::stdout();
        if let Err(e) = store.tail(n, false, &mut out) {
            eprintln!("gitc: {e}");
            return 1;
        }
    }

    0
}

// ── tui.go: the pure Elm Model / Update state machine ───────────────────────

/// Our own message type (bubbletea `tea.Msg`, an `any`). Kept independent of
/// `crossterm::KeyEvent` so every tested transition is terminal-free; the live
/// loop maps `crossterm` keys → [`Key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Msg {
    /// bubbletea `tea.WindowSizeMsg`.
    WindowSize { width: u16, height: u16 },
    /// bubbletea `tea.KeyMsg`.
    Key(Key),
}

/// A keypress, modelled on the subset of `tea.KeyMsg.String()` the Go `onKey`
/// switches on (`up/down/home/end`, printable runes, `enter/esc/backspace`,
/// `ctrl+c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    CtrlC,
    Char(char),
}

/// A `tea.Cmd` result of `update` — only `Quit` is observable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmd {
    Quit,
}

/// A minimal stand-in for bubbles `textinput.Model` (only what the audit TUI
/// uses: a value, prompt/placeholder for the footer, and a focus flag).
#[derive(Debug, Clone)]
pub(crate) struct SearchInput {
    value: String,
    prompt: String,
    placeholder: String,
    focused: bool,
}

impl SearchInput {
    fn new() -> Self {
        SearchInput {
            value: String::new(),
            prompt: "/ ".to_string(),
            placeholder: "filter command / user / mode…".to_string(),
            focused: false,
        }
    }

    fn value(&self) -> &str {
        &self.value
    }

    fn set_value(&mut self, v: &str) {
        self.value = v.to_string();
    }

    fn focus(&mut self) {
        self.focused = true;
    }

    fn blur(&mut self) {
        self.focused = false;
    }

    fn insert(&mut self, c: char) {
        self.value.push(c);
    }

    fn backspace(&mut self) {
        self.value.pop();
    }

    /// The footer render while searching (bubbles `textinput.View`): prompt then
    /// the value, or the placeholder when empty.
    fn view(&self) -> String {
        if self.value.is_empty() {
            format!("{}{}", self.prompt, self.placeholder)
        } else {
            format!("{}{}", self.prompt, self.value)
        }
    }
}

/// The audit-browser model (Go `auditModel`).
#[derive(Debug, Clone)]
pub(crate) struct AuditModel {
    rows: Vec<AuditRow>,
    visible: Vec<usize>,
    cursor: usize,
    search: SearchInput,
    searching: bool,
    w: usize,
    h: usize,
}

impl AuditModel {
    /// Build a model with every row visible (Go `newAuditModel`).
    pub(crate) fn new(rows: Vec<AuditRow>) -> Self {
        let visible = (0..rows.len()).collect();
        AuditModel {
            rows,
            visible,
            cursor: 0,
            search: SearchInput::new(),
            searching: false,
            w: 0,
            h: 0,
        }
    }

    /// Advance the state machine by one message (Go `Update`). Pure: no terminal
    /// I/O, no `ratatui`/`crossterm` types.
    pub(crate) fn update(&mut self, msg: Msg) -> Option<Cmd> {
        match msg {
            Msg::WindowSize { width, height } => {
                self.w = width as usize;
                self.h = height as usize;
                None
            }
            Msg::Key(key) => self.on_key(key),
        }
    }

    /// Handle keyboard input in both browse and filter modes (Go `onKey`).
    fn on_key(&mut self, key: Key) -> Option<Cmd> {
        if self.searching {
            match key {
                Key::Esc => {
                    self.searching = false;
                    self.search.set_value("");
                    self.search.blur();
                    self.apply_filter();
                }
                Key::Enter => {
                    self.searching = false;
                    self.search.blur();
                }
                // default: feed the text input, then re-filter.
                Key::Char(c) => {
                    self.search.insert(c);
                    self.apply_filter();
                }
                Key::Backspace => {
                    self.search.backspace();
                    self.apply_filter();
                }
                _ => {}
            }
            return None;
        }

        match key {
            Key::Char('q') | Key::CtrlC | Key::Esc => return Some(Cmd::Quit),
            Key::Char('/') => {
                self.searching = true;
                self.search.focus();
            }
            Key::Up | Key::Char('k') => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }
            Key::Down | Key::Char('j') => {
                // Go: cursor < len(visible)-1. The +1 form is empty-safe.
                if self.cursor + 1 < self.visible.len() {
                    self.cursor += 1;
                }
            }
            Key::Home | Key::Char('g') => {
                self.cursor = 0;
            }
            Key::End | Key::Char('G') => {
                // Go set cursor = len(visible)-1 (== -1 when empty, a latent bug
                // never hit since the TUI isn't launched with 0 rows). We clamp
                // to 0 to avoid an out-of-range index.
                self.cursor = self.visible.len().saturating_sub(1);
            }
            _ => {}
        }

        None
    }

    /// Recompute the visible set from the search query (Go `applyFilter`).
    fn apply_filter(&mut self) {
        let q = self.search.value().trim().to_lowercase();
        self.visible.clear();

        for (i, r) in self.rows.iter().enumerate() {
            let hay = format!("{} {} {} {}", r.command(), r.os_user, r.mode, r.ts).to_lowercase();
            if q.is_empty() || hay.contains(&q) {
                self.visible.push(i);
            }
        }

        if self.cursor >= self.visible.len() {
            self.cursor = 0;
        }
    }

    // ── rendering (pure strings; lipgloss colour/border dropped) ────────────

    /// Number of rows available to the list/detail panes (Go `bodyHeight`).
    fn body_height(&self) -> usize {
        max(self.h as i64 - 3, 3) as usize
    }

    /// The visible-index slice that fits the list, scrolled to keep the cursor
    /// on screen (Go `window`).
    fn window(&self) -> (usize, usize) {
        let rows = self.body_height();
        let mut start = 0usize;
        if self.cursor >= rows {
            start = self.cursor - rows + 1;
        }
        let end = min(start + rows, self.visible.len());
        (start, end)
    }

    /// 1-based cursor position for the footer (Go `pos`).
    fn pos(&self) -> usize {
        if self.visible.is_empty() {
            0
        } else {
            self.cursor + 1
        }
    }

    /// The left-hand list lines, hard-truncated so no row ever wraps (Go
    /// `listView`, minus the lipgloss box).
    fn list_lines(&self) -> Vec<String> {
        const INNER: usize = AUDIT_LIST_W - 2; // padding
                                               // budget: "▸ "(2) + time(8) + " "(1) + status(7) + " "(1)
        let cmd_budget = max(INNER as i64 - 19, 4) as usize;

        let (start, end) = self.window();
        let mut lines = Vec::with_capacity(end.saturating_sub(start));

        for vi in start..end {
            let r = &self.rows[self.visible[vi]];
            let line = format!(
                "{:<8} {:<7} {}",
                short_ts(&r.ts),
                status_text(r),
                trunc(&r.command(), cmd_budget)
            );

            let prefix = if vi == self.cursor { "▸ " } else { "  " };
            lines.push(trunc(&format!("{prefix}{line}"), INNER));
        }

        lines
    }

    /// The selected row's full record, clipped to the pane (Go `detailView`).
    pub(crate) fn detail_view(&self) -> String {
        let dw = max(self.w as i64 - AUDIT_LIST_W as i64 - 4, 20) as usize;

        if self.visible.is_empty() {
            return "no matching records".to_string();
        }

        let r = &self.rows[self.visible[self.cursor]];
        let vw = max(dw as i64 - 14, 10) as usize; // value column after a 12-wide label + padding

        let mut b = String::new();
        b.push_str(&format!(
            "{}  {}\n\n",
            status_text(r),
            trunc(&r.command(), dw.saturating_sub(12))
        ));

        detail_field(&mut b, "time", &r.ts, vw);
        detail_field(&mut b, "user", &format!("{} {}", r.os_user, r.identity), vw);
        detail_field(&mut b, "cwd", &r.cwd, vw);
        detail_field(
            &mut b,
            "backend",
            &format!("{} {}", r.backend, r.backend_path),
            vw,
        );
        detail_field(&mut b, "mode", &format!("{} {}", r.mode, r.shortcut), vw);
        detail_field(&mut b, "exit", &r.exit.to_string(), vw);

        if r.duration_ms > 0 {
            detail_field(&mut b, "duration", &format!("{} ms", r.duration_ms), vw);
        }

        detail_field(&mut b, "env", &r.env, vw);
        detail_field(&mut b, "enrichment", &r.enrichment, vw);

        b
    }

    /// Full-screen render (Go `View`): header, the list+detail panes joined
    /// horizontally, and a footer. Padded to `body_height` lines so it never
    /// overflows the terminal height (the wrapping bug the tests guard against).
    pub(crate) fn view(&self) -> String {
        if self.w == 0 {
            return "loading audit log…".to_string();
        }

        let header = format!("◆ gitc audit  {} record(s)", self.rows.len());

        let bh = self.body_height();
        let list = self.list_lines();
        let detail: Vec<String> = self.detail_view().split('\n').map(str::to_string).collect();

        let mut body_lines = Vec::with_capacity(bh);
        for i in 0..bh {
            let l = list.get(i).map(String::as_str).unwrap_or("");
            let d = detail.get(i).map(String::as_str).unwrap_or("");
            body_lines.push(format!("{}{}", pad_right(l, AUDIT_LIST_W), d));
        }

        let footer = if self.searching {
            self.search.view()
        } else {
            format!(
                "↑/↓ move • / filter • q quit    {}/{}",
                self.pos(),
                self.visible.len()
            )
        };

        format!("{}\n{}\n{}", header, body_lines.join("\n"), footer)
    }
}

/// Append a `label value` line when `v` is non-blank (Go `detailView`'s `field`
/// closure). `%-10s ` → `{:<10} `.
fn detail_field(b: &mut String, k: &str, v: &str, vw: usize) {
    let v = v.trim();
    if !v.is_empty() {
        b.push_str(&format!("{:<10} {}\n", k, trunc(v, vw)));
    }
}

/// A fixed-width plain status token (no ANSI) for aligned columns. Go `statusText`.
fn status_text(r: &AuditRow) -> String {
    if r.blocked() {
        "BLOCKED".to_string()
    } else if r.exit != 0 {
        format!("exit={:<2}", r.exit)
    } else {
        "ok".to_string()
    }
}

/// The `HH:MM:SS` slice of an RFC3339 timestamp (Go `shortTS`; byte-indexed —
/// faithful for the ASCII timestamps the store emits).
fn short_ts(ts: &str) -> String {
    if let Some(i) = ts.find('T') {
        if ts.len() >= i + 9 {
            return ts[i + 1..i + 9].to_string();
        }
    }

    if ts.len() > 8 {
        return ts[..8].to_string();
    }

    ts.to_string()
}

/// Truncate to `n` display columns, ellipsising the last (Go `trunc`). Go sliced
/// by BYTES; we slice by chars, which matches for ASCII and avoids splitting a
/// UTF-8 rune (the only observable divergence, on non-ASCII commands).
fn trunc(s: &str, n: usize) -> String {
    let n = if n < 1 { 1 } else { n };

    if s.chars().count() <= n {
        return s.to_string();
    }

    let mut out: String = s.chars().take(n - 1).collect();
    out.push('…');
    out
}

/// Display width of a rendered line. lipgloss used go-runewidth (ANSI-stripped,
/// wide-char aware); our render emits plain text of narrow-width runes, so a
/// char count is the faithful equivalent.
fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Right-pad `s` with spaces to `width` display columns (lipgloss `Width`).
fn pad_right(s: &str, width: usize) -> String {
    let w = display_width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - w))
    }
}

// ── the untested live event loop (ratatui + crossterm ONLY here) ────────────

/// Drive the pure [`AuditModel`] against a real terminal: set up the alt screen,
/// paint `view()` each frame via `ratatui`, translate `crossterm` keys to [`Msg`],
/// and quit on `Cmd::Quit`. Never exercised by the tests.
fn run_tui_loop(mut model: AuditModel) -> std::io::Result<()> {
    use crossterm::event::{self, Event};
    use crossterm::{execute, terminal};
    use ratatui::backend::CrosstermBackend;
    use ratatui::widgets::Paragraph;
    use ratatui::Terminal;

    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let size = terminal.size()?;
    model.update(Msg::WindowSize {
        width: size.width,
        height: size.height,
    });

    let result = (|| -> std::io::Result<()> {
        loop {
            terminal.draw(|f| {
                let area = f.area();
                f.render_widget(Paragraph::new(model.view()), area);
            })?;

            // keep the model's idea of the terminal size current for next frame
            let area = terminal.size()?;
            model.update(Msg::WindowSize {
                width: area.width,
                height: area.height,
            });

            match event::read()? {
                Event::Key(key) => {
                    if let Some(msg) = map_key(key) {
                        if model.update(msg) == Some(Cmd::Quit) {
                            break;
                        }
                    }
                }
                Event::Resize(w, h) => {
                    model.update(Msg::WindowSize {
                        width: w,
                        height: h,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    })();

    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), terminal::LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Translate a `crossterm` key event to our [`Msg`] (the only crossterm→Msg
/// boundary; kept out of the tested `update`).
fn map_key(ev: crossterm::event::KeyEvent) -> Option<Msg> {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    // Windows delivers both Press and Release; act on the press only.
    if ev.kind == KeyEventKind::Release {
        return None;
    }

    let key = match ev.code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Char('c') if ev.modifiers.contains(KeyModifiers::CONTROL) => Key::CtrlC,
        KeyCode::Char(c) => Key::Char(c),
        _ => return None,
    };

    Some(Msg::Key(key))
}

// ── tests (ported from tui_test.go; pure — no terminal required) ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AuditRow;

    /// Build an `AuditRow` with the fields the tests care about; the rest empty.
    fn mk_row(id: i64, ts: &str, os_user: &str, mode: &str, argv: &str, exit: i32) -> AuditRow {
        AuditRow {
            id,
            ts: ts.to_string(),
            os_user: os_user.to_string(),
            identity: String::new(),
            cwd: String::new(),
            argv: argv.to_string(),
            env: String::new(),
            backend: String::new(),
            backend_path: String::new(),
            mode: mode.to_string(),
            shortcut: String::new(),
            exit,
            duration_ms: 0,
            enrichment: String::new(),
            policy_path: String::new(),
        }
    }

    /// Go `auditRows`.
    fn audit_rows() -> Vec<AuditRow> {
        vec![
            mk_row(
                3,
                "2026-07-10T06:00:00Z",
                "dev",
                "passthrough",
                r#"["status"]"#,
                0,
            ),
            mk_row(
                2,
                "2026-07-10T06:01:00Z",
                "dev",
                "blocked",
                r#"["push","evil"]"#,
                1,
            ),
            mk_row(
                1,
                "2026-07-10T06:02:00Z",
                "dev",
                "passthrough",
                r#"["commit","-m","x"]"#,
                2,
            ),
        ]
    }

    #[test]
    fn test_audit_model_navigate_and_filter() {
        let mut m = AuditModel::new(audit_rows());

        assert_eq!(m.visible.len(), 3, "all rows visible initially");

        m.update(Msg::WindowSize {
            width: 120,
            height: 24,
        });

        assert!(
            !m.view().contains("loading"),
            "View should render after a size message"
        );

        // Selecting the blocked row (index 1) must show its command in the detail.
        m.update(Msg::Key(Key::Down));

        assert!(
            m.detail_view().contains("push evil"),
            "detail pane should show the selected row's command:\n{}",
            m.detail_view()
        );

        // The full view must not overflow the terminal — neither in height (rows)
        // nor width (each line ≤ terminal width). Overflow is what made the header
        // and detail pane scroll off in the original wrapping bug.
        let view = m.view();
        let lines = view.matches('\n').count() + 1;
        assert!(
            lines <= 24,
            "rendered view is {lines} lines, exceeds terminal height 24 (wrapping?)"
        );

        for ln in view.split('\n') {
            let w = display_width(ln);
            assert!(
                w <= 120,
                "line width {w} exceeds terminal width 120 (would wrap): {ln:?}"
            );
        }

        // Filtering narrows the visible set.
        m.search.set_value("commit");
        m.apply_filter();

        assert_eq!(m.visible.len(), 1, "filter \"commit\" should match one row");
    }

    #[test]
    fn test_audit_status_text() {
        let rows = audit_rows();

        assert_eq!(
            status_text(&rows[1]),
            "BLOCKED",
            "a blocked row must render BLOCKED"
        );

        assert!(
            status_text(&rows[2]).contains("exit=2"),
            "a failed row must render its exit code"
        );

        assert_eq!(
            status_text(&rows[0]),
            "ok",
            "a successful row must render ok"
        );
    }

    #[test]
    fn test_audit_row_command() {
        let r = mk_row(0, "", "", "", r#"["push","origin","main"]"#, 0);
        assert_eq!(
            r.command(),
            "push origin main",
            "Command() should space-join the argv"
        );

        assert!(!r.blocked(), "a passthrough row must not report Blocked");

        let blocked = mk_row(0, "", "", "blocked", "", 0);
        assert!(blocked.blocked(), "a blocked-mode row must report Blocked");
    }
}
