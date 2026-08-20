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

    /// A fully-populated row so `detail_view` exercises every `detail_field` branch
    /// (including the `duration_ms > 0` conditional and the trailing env/enrichment).
    fn full_row() -> AuditRow {
        AuditRow {
            id: 9,
            ts: "2026-07-10T06:00:00Z".to_string(),
            os_user: "dev".to_string(),
            identity: "dev@host".to_string(),
            cwd: "/home/dev/proj".to_string(),
            argv: r#"["commit","-m","hello"]"#.to_string(),
            env: "GIT_DIR=/x".to_string(),
            backend: "git".to_string(),
            backend_path: "/usr/bin/git".to_string(),
            mode: "passthrough".to_string(),
            shortcut: "cm".to_string(),
            exit: 0,
            duration_ms: 42,
            enrichment: "note".to_string(),
            policy_path: String::new(),
        }
    }

    /// Many synthetic rows to drive scrolling / windowing.
    fn many_rows(n: i64) -> Vec<AuditRow> {
        (0..n)
            .map(|i| {
                mk_row(
                    i,
                    &format!("2026-07-10T06:{:02}:00Z", i % 60),
                    "dev",
                    "passthrough",
                    &format!("[\"cmd{i}\"]"),
                    0,
                )
            })
            .collect()
    }

    #[test]
    fn test_view_loading_before_size() {
        // No WindowSize yet → width 0 → the placeholder frame, no panes.
        let m = AuditModel::new(audit_rows());
        assert_eq!(m.view(), "loading audit log…");
    }

    #[test]
    fn test_empty_rows_render_and_navigation() {
        let mut m = AuditModel::new(Vec::new());
        m.update(Msg::WindowSize {
            width: 100,
            height: 20,
        });

        // Detail pane says so; footer position is 0.
        assert_eq!(m.detail_view(), "no matching records");
        assert_eq!(m.pos(), 0);

        let view = m.view();
        assert!(view.contains("no matching records"));
        assert!(view.contains("0/0"), "footer shows 0/0 for an empty log: {view}");

        // Navigation on an empty set is a no-op and must not panic / index oob.
        m.update(Msg::Key(Key::Down));
        m.update(Msg::Key(Key::Up));
        m.update(Msg::Key(Key::End));
        m.update(Msg::Key(Key::Home));
        assert_eq!(m.cursor, 0);
        // list_lines over an empty window is empty.
        assert!(m.list_lines().is_empty());
    }

    #[test]
    fn test_detail_view_all_fields() {
        let mut m = AuditModel::new(vec![full_row()]);
        m.update(Msg::WindowSize {
            width: 120,
            height: 24,
        });
        let d = m.detail_view();
        // Header line: status + command.
        assert!(d.starts_with("ok  commit -m hello"), "detail header: {d:?}");
        for (label, val) in [
            ("time", "06:00:00"),
            ("user", "dev dev@host"),
            ("cwd", "/home/dev/proj"),
            ("backend", "git /usr/bin/git"),
            ("mode", "passthrough cm"),
            ("exit", "0"),
            ("duration", "42 ms"),
            ("env", "GIT_DIR=/x"),
            ("enrichment", "note"),
        ] {
            assert!(d.contains(label), "detail missing label {label}: {d}");
            assert!(d.contains(val), "detail missing value {val}: {d}");
        }
    }

    #[test]
    fn test_detail_field_skips_blank() {
        // A blank value contributes no line (the `field` closure guard).
        let mut b = String::new();
        detail_field(&mut b, "cwd", "   ", 40);
        assert!(b.is_empty(), "blank field must not render: {b:?}");
        detail_field(&mut b, "cwd", "/x", 40);
        // `{:<10} {}` — a 10-wide label, a space, then the (trimmed) value.
        assert_eq!(b, format!("{:<10} {}\n", "cwd", "/x"));
        assert!(b.starts_with("cwd") && b.ends_with("/x\n"));
    }

    #[test]
    fn test_key_navigation_moves_cursor() {
        let mut m = AuditModel::new(audit_rows());
        m.update(Msg::WindowSize {
            width: 120,
            height: 24,
        });
        assert_eq!(m.cursor, 0);

        // Down / j advance; Up / k retreat; clamped at the ends.
        m.update(Msg::Key(Key::Down));
        assert_eq!(m.cursor, 1);
        m.update(Msg::Key(Key::Char('j')));
        assert_eq!(m.cursor, 2);
        m.update(Msg::Key(Key::Down)); // clamp at last
        assert_eq!(m.cursor, 2);
        m.update(Msg::Key(Key::Up));
        assert_eq!(m.cursor, 1);
        m.update(Msg::Key(Key::Char('k')));
        assert_eq!(m.cursor, 0);
        m.update(Msg::Key(Key::Up)); // clamp at first
        assert_eq!(m.cursor, 0);

        // End / G jump to last; Home / g to first.
        m.update(Msg::Key(Key::End));
        assert_eq!(m.cursor, 2);
        m.update(Msg::Key(Key::Home));
        assert_eq!(m.cursor, 0);
        m.update(Msg::Key(Key::Char('G')));
        assert_eq!(m.cursor, 2);
        m.update(Msg::Key(Key::Char('g')));
        assert_eq!(m.cursor, 0);
    }

    #[test]
    fn test_quit_keys() {
        let mut m = AuditModel::new(audit_rows());
        assert_eq!(m.update(Msg::Key(Key::Char('q'))), Some(Cmd::Quit));
        assert_eq!(m.update(Msg::Key(Key::CtrlC)), Some(Cmd::Quit));
        assert_eq!(m.update(Msg::Key(Key::Esc)), Some(Cmd::Quit));
        // An unmapped key is ignored (no cmd, no state change).
        assert_eq!(m.update(Msg::Key(Key::Enter)), None);
    }

    #[test]
    fn test_search_flow_via_keys() {
        let mut m = AuditModel::new(audit_rows());
        m.update(Msg::WindowSize {
            width: 120,
            height: 24,
        });

        // Enter search mode; the footer becomes the text-input view.
        m.update(Msg::Key(Key::Char('/')));
        assert!(m.searching);
        assert!(m.view().contains("filter command"), "placeholder in footer");

        // Type "commit" one char at a time; the filter narrows live.
        for c in "commit".chars() {
            m.update(Msg::Key(Key::Char(c)));
        }
        assert_eq!(m.search.value(), "commit");
        assert_eq!(m.visible.len(), 1, "live filter matches one row");
        assert!(m.view().contains("/ commit"), "footer echoes the query");

        // Backspace re-widens the set.
        m.update(Msg::Key(Key::Backspace));
        assert_eq!(m.search.value(), "commi");

        // Enter confirms: leaves search mode but keeps the filter/value.
        m.update(Msg::Key(Key::Enter));
        assert!(!m.searching);
        assert_eq!(m.search.value(), "commi");

        // Re-enter and Esc: cancels, clearing the query and restoring all rows.
        m.update(Msg::Key(Key::Char('/')));
        m.update(Msg::Key(Key::Char('x')));
        m.update(Msg::Key(Key::Esc));
        assert!(!m.searching);
        assert_eq!(m.search.value(), "");
        assert_eq!(m.visible.len(), 3, "esc restores every row");
    }

    #[test]
    fn test_search_ignored_keys_in_search_mode() {
        // Non-text keys while searching are swallowed (the `_ => {}` arm).
        let mut m = AuditModel::new(audit_rows());
        m.update(Msg::Key(Key::Char('/')));
        assert_eq!(m.update(Msg::Key(Key::Down)), None);
        assert_eq!(m.update(Msg::Key(Key::Home)), None);
        assert!(m.searching, "arrow keys don't leave search mode");
    }

    #[test]
    fn test_filtered_to_zero() {
        let mut m = AuditModel::new(audit_rows());
        m.update(Msg::WindowSize {
            width: 120,
            height: 24,
        });
        m.search.set_value("no-such-command-xyz");
        m.apply_filter();
        assert!(m.visible.is_empty());
        assert_eq!(m.detail_view(), "no matching records");
        assert_eq!(m.pos(), 0);
        let view = m.view();
        assert!(view.contains("no matching records"));
        // A zero-match render must still be bounded.
        assert!(view.matches('\n').count() + 1 <= 24);
    }

    #[test]
    fn test_scroll_past_a_screen() {
        let mut m = AuditModel::new(many_rows(30));
        m.update(Msg::WindowSize {
            width: 120,
            height: 10,
        });
        let bh = m.body_height();
        assert_eq!(bh, 7, "body height = max(h-3,3)");

        // At the top, the window starts at 0.
        assert_eq!(m.window(), (0, 7));
        assert_eq!(m.list_lines().len(), 7);

        // Jump to the end: the window scrolls to keep the cursor on screen.
        m.update(Msg::Key(Key::End));
        assert_eq!(m.cursor, 29);
        let (start, end) = m.window();
        assert_eq!((start, end), (23, 30));
        let lines = m.list_lines();
        assert_eq!(lines.len(), 7);
        // The cursor row is marked and on-screen; earlier rows scrolled off.
        assert!(lines.last().unwrap().starts_with('▸'));
        assert!(lines[0].contains("cmd23"));

        // The full frame never exceeds the terminal box.
        let view = m.view();
        assert!(view.matches('\n').count() + 1 <= 10);
        for ln in view.split('\n') {
            assert!(display_width(ln) <= 120, "line too wide: {ln:?}");
        }
    }

    #[test]
    fn test_short_ts_branches() {
        // RFC3339 → the HH:MM:SS slice after the `T`.
        assert_eq!(short_ts("2026-07-10T06:07:08Z"), "06:07:08");
        // No `T`, longer than 8 → the leading 8 bytes.
        assert_eq!(short_ts("2026-07-10 06:07:08"), "2026-07-");
        // Short string → returned verbatim.
        assert_eq!(short_ts("06:07"), "06:07");
        // `T` present but too short a tail → falls through to the len>8 branch.
        assert_eq!(short_ts("2026-07-10T"), "2026-07-");
    }

    #[test]
    fn test_trunc_and_width_helpers() {
        assert_eq!(trunc("hello", 10), "hello", "short strings unchanged");
        assert_eq!(trunc("hello world", 5), "hell…", "long strings ellipsised");
        assert_eq!(trunc("x", 0), "x", "n<1 clamps to 1");
        assert_eq!(trunc("ab", 1), "…", "n==1 keeps only the ellipsis");
        assert_eq!(display_width("héllo"), 5);
        assert_eq!(pad_right("ab", 5), "ab   ", "pads to width");
        assert_eq!(pad_right("abcdef", 3), "abcdef", "never truncates when longer");
    }

    #[test]
    fn test_status_text_exit_code_branch() {
        // A non-blocked, non-zero-exit row renders its padded exit code.
        let r = mk_row(0, "", "", "passthrough", r#"["x"]"#, 7);
        assert_eq!(status_text(&r), "exit=7 ");
    }

    #[test]
    fn test_search_input_unit() {
        let mut s = SearchInput::new();
        assert_eq!(s.view(), "/ filter command / user / mode…");
        s.focus();
        s.insert('a');
        s.insert('b');
        assert_eq!(s.value(), "ab");
        assert_eq!(s.view(), "/ ab");
        s.backspace();
        assert_eq!(s.value(), "a");
        s.set_value("");
        s.blur();
        assert_eq!(s.view(), "/ filter command / user / mode…");
    }
}
