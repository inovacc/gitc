//! Port of the slice of `gitleaks/go-gitdiff` that betterleaks actually uses —
//! parsing a `git log -p` / `git diff` stream into files, hunks and lines.
//!
//! **Why this is ported rather than delegated.** Go depends on a FORK of
//! go-gitdiff, so no Rust crate is a drop-in by definition, and PORT-PLAN
//! flagged `patch` with a warning for that reason. The consumed surface is
//! narrow — `NewName`, `IsDelete`, `IsBinary`, each hunk's `NewPosition`, and
//! `TextFragment.Raw(OpAdd)` (the added lines only) — plus the commit header.
//! That is a parser, and parsers port cleanly.
//!
//! **Only ADDED lines are scanned.** `Raw(OpAdd)` is what the git source feeds
//! the detector: a secret being REMOVED in a commit is not a new leak, and
//! context lines belong to some other commit. Getting this wrong in either
//! direction is the difference between missing every leak and reporting every
//! line of history.

use std::collections::BTreeMap;

/// What a diff line does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// ` ` — unchanged context.
    Context,
    /// `+` — added.
    Add,
    /// `-` — removed.
    Delete,
}

/// One line inside a hunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub op: Op,
    /// The line's text WITHOUT the leading op character, including its newline.
    pub text: String,
}

/// Go `gitdiff.TextFragment` — one `@@` hunk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextFragment {
    /// Start line in the OLD file (`@@ -a,b`).
    pub old_position: i64,
    pub old_lines: i64,
    /// Start line in the NEW file (`@@ +c,d`) — this becomes the fragment's
    /// `start_line`, so a finding's line number is a real line in the new file.
    pub new_position: i64,
    pub new_lines: i64,
    pub lines: Vec<Line>,
}

impl TextFragment {
    /// Go `TextFragment.Raw(op)` — concatenate the text of lines with this op.
    pub fn raw(&self, op: Op) -> String {
        let mut out = String::new();
        for l in &self.lines {
            if l.op == op {
                out.push_str(&l.text);
            }
        }
        out
    }
}

/// Go `gitdiff.PatchHeader` — the commit a diff belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchHeader {
    pub sha: String,
    pub author_name: String,
    pub author_email: String,
    /// The raw `Date:` value, as git printed it.
    pub author_date: String,
    /// The commit message with git's four-space indent stripped.
    pub message: String,
}

/// Go `gitdiff.File`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct File {
    pub old_name: String,
    /// The path as of THIS commit — what a finding is attributed to.
    pub new_name: String,
    pub is_delete: bool,
    pub is_new: bool,
    pub is_binary: bool,
    pub is_rename: bool,
    pub text_fragments: Vec<TextFragment>,
    pub patch_header: Option<PatchHeader>,
}

/// Parse a `git log -p` (or `git diff`) stream.
///
/// Robustness posture matches the source's: an unrecognised line is SKIPPED
/// rather than fatal. A diff stream carries arbitrary file content, and one odd
/// line must not abort a whole-history scan.
pub fn parse(input: &str) -> Vec<File> {
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let mut files: Vec<File> = Vec::new();
    let mut header: Option<PatchHeader> = None;
    let mut i = 0usize;

    while i < lines.len() {
        let line = lines[i];
        let t = trim_newline(line);

        // ── commit header ───────────────────────────────────────────────
        if let Some(sha) = t.strip_prefix("commit ") {
            let mut h = PatchHeader {
                // `commit <sha>` may be followed by decorations like
                // "(HEAD -> main)"; take the first token only.
                sha: sha.split_whitespace().next().unwrap_or("").to_string(),
                ..Default::default()
            };
            i += 1;
            let mut message = String::new();
            let mut started_message = false;
            while i < lines.len() {
                let t = trim_newline(lines[i]);
                if t.starts_with("diff --git ") || t.starts_with("commit ") {
                    break;
                }
                if let Some(a) = t.strip_prefix("Author: ") {
                    let (name, email) = split_author(a);
                    h.author_name = name;
                    h.author_email = email;
                } else if let Some(d) = t.strip_prefix("Date: ") {
                    h.author_date = d.trim().to_string();
                } else if let Some(body) = t.strip_prefix("    ") {
                    // git indents the message by four spaces.
                    if started_message {
                        message.push('\n');
                    }
                    started_message = true;
                    message.push_str(body);
                } else if t.trim().is_empty() && started_message {
                    // A PARAGRAPH BREAK inside the message is an empty line, not
                    // an indented one — git does not pad it to four spaces. Only
                    // count it once the message has started, so the blank line
                    // separating the headers from the body is not captured.
                    message.push('\n');
                }
                i += 1;
            }
            // The blank line separating the message from the diff is captured by
            // the paragraph-break rule above; trim it back off so the message
            // ends at its last real line.
            h.message = message.trim_end_matches('\n').to_string();
            header = Some(h);
            continue;
        }

        // ── file header ─────────────────────────────────────────────────
        if let Some(rest) = t.strip_prefix("diff --git ") {
            let (old, new) = split_diff_git_paths(rest);
            let mut f = File {
                old_name: old,
                new_name: new,
                patch_header: header.clone(),
                ..Default::default()
            };
            i += 1;

            // Extended headers, up to the first hunk or the next file/commit.
            while i < lines.len() {
                let t = trim_newline(lines[i]);
                if t.starts_with("@@") || t.starts_with("diff --git ") || t.starts_with("commit ") {
                    break;
                }
                if t.starts_with("new file mode") {
                    f.is_new = true;
                } else if t.starts_with("deleted file mode") {
                    f.is_delete = true;
                } else if t.starts_with("rename from ") {
                    f.is_rename = true;
                    f.old_name = t["rename from ".len()..].to_string();
                } else if t.starts_with("rename to ") {
                    f.is_rename = true;
                    f.new_name = t["rename to ".len()..].to_string();
                } else if t.starts_with("Binary files ") || t.starts_with("GIT binary patch") {
                    f.is_binary = true;
                } else if let Some(p) = t.strip_prefix("--- ") {
                    if p != "/dev/null" {
                        f.old_name = strip_ab_prefix(p);
                    }
                } else if let Some(p) = t.strip_prefix("+++ ") {
                    if p == "/dev/null" {
                        f.is_delete = true;
                    } else {
                        f.new_name = strip_ab_prefix(p);
                    }
                }
                i += 1;
            }

            // Hunks.
            while i < lines.len() {
                let t = trim_newline(lines[i]);
                if t.starts_with("diff --git ") || t.starts_with("commit ") {
                    break;
                }
                if !t.starts_with("@@") {
                    i += 1;
                    continue;
                }
                let Some(mut frag) = parse_hunk_header(t) else {
                    i += 1;
                    continue;
                };
                i += 1;
                while i < lines.len() {
                    let raw = lines[i];
                    let t = trim_newline(raw);
                    if t.starts_with("@@")
                        || t.starts_with("diff --git ")
                        || t.starts_with("commit ")
                    {
                        break;
                    }
                    // `\ No newline at end of file` annotates the PREVIOUS line
                    // and is not content.
                    if t.starts_with('\\') {
                        i += 1;
                        continue;
                    }
                    let (op, body) = match raw.as_bytes().first() {
                        Some(b'+') => (Op::Add, &raw[1..]),
                        Some(b'-') => (Op::Delete, &raw[1..]),
                        Some(b' ') => (Op::Context, &raw[1..]),
                        // An empty line inside a hunk is a context line whose
                        // single space git trimmed.
                        Some(b'\n') | None => (Op::Context, raw),
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    frag.lines.push(Line { op, text: body.to_string() });
                    i += 1;
                }
                f.text_fragments.push(frag);
            }

            files.push(f);
            continue;
        }

        i += 1;
    }

    files
}

/// Collect the commit attributes betterleaks stamps on a fragment.
///
/// Kept here so the mapping from a parsed header to attribute KEYS lives beside
/// the parser it reads from.
pub fn commit_attributes(h: &PatchHeader) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("git.sha".to_string(), h.sha.clone());
    m.insert("git.message".to_string(), h.message.clone());
    if !h.author_date.is_empty() {
        m.insert("git.date".to_string(), h.author_date.clone());
    }
    if !h.author_name.is_empty() {
        m.insert("git.author_name".to_string(), h.author_name.clone());
    }
    if !h.author_email.is_empty() {
        m.insert("git.author_email".to_string(), h.author_email.clone());
    }
    m
}

fn trim_newline(s: &str) -> &str {
    s.trim_end_matches('\n').trim_end_matches('\r')
}

/// `Name <email>` → (name, email). A missing `<…>` leaves the email empty
/// rather than mangling the name.
fn split_author(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some(open) = s.rfind('<') {
        if let Some(close) = s[open..].find('>') {
            let name = s[..open].trim().to_string();
            let email = s[open + 1..open + close].to_string();
            return (name, email);
        }
    }
    (s.to_string(), String::new())
}

/// Strip git's `a/` or `b/` path prefix.
fn strip_ab_prefix(p: &str) -> String {
    let p = p.trim();
    // Only strip a real prefix; a file genuinely named `a/...` keeps its path
    // because git would have written `a/a/...`.
    if let Some(r) = p.strip_prefix("a/") {
        return r.to_string();
    }
    if let Some(r) = p.strip_prefix("b/") {
        return r.to_string();
    }
    p.to_string()
}

/// `a/x b/x` → (x, x). Paths containing spaces are why this splits on ` b/`
/// rather than on whitespace.
fn split_diff_git_paths(rest: &str) -> (String, String) {
    if let Some(idx) = rest.find(" b/") {
        let old = strip_ab_prefix(&rest[..idx]);
        let new = strip_ab_prefix(&rest[idx + 1..]);
        return (old, new);
    }
    let mut it = rest.split_whitespace();
    let a = it.next().unwrap_or("");
    let b = it.next().unwrap_or(a);
    (strip_ab_prefix(a), strip_ab_prefix(b))
}

/// `@@ -12,7 +12,9 @@ optional section heading` → positions and counts.
///
/// A count may be omitted (`@@ -1 +1 @@`), which means 1.
fn parse_hunk_header(t: &str) -> Option<TextFragment> {
    let body = t.strip_prefix("@@")?;
    let end = body.find("@@")?;
    let spec = body[..end].trim();

    let mut old = (0i64, 1i64);
    let mut new = (0i64, 1i64);
    for part in spec.split_whitespace() {
        if let Some(v) = part.strip_prefix('-') {
            old = parse_pos(v)?;
        } else if let Some(v) = part.strip_prefix('+') {
            new = parse_pos(v)?;
        }
    }
    Some(TextFragment {
        old_position: old.0,
        old_lines: old.1,
        new_position: new.0,
        new_lines: new.1,
        lines: Vec::new(),
    })
}

fn parse_pos(v: &str) -> Option<(i64, i64)> {
    match v.split_once(',') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => Some((v.parse().ok()?, 1)),
    }
}

#[cfg(test)]
mod tests;
