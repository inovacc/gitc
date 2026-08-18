//! Port of Go `config/allowlist.go` + `config/translate_filters.go`.
//!
//! **Why this matters more than the earlier deferral suggested.** The previous
//! note justified skipping allowlists because "the shipped catalogue contains
//! zero allowlists". That is true of the CATALOGUE and irrelevant in practice:
//! allowlists are what USER configs are made of. betterleaks' own repository
//! ships a `.betterleaks.toml` whose entire content is an allowlist, and without
//! it a scan of that tree reports 559 findings instead of 1.
//!
//! Allowlists are not evaluated directly. Go TRANSLATES them into the same
//! filter-expression language everything else uses, so there is one evaluator
//! rather than two subtly different ones. Each generated sub-expression means
//! **"suppress when true"**:
//!
//! ```text
//! paths     → matchesAny(attributes["path"], [`re`, …])   (prefilter)
//! commits   → attributes["git.sha"] in ["sha", …]         (prefilter)
//! regexes   → matchesAny(finding["secret"], [`re`, …])    (filter)
//! stopwords → containsAny(finding["secret"], ["w", …])    (filter)
//! ```
//!
//! The prefilter/filter split is the load-bearing part: path and commit are
//! ATTRIBUTE-only, so they can suppress a fragment before any regex runs, while
//! regex and stopword checks need a finding and must wait.

use std::fmt::Write as _;

/// Go `AllowlistMatchCondition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchCondition {
    /// Any condition suppresses. Go's default.
    #[default]
    Or,
    /// Every condition must match to suppress.
    And,
}

/// Go `config.Allowlist`.
///
/// Patterns are kept as SOURCE STRINGS rather than compiled regexes: the only
/// thing translation does with them is `.String()`, and compiling twice (once
/// here, once in the generated expression) would be wasted work plus a second
/// place for a pattern to be rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    pub description: String,
    pub match_condition: MatchCondition,
    pub commits: Vec<String>,
    pub paths: Vec<String>,
    /// `match`, `line`, or empty for the secret itself.
    pub regex_target: String,
    pub regexes: Vec<String>,
    pub stopwords: Vec<String>,
    /// Rules this allowlist targets. A non-empty list keeps it OUT of the global
    /// set and attaches it to those rules instead.
    pub target_rules: Vec<String>,
}

impl Allowlist {
    /// Go `(*Allowlist).Validate` — an allowlist that checks nothing is a
    /// config error, not a no-op. A silently-empty allowlist would look like
    /// suppression that never fires.
    pub fn validate(&self) -> Result<(), String> {
        if self.commits.is_empty()
            && self.paths.is_empty()
            && self.regexes.is_empty()
            && self.stopwords.is_empty()
        {
            return Err(
                "must contain at least one check for: commits, paths, regexes, or stopwords"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Go's Validate also normalises: commits are lower-cased and deduplicated
    /// (they are compared case-insensitively), as are stopwords.
    pub fn normalized(&self) -> Allowlist {
        let mut a = self.clone();
        a.commits = dedup_lower(&a.commits);
        a.stopwords = dedup_lower(&a.stopwords);
        a
    }
}

/// Lower-case + deduplicate, preserving first-seen order.
///
/// Go builds a map and takes its keys, so its order is RANDOM; this keeps input
/// order so the generated expression is stable and diffable. A deliberate
/// divergence with no semantic effect — the list is a membership test.
fn dedup_lower(items: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for it in items {
        let k = it.trim().to_lowercase();
        if seen.insert(k.clone()) {
            out.push(k);
        }
    }
    out
}

/// Go `translateAllowlist` — one allowlist into (prefilter parts, filter parts).
pub fn translate_allowlist(a: &Allowlist) -> (Vec<String>, Vec<String>) {
    let a = a.normalized();
    let mut path_parts = Vec::new();
    let mut commit_parts = Vec::new();
    let mut regex_parts = Vec::new();
    let mut stop_parts = Vec::new();

    if !a.paths.is_empty() {
        path_parts.push(format!(
            "matchesAny(attributes[\"path\"], {})",
            expr_regex_list(&a.paths)
        ));
    }
    if !a.commits.is_empty() {
        commit_parts.push(format!(
            "attributes[\"git.sha\"] in {}",
            expr_string_list(&a.commits)
        ));
    }
    if !a.regexes.is_empty() {
        let target = if a.regex_target.is_empty() {
            "secret"
        } else {
            &a.regex_target
        };
        regex_parts.push(format!(
            "matchesAny(finding[{}], {})",
            expr_string_lit(target),
            expr_regex_list(&a.regexes)
        ));
    }
    if !a.stopwords.is_empty() {
        stop_parts.push(format!(
            "containsAny(finding[\"secret\"], {})",
            expr_string_list(&a.stopwords)
        ));
    }

    let mut prefilter_parts = Vec::new();
    let mut filter_parts = Vec::new();

    if a.match_condition == MatchCondition::And {
        // Every condition must hold, so the whole thing must be evaluated
        // together in the FILTER. Putting the path half in the prefilter would
        // suppress fragments the AND was never meant to reach.
        let all: Vec<String> = path_parts
            .into_iter()
            .chain(commit_parts)
            .chain(regex_parts)
            .chain(stop_parts)
            .collect();
        if !all.is_empty() {
            filter_parts.push(join_and(&all));
        }
    } else {
        if !path_parts.is_empty() || !commit_parts.is_empty() {
            let attrs: Vec<String> = path_parts.into_iter().chain(commit_parts).collect();
            prefilter_parts.push(join_or(&attrs));
        }
        if !regex_parts.is_empty() || !stop_parts.is_empty() {
            let finds: Vec<String> = regex_parts.into_iter().chain(stop_parts).collect();
            filter_parts.push(join_or(&finds));
        }
    }

    (prefilter_parts, filter_parts)
}

/// Go `translateAllowlistSlice`.
pub fn translate_allowlist_slice(allowlists: &[Allowlist]) -> (Vec<String>, Vec<String>) {
    let mut pre = Vec::new();
    let mut fil = Vec::new();
    for a in allowlists {
        let (p, f) = translate_allowlist(a);
        pre.extend(p);
        fil.extend(f);
    }
    (pre, fil)
}

/// Go `composeFilters` — OR the skip predicates together with any user
/// expression, joined by a NEWLINE + `|| `.
///
/// A user expression beginning with `let ` is PARENTHESISED when there is
/// anything to OR it with, because `let x = …; expr || other` would otherwise
/// bind the wrong way.
pub fn compose_filters(skip_parts: &[String], user_expr: &str) -> String {
    let mut parts: Vec<String> = skip_parts.to_vec();
    if !user_expr.is_empty() {
        if !parts.is_empty() && starts_with_let(user_expr) {
            parts.push(format!("({user_expr})"));
        } else {
            parts.push(user_expr.to_string());
        }
    }
    if parts.len() <= 1 {
        return parts.join("");
    }
    parts.join("\n|| ")
}

/// Go `startsWithLet` — skipping any leading `//` comment lines.
fn starts_with_let(expr: &str) -> bool {
    let mut e = expr.trim_start();
    while e.starts_with("//") {
        match e.find('\n') {
            Some(nl) => e = e[nl + 1..].trim_start(),
            None => return false,
        }
    }
    e.starts_with("let ")
}

/// Go `exprRegexLit` — backticks preferred for readability, quoted only when the
/// pattern itself contains a backtick.
fn expr_regex_lit(s: &str) -> String {
    if !s.contains('`') {
        format!("`{s}`")
    } else {
        quote(s)
    }
}

fn expr_string_lit(s: &str) -> String {
    quote(s)
}

/// Go `strconv.Quote` for the inputs this actually sees — paths, rule ids,
/// stopwords and commit SHAs.
///
/// **Narrowing (flagged):** the escape set covers ASCII control characters and
/// the two characters that must be escaped. Go additionally escapes
/// non-printable NON-ASCII as `\uXXXX`; here such a character is passed through
/// literally, which the expression lexer accepts. Divergent only for an
/// allowlist containing unprintable Unicode.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn expr_regex_list(ss: &[String]) -> String {
    expr_list_lit(ss, expr_regex_lit)
}

fn expr_string_list(ss: &[String]) -> String {
    expr_list_lit(ss, expr_string_lit)
}

/// Go `exprListLit` — a single element stays inline; several are laid out one
/// per line, which is what makes a translated expression readable in a debug log.
fn expr_list_lit(ss: &[String], lit: fn(&str) -> String) -> String {
    let parts: Vec<String> = ss.iter().map(|s| lit(s)).collect();
    if parts.len() <= 1 {
        return format!("[{}]", parts.join(", "));
    }
    let mut b = String::from("[\n");
    for (i, p) in parts.iter().enumerate() {
        b.push_str("  ");
        b.push_str(p);
        if i < parts.len() - 1 {
            b.push(',');
        }
        b.push('\n');
    }
    b.push(']');
    b
}

fn join_or(parts: &[String]) -> String {
    if parts.len() == 1 {
        return parts[0].clone();
    }
    format!("({})", parts.join(" || "))
}

fn join_and(parts: &[String]) -> String {
    if parts.len() == 1 {
        return parts[0].clone();
    }
    format!("({})", parts.join(" && "))
}

#[cfg(test)]
mod tests;
