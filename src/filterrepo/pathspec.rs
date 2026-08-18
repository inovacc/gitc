//! Path filtering + renaming rules (Rust port of git-filter-repo's --path engine).
//!
//! An ordered set of path filtering + renaming rules — the union of
//! git-filter-repo's `--path` / `--path-glob` / `--path-regex` / `--path-rename`
//! plus `--invert-paths`. Pure: [`PathSpec::new_name`] performs no I/O. Uses
//! `regex::bytes` because paths are raw bytes, not guaranteed UTF-8.

use std::error::Error;
use std::fmt;
use std::io::BufRead;

use regex::bytes::Regex;

use super::bytesutil::{decode, glob_to_regex};

/// Selection ("filter") vs renaming ("rename") rules.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PathMod {
    Filter,
    Rename,
}

/// The matching style of a rule.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PathKind {
    /// Exact path / leading-directory match.
    Match,
    /// Shell glob (fnmatch), compiled to an anchored regex.
    Glob,
    /// Arbitrary regular expression (unanchored search).
    Regex,
}

/// A single path selection or renaming directive (opaque; built via `add_*`).
struct PathRule {
    mod_: PathMod,
    kind: PathKind,
    /// Raw expression for `Match` (filter or rename source).
    match_: Vec<u8>,
    /// Rename replacement (`Match`/`Regex` renames).
    repl: Vec<u8>,
    /// Compiled matcher for `Glob` / `Regex`.
    re: Option<Regex>,
}

/// Error from building a [`PathSpec`] (invalid path, or a regex RE2 rejects).
#[derive(Debug)]
pub struct PathSpecError(pub String);

impl fmt::Display for PathSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PathSpecError {}

/// An ordered set of path filtering and renaming rules.
#[derive(Default)]
pub struct PathSpec {
    rules: Vec<PathRule>,
    /// Whether any filter (selection) rule was added.
    has_filter: bool,
    /// `--invert-paths`: when true, files matching a filter rule are dropped
    /// instead of kept. Only meaningful when at least one filter rule exists.
    pub invert: bool,
}

impl PathSpec {
    /// An empty spec that keeps every path.
    pub fn new() -> Self {
        PathSpec::default()
    }

    /// Add an exact path (file or leading directory) selection rule (`--path`).
    pub fn add_match(&mut self, path: &[u8]) -> Result<(), PathSpecError> {
        validate_path(path)?;
        self.rules.push(PathRule {
            mod_: PathMod::Filter,
            kind: PathKind::Match,
            match_: path.to_vec(),
            repl: Vec::new(),
            re: None,
        });
        self.has_filter = true;
        Ok(())
    }

    /// Add a glob selection rule (`--path-glob`). A glob not ending in `*` also
    /// matches everything beneath it: an extra `glob+"/*"` (or `glob+"*"` when it
    /// ends in `/`) rule is appended so a directory glob selects its contents too.
    pub fn add_glob(&mut self, glob: &[u8]) -> Result<(), PathSpecError> {
        validate_path(glob)?;
        let re = compile_glob_rule(glob)?;
        self.rules.push(PathRule {
            mod_: PathMod::Filter,
            kind: PathKind::Glob,
            match_: glob.to_vec(),
            repl: Vec::new(),
            re: Some(re),
        });
        self.has_filter = true;

        if !glob.ends_with(b"*") {
            let ext: &[u8] = if glob.ends_with(b"/") { b"*" } else { b"/*" };
            let mut extended = glob.to_vec();
            extended.extend_from_slice(ext);
            let re2 = compile_glob_rule(&extended)?;
            self.rules.push(PathRule {
                mod_: PathMod::Filter,
                kind: PathKind::Glob,
                match_: extended,
                repl: Vec::new(),
                re: Some(re2),
            });
        }
        Ok(())
    }

    /// Add a regular-expression selection rule (`--path-regex`), searched
    /// (unanchored) against each path.
    pub fn add_regex(&mut self, pattern: &[u8]) -> Result<(), PathSpecError> {
        validate_path(pattern)?;
        let re = compile_path_regex(pattern)?;
        self.rules.push(PathRule {
            mod_: PathMod::Filter,
            kind: PathKind::Regex,
            match_: Vec::new(),
            repl: Vec::new(),
            re: Some(re),
        });
        self.has_filter = true;
        Ok(())
    }

    /// Add an exact-match renaming rule (`--path-rename`): a path matching `old`
    /// (as a file or leading directory) has its first occurrence of `old`
    /// rewritten to `dst`.
    pub fn add_rename(&mut self, old: &[u8], dst: &[u8]) -> Result<(), PathSpecError> {
        validate_rename(old, dst)?;
        self.rules.push(PathRule {
            mod_: PathMod::Rename,
            kind: PathKind::Match,
            match_: old.to_vec(),
            repl: dst.to_vec(),
            re: None,
        });
        Ok(())
    }

    /// Add a regex renaming rule. Every match of `pattern` is replaced by `repl`;
    /// Python-style numeric backreferences (`\1`) in `repl` are translated to
    /// Rust/RE2 `${1}` form.
    pub fn add_rename_regex(&mut self, pattern: &[u8], repl: &[u8]) -> Result<(), PathSpecError> {
        let re = compile_path_regex(pattern)?;
        self.rules.push(PathRule {
            mod_: PathMod::Rename,
            kind: PathKind::Regex,
            match_: Vec::new(),
            repl: translate_backrefs(repl),
            re: Some(re),
        });
        Ok(())
    }

    /// Parse a paths file (one directive per line, `--paths-from-file`) and append
    /// the rules. Blank + `#` lines ignored; a line may be prefixed `regex:`,
    /// `glob:`, or `literal:` (default) and may contain `==>` for a rename.
    pub fn add_from_file(&mut self, filename: &str) -> Result<(), PathSpecError> {
        let f = std::fs::File::open(filename).map_err(|e| PathSpecError(e.to_string()))?;
        self.add_from_reader(std::io::BufReader::new(f))
    }

    /// The byte-oriented core of [`add_from_file`], exercised directly in tests.
    pub fn add_from_reader(&mut self, mut r: impl BufRead) -> Result<(), PathSpecError> {
        loop {
            let mut line = Vec::new();
            let n = r
                .read_until(b'\n', &mut line)
                .map_err(|e| PathSpecError(e.to_string()))?;
            if !line.is_empty() {
                self.add_line(&line)?;
            }
            if n == 0 {
                return Ok(());
            }
        }
    }

    fn add_line(&mut self, line: &[u8]) -> Result<(), PathSpecError> {
        let line = trim_end_crlf(line);
        if line.is_empty() || line[0] == b'#' {
            return Ok(());
        }

        let (mut work, repl, has_repl) = match last_index(line, b"==>") {
            Some(idx) => (&line[..idx], line[idx + 3..].to_vec(), true),
            None => (line, Vec::new(), false),
        };

        if let Some(pat) = work.strip_prefix(b"regex:") {
            return if has_repl {
                self.add_rename_regex(pat, &repl)
            } else {
                self.add_regex(pat)
            };
        }
        if let Some(g) = work.strip_prefix(b"glob:") {
            if has_repl {
                return Err(PathSpecError(
                    "'glob:' and '==>' are incompatible (renaming globs makes no sense)"
                        .to_string(),
                ));
            }
            return self.add_glob(g);
        }
        if let Some(m) = work.strip_prefix(b"literal:") {
            work = m;
        }
        if has_repl {
            return self.add_rename(work, &repl);
        }
        if work.is_empty() {
            return Ok(());
        }
        self.add_match(work)
    }

    /// Apply every rule in order and report the resulting name if the path is
    /// kept (`None` = dropped). Reproduces git-filter-repo's `newname()`.
    pub fn new_name(&self, path: &[u8]) -> Option<Vec<u8>> {
        let mut wanted = false;
        let mut name = path.to_vec();

        for r in &self.rules {
            match r.mod_ {
                PathMod::Filter => {
                    if wanted {
                        continue;
                    }
                    match r.kind {
                        PathKind::Match => {
                            if filename_matches(&r.match_, &name) {
                                wanted = true;
                            }
                        }
                        PathKind::Glob | PathKind::Regex => {
                            if r.re.as_ref().is_some_and(|re| re.is_match(&name)) {
                                wanted = true;
                            }
                        }
                    }
                }
                PathMod::Rename => match r.kind {
                    PathKind::Match => {
                        if filename_matches(&r.match_, &name) {
                            name = replace_first(&name, &r.match_, &r.repl);
                        }
                    }
                    PathKind::Regex => {
                        if let Some(re) = &r.re {
                            name = re.replace_all(&name, r.repl.as_slice()).into_owned();
                        }
                    }
                    PathKind::Glob => {}
                },
            }
        }

        if wanted == self.inclusive() {
            Some(name)
        } else {
            None
        }
    }

    /// The effective selection polarity: inclusive only when not inverted and at
    /// least one filter rule exists (otherwise every non-inverted path is kept).
    fn inclusive(&self) -> bool {
        !self.invert && self.has_filter
    }
}

/// Whether `expr` matches `pathname` or a leading directory of it, tolerating a
/// missing trailing slash on a directory expression.
fn filename_matches(expr: &[u8], pathname: &[u8]) -> bool {
    if expr.is_empty() {
        return true;
    }
    let n = expr.len();
    if !pathname.starts_with(expr) {
        return false;
    }
    expr[n - 1] == b'/' || pathname.len() == n || pathname[n] == b'/'
}

/// `s` with the first occurrence of `old` replaced by `repl`.
fn replace_first(s: &[u8], old: &[u8], repl: &[u8]) -> Vec<u8> {
    match find_sub(s, old) {
        Some(i) => {
            let mut out = Vec::with_capacity(s.len() - old.len() + repl.len());
            out.extend_from_slice(&s[..i]);
            out.extend_from_slice(repl);
            out.extend_from_slice(&s[i + old.len()..]);
            out
        }
        None => s.to_vec(),
    }
}

/// Compile a shell glob to an anchored RE2 matcher.
fn compile_glob_rule(glob: &[u8]) -> Result<Regex, PathSpecError> {
    let src = glob_to_regex(glob);
    compile_bytes_regex(&src)
        .map_err(|e| PathSpecError(format!("invalid path glob {:?}: {e}", decode(glob))))
}

/// Compile a user-supplied regex, wrapping RE2 rejections with a clear message.
fn compile_path_regex(pattern: &[u8]) -> Result<Regex, PathSpecError> {
    compile_bytes_regex(pattern).map_err(|e| {
        PathSpecError(format!(
            "invalid path regex {:?} (RE2 does not support backreferences or lookaround): {e}",
            decode(pattern)
        ))
    })
}

/// Build a `regex::bytes::Regex` from a raw-byte pattern. A valid-UTF-8 pattern
/// is used directly (unicode-aware, matching Go); a non-UTF-8 pattern is made
/// byte-oriented (`(?-u)` + `\xNN` escapes) so raw bytes still match literally.
/// Shared with `replacetext` (both compile RE2 patterns the same way).
pub(super) fn compile_bytes_regex(pattern: &[u8]) -> Result<Regex, regex::Error> {
    match std::str::from_utf8(pattern) {
        Ok(s) => Regex::new(s),
        Err(_) => {
            let mut p = String::from("(?-u)");
            for &b in pattern {
                if b < 0x80 {
                    p.push(b as char);
                } else {
                    p.push_str(&format!("\\x{b:02x}"));
                }
            }
            Regex::new(&p)
        }
    }
}

/// Reject absolute paths and `.`/`..` components.
fn validate_path(p: &[u8]) -> Result<(), PathSpecError> {
    if p.starts_with(b"/") {
        return Err(PathSpecError(format!(
            "pathnames cannot begin with a '/': {:?}",
            decode(p)
        )));
    }
    for comp in p.split(|&b| b == b'/') {
        if comp == b"." || comp == b".." {
            return Err(PathSpecError(format!(
                "invalid path component {:?} found in {:?}",
                decode(comp),
                decode(p)
            )));
        }
    }
    Ok(())
}

/// Validate both sides of a `--path-rename` directive.
fn validate_rename(old: &[u8], dst: &[u8]) -> Result<(), PathSpecError> {
    validate_path(old)?;
    validate_path(dst)?;
    if !old.is_empty() && !dst.is_empty() && old.ends_with(b"/") != dst.ends_with(b"/") {
        return Err(PathSpecError(
            "when renaming, if OLD_NAME and NEW_NAME are both non-empty and either ends with a slash then both must".to_string(),
        ));
    }
    Ok(())
}

/// Rewrite Python-style `\N` backreferences to RE2 `${N}` and escape literal `$`
/// so it is not interpreted by `replace_all` (mirrors Go `translateBackrefs`).
fn translate_backrefs(repl: &[u8]) -> Vec<u8> {
    // First escape literal '$' as '$$'.
    let mut escaped = Vec::with_capacity(repl.len());
    for &b in repl {
        if b == b'$' {
            escaped.push(b'$');
        }
        escaped.push(b);
    }
    // Then rewrite \N / \NN -> ${N}.
    let mut out = Vec::with_capacity(escaped.len());
    let mut i = 0;
    while i < escaped.len() {
        if escaped[i] == b'\\' && i + 1 < escaped.len() && escaped[i + 1].is_ascii_digit() {
            let start = i + 1;
            let mut j = start;
            while j < escaped.len() && j < start + 2 && escaped[j].is_ascii_digit() {
                j += 1;
            }
            out.extend_from_slice(b"${");
            out.extend_from_slice(&escaped[start..j]);
            out.push(b'}');
            i = j;
        } else {
            out.push(escaped[i]);
            i += 1;
        }
    }
    out
}

fn trim_end_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn last_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(haystack.len());
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (keep, name) — name is empty when dropped.
    fn eval(s: &PathSpec, path: &[u8]) -> (bool, Vec<u8>) {
        match s.new_name(path) {
            Some(n) => (true, n),
            None => (false, Vec::new()),
        }
    }

    #[test]
    fn new_name_exact_match_table() {
        let one_match = |m: &[u8]| {
            let mut s = PathSpec::new();
            s.add_match(m).unwrap();
            s
        };

        assert_eq!(
            eval(&one_match(b"filename"), b"filename"),
            (true, b"filename".to_vec())
        );
        assert_eq!(eval(&one_match(b"filename"), b"other").0, false);
        assert_eq!(
            eval(&one_match(b"moduleA"), b"moduleA/keepme"),
            (true, b"moduleA/keepme".to_vec())
        );
        assert_eq!(eval(&one_match(b"mod"), b"moduleA").0, false); // prefix without boundary

        let mut two = PathSpec::new();
        two.add_match(b"ten").unwrap();
        two.add_match(b"twenty").unwrap();
        assert_eq!(eval(&two, b"twenty"), (true, b"twenty".to_vec()));

        assert_eq!(
            eval(&PathSpec::new(), b"anything/here"),
            (true, b"anything/here".to_vec())
        );
        assert_eq!(
            eval(&one_match(b""), b"whatever"),
            (true, b"whatever".to_vec())
        ); // empty match keeps all
    }

    #[test]
    fn glob_and_invert() {
        let mut s = PathSpec::new();
        s.add_glob(b"t*en*").unwrap();
        s.invert = true;
        assert_eq!(
            eval(&s, b"twenty").0,
            false,
            "twenty dropped under inverted glob"
        );
        assert_eq!(eval(&s, b"filename"), (true, b"filename".to_vec()));
    }

    #[test]
    fn glob_directory_extension() {
        let mut s = PathSpec::new();
        s.add_glob(b"moduleA").unwrap();
        assert_eq!(
            eval(&s, b"moduleA/keepme").0,
            true,
            "auto directory extension"
        );
    }

    #[test]
    fn regex_invert() {
        let mut s = PathSpec::new();
        s.add_regex(b"f.*e.*e").unwrap();
        s.invert = true;
        assert_eq!(
            eval(&s, b"filename").0,
            false,
            "match dropped when inverted"
        );
        assert_eq!(eval(&s, b"ten").0, true, "non-match kept when inverted");
    }

    #[test]
    fn regex_rejects_backref() {
        let mut s = PathSpec::new();
        assert!(
            s.add_regex(br"(a)\1").is_err(),
            "RE2 must reject a backreference"
        );
    }

    #[test]
    fn rename_exact() {
        let mut s = PathSpec::new();
        s.add_rename(b"sequences/tiny", b"sequences/small").unwrap();
        assert_eq!(
            eval(&s, b"sequences/tiny/one"),
            (true, b"sequences/small/one".to_vec())
        );
        assert_eq!(eval(&s, b"values/big"), (true, b"values/big".to_vec()));
    }

    #[test]
    fn rename_regex_backref() {
        let mut s = PathSpec::new();
        s.add_rename_regex(br"^([^/]*)/(.*)ge$", br"\2/\1/ge")
            .unwrap();
        assert_eq!(
            s.new_name(b"values/huge").unwrap(),
            b"hu/values/ge".to_vec()
        );
    }

    #[test]
    fn from_file_directives() {
        let mut spec = PathSpec::new();
        let input = b"# comment\n\nliteral:keepme\nglob:*.txt\n";
        spec.add_from_reader(&input[..]).unwrap();
        assert_eq!(eval(&spec, b"keepme").0, true);
        assert_eq!(eval(&spec, b"a/b.txt").0, true, "*.txt selects a/b.txt");
        assert_eq!(eval(&spec, b"other").0, false);

        let mut rename_spec = PathSpec::new();
        rename_spec
            .add_from_reader(&b"values/huge==>values/gargantuan\n"[..])
            .unwrap();
        assert_eq!(
            rename_spec.new_name(b"values/huge").unwrap(),
            b"values/gargantuan".to_vec()
        );
    }
}
