//! Port of Go `regexp/` — the project's regex FACADE (`regexp.go`,
//! `stdlib.go`, `internal/compiledregexp.go`).
//!
//! Two things make this a facade rather than a thin alias, and both are ported:
//!
//! 1. **Lazy compilation.** `Compile` validates the pattern and records its
//!    capture count, but does NOT build an engine program until the first match
//!    operation. A later engine failure degrades every accessor to a zero value
//!    instead of panicking.
//! 2. **Engine indirection.** The active engine is swappable at runtime.
//!
//! **Engine scope (verified, PORT-PLAN §7):** `regexp.go:96` gates every pattern
//! through `syntax.Parse(str, syntax.Perl)` and `regexp.go:88` defaults to Go's
//! stdlib engine, so no lookaround or backreference is reachable anywhere in the
//! codebase. Rust's `regex` (RE2 lineage, leftmost-first like Go's Perl-syntax
//! `regexp`) is the correct target.
//!
//! **`regexp/re2` and `regexp/internal` are now PORTED, not excluded.** They
//! were listed as excluded on the grounds that the WASM RE2 engine has identical
//! semantics — which is true, and is precisely why they port cleanly rather than
//! why they should be dropped. `internal.CompiledRegexp` is the
//! [`CompiledRegexp`] trait; `re2.RE2` is [`Re2`], delegating to the same
//! backend and reporting `"re2"` from [`Engine::version`]. Keeping the engine
//! REAL is what lets `--regex-engine` be honoured and reported honestly rather
//! than accepted and quietly ignored.
//!
//! **Known divergence carried forward (PORT-PLAN §7):** Go's `\w`/`\d`/`\s`/`\b`
//! are ASCII; Rust's are Unicode by default. This crate does NOT silently rewrite
//! patterns — that decision belongs to M9 (`config.full`), which owns the rule
//! catalogue and can apply selective `(?-u:…)`.

use std::fmt;
use std::sync::{Arc, OnceLock, RwLock};

/// Go's error from `syntax.Parse` / an engine `Compile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Error {
        Error(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Go `internal.CompiledRegexp` — the interface satisfied by both the stdlib
/// engine and go-re2.
///
/// **Reshape:** Go returns `nil` slices for "no match"; Rust models that as
/// `Option<Vec<…>>`, where `None` IS Go's nil. `[usize; 2]` replaces Go's
/// `[]int` pair.
pub trait CompiledRegexp: Send + Sync {
    fn is_match(&self, s: &str) -> bool;
    fn find(&self, s: &str) -> String;
    fn find_submatch(&self, s: &str) -> Option<Vec<String>>;
    fn find_all_index(&self, s: &str, n: i32) -> Option<Vec<[usize; 2]>>;
    fn replace_all(&self, src: &str, repl: &str) -> String;
    fn num_subexp(&self) -> usize;
    fn subexp_names(&self) -> Option<Vec<String>>;
    fn as_str(&self) -> &str;
}

/// Go `regexp.Engine`.
pub trait Engine: Send + Sync {
    fn compile(&self, s: &str) -> Result<Box<dyn CompiledRegexp>, Error>;
    fn version(&self) -> &str;
}

/// Go `regexp.Stdlib` — the engine backed by the language's own regex package.
pub struct Stdlib;

/// Compiled-program size ceiling for the stdlib engine.
///
/// **Why this is raised from the 10 MB default.** Go's `regexp` has NO
/// compile-size limit — it simulates an NFA and never builds the DFA tables
/// whose blow-up the Rust limit exists to bound. Two rules in the shipped
/// catalogue (`pypi-upload-token` and `vault-batch-token`, both products of
/// `MergeRegexps`) compile fine in Go and are REJECTED by Rust's default,
/// which would silently cost two rules' worth of detection.
///
/// 64 MB is chosen to clear those two comfortably while still bounding a
/// pathological pattern — dropping the limit entirely is not on the table.
/// PORT-PLAN §7 flagged this as unmeasured; it is now measured at exactly 2
/// rules.
const SIZE_LIMIT: usize = 64 * 1024 * 1024;

impl Engine for Stdlib {
    fn compile(&self, s: &str) -> Result<Box<dyn CompiledRegexp>, Error> {
        match regex::RegexBuilder::new(s).size_limit(SIZE_LIMIT).build() {
            Ok(re) => Ok(Box::new(StdlibRegexp(re))),
            Err(e) => Err(Error::new(e.to_string())),
        }
    }
    fn version(&self) -> &str {
        "stdlib"
    }
}

/// Go `regexp/re2.RE2` — the engine `--regex-engine re2` selects, and Go's
/// DEFAULT (`cmd/root.go:162-163`).
///
/// In Go this wraps `github.com/betterleaks/go-re2`, a WASM/cgo build of C++
/// RE2. Here it delegates to the same `regex` backend [`Stdlib`] uses, and that
/// is the faithful port rather than a shortcut: `go-re2` exists as a DROP-IN
/// replacement for Go's own `regexp` — `re2.go` returns a `gore2.Regexp` through
/// the very `internal.CompiledRegexp` interface `*regexp.Regexp` satisfies. The
/// two engines differ in throughput on large inputs, not in what they match;
/// neither backtracks and neither has lookaround, and Rust's `regex` is that
/// same RE2 lineage.
///
/// So the only thing that distinguishes them here is what [`Engine::version`]
/// reports, which is what Go's `using %s regex engine` debug line prints. It is
/// kept as a real, selectable engine rather than an alias so that line tells the
/// truth about which value the operator passed.
pub struct Re2;

impl Engine for Re2 {
    fn compile(&self, s: &str) -> Result<Box<dyn CompiledRegexp>, Error> {
        Stdlib.compile(s)
    }
    fn version(&self) -> &str {
        "re2"
    }
}

struct StdlibRegexp(regex::Regex);

impl CompiledRegexp for StdlibRegexp {
    fn is_match(&self, s: &str) -> bool {
        self.0.is_match(s)
    }

    /// Go `FindString` returns "" when there is no match — indistinguishable
    /// from an empty match, exactly as upstream.
    fn find(&self, s: &str) -> String {
        self.0.find(s).map(|m| m.as_str().to_string()).unwrap_or_default()
    }

    /// Go `FindStringSubmatch` returns nil on no match. A group that did not
    /// participate is "" in Go, so a non-participating Rust `None` maps to "".
    fn find_submatch(&self, s: &str) -> Option<Vec<String>> {
        let caps = self.0.captures(s)?;
        Some(
            caps.iter()
                .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                .collect(),
        )
    }

    /// Go `FindAllStringIndex(s, n)`: n < 0 means all; n == 0 yields nil; no
    /// match at all yields nil.
    fn find_all_index(&self, s: &str, n: i32) -> Option<Vec<[usize; 2]>> {
        if n == 0 {
            return None;
        }
        let mut out = Vec::new();
        for m in self.0.find_iter(s) {
            out.push([m.start(), m.end()]);
            if n > 0 && out.len() >= n as usize {
                break;
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    fn replace_all(&self, src: &str, repl: &str) -> String {
        self.0.replace_all(src, repl).into_owned()
    }

    fn num_subexp(&self) -> usize {
        // `captures_len` counts the implicit whole-match group; Go's NumSubexp
        // does not.
        self.0.captures_len().saturating_sub(1)
    }

    /// Go `SubexpNames`: index 0 is the whole match (always ""), and unnamed
    /// groups contribute "".
    fn subexp_names(&self) -> Option<Vec<String>> {
        Some(
            self.0
                .capture_names()
                .map(|n| n.unwrap_or("").to_string())
                .collect(),
        )
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Go's package-level `currentEngine`.
///
/// **Reshape:** Go uses a bare package `var` (racy by construction, set at
/// startup). Rust needs interior mutability to allow the same swap, so this is
/// an `RwLock<Arc<dyn Engine>>` — strictly safer, same observable behaviour.
fn engine_slot() -> &'static RwLock<Arc<dyn Engine>> {
    static SLOT: OnceLock<RwLock<Arc<dyn Engine>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(Stdlib)))
}

/// The engine subsequent `compile` calls will bind to.
pub fn current_engine() -> Arc<dyn Engine> {
    engine_slot().read().expect("engine lock").clone()
}

/// Go `SetEngine`.
pub fn set_engine(e: Arc<dyn Engine>) {
    *engine_slot().write().expect("engine lock") = e;
}

/// Go `Version` — the name of the active regex engine.
pub fn version() -> String {
    current_engine().version().to_string()
}

/// Go `regexp.Regexp` — a pattern whose compilation is deferred to first use.
pub struct Regexp {
    pattern: String,
    engine: Arc<dyn Engine>,
    num_subexp: usize,
    /// Go's `sync.Once` + (`e`, `err`) pair.
    compiled: OnceLock<Result<Box<dyn CompiledRegexp>, Error>>,
}

impl Regexp {
    /// Go's private `compiled()` — run the once-only engine compile and report
    /// whether a usable program came out.
    fn compiled(&self) -> Option<&dyn CompiledRegexp> {
        match self.compiled.get_or_init(|| self.engine.compile(&self.pattern)) {
            Ok(c) => Some(c.as_ref()),
            Err(_) => None,
        }
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.compiled().is_some_and(|e| e.is_match(s))
    }

    pub fn find(&self, s: &str) -> String {
        self.compiled().map(|e| e.find(s)).unwrap_or_default()
    }

    pub fn find_submatch(&self, s: &str) -> Option<Vec<String>> {
        self.compiled()?.find_submatch(s)
    }

    pub fn find_all_index(&self, s: &str, n: i32) -> Option<Vec<[usize; 2]>> {
        self.compiled()?.find_all_index(s, n)
    }

    /// Go returns the SOURCE unchanged when the engine failed to compile.
    pub fn replace_all(&self, src: &str, repl: &str) -> String {
        match self.compiled() {
            Some(e) => e.replace_all(src, repl),
            None => src.to_string(),
        }
    }

    /// Go `NumSubexp` — precomputed at `Compile` time, so it never triggers an
    /// engine compile.
    pub fn num_subexp(&self) -> usize {
        self.num_subexp
    }

    pub fn subexp_names(&self) -> Option<Vec<String>> {
        self.compiled()?.subexp_names()
    }

    /// Go `String` — the original pattern; never triggers an engine compile.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Go's `Regexp.Compile()` — force compilation and surface the error.
    /// Renamed from `compile` to avoid colliding with the free function.
    pub fn force_compile(&self) -> Result<(), Error> {
        match self.compiled.get_or_init(|| self.engine.compile(&self.pattern)) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.clone()),
        }
    }
}

impl fmt::Display for Regexp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

/// Hand-written because the lazily-compiled program (`OnceLock<Result<Box<dyn
/// CompiledRegexp>, _>>`) and the engine handle are not `Debug`. Reports the
/// pattern plus the compilation state WITHOUT forcing compilation — a `Debug`
/// print must not have the side effect the whole facade exists to defer.
impl fmt::Debug for Regexp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.compiled.get() {
            None => "uncompiled",
            Some(Ok(_)) => "compiled",
            Some(Err(_)) => "compile-failed",
        };
        f.debug_struct("Regexp")
            .field("pattern", &self.pattern)
            .field("num_subexp", &self.num_subexp)
            .field("state", &state)
            .finish()
    }
}

/// Go `Compile` — parse the pattern for validity and capture count, bind the
/// CURRENT engine, but do not build a program yet.
pub fn compile(pattern: &str) -> Result<Regexp, Error> {
    let num_subexp = count_capturing_groups(pattern)?;
    Ok(Regexp {
        pattern: pattern.to_string(),
        engine: current_engine(),
        num_subexp,
        compiled: OnceLock::new(),
    })
}

/// Go `MustCompile`.
pub fn must_compile(pattern: &str) -> Regexp {
    compile(pattern).unwrap_or_else(|e| panic!("{e}"))
}

/// Go's `syntax.Parse(str, syntax.Perl)` + `parsed.MaxCap()`.
///
/// This must NOT go through the engine: `TestCompileIsLazy` asserts
/// `NumSubexp()` is available with ZERO engine compiles. `regex-syntax` parses
/// to an AST we can walk for capture indices.
fn count_capturing_groups(pattern: &str) -> Result<usize, Error> {
    let ast = regex_syntax::ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|e| Error::new(e.to_string()))?;
    let mut max = 0usize;
    walk_ast(&ast, &mut max);
    Ok(max)
}

fn walk_ast(ast: &regex_syntax::ast::Ast, max: &mut usize) {
    use regex_syntax::ast::{Ast, GroupKind};
    match ast {
        Ast::Group(g) => {
            match &g.kind {
                GroupKind::CaptureIndex(i) => *max = (*max).max(*i as usize),
                GroupKind::CaptureName { name, .. } => *max = (*max).max(name.index as usize),
                GroupKind::NonCapturing(_) => {}
            }
            walk_ast(&g.ast, max);
        }
        Ast::Alternation(a) => a.asts.iter().for_each(|c| walk_ast(c, max)),
        Ast::Concat(c) => c.asts.iter().for_each(|c| walk_ast(c, max)),
        Ast::Repetition(r) => walk_ast(&r.ast, max),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
