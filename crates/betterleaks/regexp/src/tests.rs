//! Faithful port of Go `regexp/regexp_test.go` — all three tests — plus
//! characterization of the delegating methods the Go tests only touch on the
//! failure path.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Go runs a package's test functions SEQUENTIALLY unless they opt in with
/// `t.Parallel()`, so its `SetEngine`/`defer SetEngine(previous)` dance is safe.
/// Rust runs tests in parallel THREADS of one process, and the active engine is
/// process-global — so without this every engine-swapping test corrupts its
/// neighbours. Taking one lock per test restores Go's sequential semantics; it
/// is a HARNESS adaptation, not a behaviour change.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    // A panicking test poisons the lock; the data is `()`, so recover and carry on.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Port of Go's `countingEngine`: delegates to Stdlib but counts compiles.
#[derive(Default)]
struct CountingEngine {
    compiles: AtomicUsize,
}

impl Engine for CountingEngine {
    fn compile(&self, s: &str) -> Result<Box<dyn CompiledRegexp>, Error> {
        self.compiles.fetch_add(1, Ordering::SeqCst);
        Stdlib.compile(s)
    }
    fn version(&self) -> &str {
        "counting"
    }
}

/// Port of Go's `failingEngine`.
struct FailingEngine;

impl Engine for FailingEngine {
    fn compile(&self, _s: &str) -> Result<Box<dyn CompiledRegexp>, Error> {
        Err(Error::new("compile failed"))
    }
    fn version(&self) -> &str {
        "failing"
    }
}

/// Restore the previous engine on drop, mirroring Go's `defer SetEngine(previous)`.
struct EngineGuard(Arc<dyn Engine>);
impl EngineGuard {
    fn install(e: Arc<dyn Engine>) -> EngineGuard {
        let previous = current_engine();
        set_engine(e);
        EngineGuard(previous)
    }
}
impl Drop for EngineGuard {
    fn drop(&mut self) {
        set_engine(self.0.clone());
    }
}

/// Port of Go `TestCompileIsLazy`. Compilation is deferred until the first match
/// operation; metadata access (`String`, `NumSubexp`) must NOT trigger it, and a
/// second match operation must NOT recompile.
#[test]
fn compile_is_lazy() {
    let _serial = serial();
    let engine = Arc::new(CountingEngine::default());
    let _guard = EngineGuard::install(engine.clone());

    let re = compile(r"(foo)(bar)?").expect("compile");
    assert_eq!(
        engine.compiles.load(Ordering::SeqCst),
        0,
        "Compile compiled regex eagerly"
    );
    assert_eq!(re.as_str(), r"(foo)(bar)?", "String changed pattern");
    assert_eq!(re.num_subexp(), 2, "NumSubexp");
    assert_eq!(
        engine.compiles.load(Ordering::SeqCst),
        0,
        "metadata access compiled regex eagerly"
    );

    assert!(re.is_match("foobar"), "MatchString returned false");
    assert_eq!(engine.compiles.load(Ordering::SeqCst), 1, "compiles");

    let _ = re.find("foobar");
    assert_eq!(
        engine.compiles.load(Ordering::SeqCst),
        1,
        "regex compiled more than once"
    );
}

/// Port of Go `TestLazyCompileFailureDoesNotPanic`. Every accessor degrades to a
/// zero value after a compile failure — and `ReplaceAllString` returns the
/// SOURCE unchanged, not the empty string.
#[test]
fn lazy_compile_failure_does_not_panic() {
    let _serial = serial();
    let _guard = EngineGuard::install(Arc::new(FailingEngine));

    let re = compile("foo").expect("Compile itself must still succeed");
    assert!(!re.is_match("foo"), "MatchString returned true");
    assert_eq!(re.find("foo"), "", "FindString");
    assert_eq!(re.find_submatch("foo"), None, "FindStringSubmatch");
    assert_eq!(re.find_all_index("foo", -1), None, "FindAllStringIndex");
    assert_eq!(
        re.replace_all("foo", "bar"),
        "foo",
        "ReplaceAllString must return the original"
    );
    assert_eq!(re.subexp_names(), None, "SubexpNames");
}

/// Port of Go `TestCompileReturnsLazyCompileError`. `Compile()` on the Regexp
/// forces compilation and surfaces the engine's error.
#[test]
fn compile_returns_lazy_compile_error() {
    let _serial = serial();
    let _guard = EngineGuard::install(Arc::new(FailingEngine));

    let re = compile("foo").expect("Compile");
    assert!(
        re.force_compile().is_err(),
        "Compile returned nil after engine compile failure"
    );
}

/// Characterization: `Compile` rejects a syntactically invalid pattern UP FRONT
/// (Go returns `syntax.Parse`'s error before ever building a Regexp).
#[test]
fn compile_rejects_invalid_pattern() {
    let _serial = serial();
    assert!(compile("(unclosed").is_err());
    assert!(compile("a{2,1}").is_err());
}

/// Characterization: `NumSubexp` counts capturing groups only — non-capturing
/// `(?:…)` groups do not count, named groups do.
#[test]
fn num_subexp_counts_capturing_groups_only() {
    let _serial = serial();
    assert_eq!(compile("foo").unwrap().num_subexp(), 0);
    assert_eq!(compile("(a)").unwrap().num_subexp(), 1);
    assert_eq!(compile("(?:a)").unwrap().num_subexp(), 0);
    assert_eq!(compile("(a)(?:b)(c)").unwrap().num_subexp(), 2);
    assert_eq!(compile("(?P<name>a)(b)").unwrap().num_subexp(), 2);
    assert_eq!(compile("((a)(b))").unwrap().num_subexp(), 3);
}

/// Characterization of the happy path through the default Stdlib engine — the
/// Go tests only exercise these via the counting/failing engines.
#[test]
fn stdlib_engine_delegation() {
    let _serial = serial();
    let re = compile(r"(\w+)@(\w+)").expect("compile");
    assert!(re.is_match("user@host"));
    assert_eq!(re.find("say user@host now"), "user@host");
    assert_eq!(
        re.find_submatch("user@host"),
        Some(vec![
            "user@host".to_string(),
            "user".to_string(),
            "host".to_string()
        ])
    );
    assert_eq!(re.find_all_index("a@b c@d", -1), Some(vec![[0, 3], [4, 7]]));
    assert_eq!(re.replace_all("user@host", "X"), "X");
    assert_eq!(re.num_subexp(), 2);
}

/// `n >= 0` bounds the number of matches; Go's `-1` means all.
#[test]
fn find_all_index_respects_n() {
    let _serial = serial();
    let re = compile("a").expect("compile");
    assert_eq!(re.find_all_index("aaa", -1), Some(vec![[0, 1], [1, 2], [2, 3]]));
    assert_eq!(re.find_all_index("aaa", 2), Some(vec![[0, 1], [1, 2]]));
    // Go returns nil for n == 0.
    assert_eq!(re.find_all_index("aaa", 0), None);
}

/// Go returns nil (not an empty slice) when there is no match at all.
#[test]
fn find_all_index_no_match_is_none() {
    let _serial = serial();
    let re = compile("z").expect("compile");
    assert_eq!(re.find_all_index("aaa", -1), None);
}

/// `SubexpNames` mirrors Go: index 0 is the whole match (always empty), and an
/// unnamed group contributes an empty string.
#[test]
fn subexp_names_shape() {
    let _serial = serial();
    let re = compile(r"(?P<user>\w+)@(\w+)").expect("compile");
    assert_eq!(
        re.subexp_names(),
        Some(vec![String::new(), "user".to_string(), String::new()])
    );
}

/// The engine indirection reports its name, and the default is Stdlib.
#[test]
fn version_reports_active_engine() {
    let _serial = serial();
    assert_eq!(version(), "stdlib");
    let _guard = EngineGuard::install(Arc::new(FailingEngine));
    assert_eq!(version(), "failing");
}
