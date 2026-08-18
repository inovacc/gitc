//! Port of Go `internal/runner` — gitc's execution core. It resolves the git
//! backend once, executes passthrough commands or built-in shortcuts, and writes
//! an append-only forensic audit record for every git invocation it issues.
//!
//! Audit writes are best-effort: a logging failure is reported to stderr but never
//! blocks or fails the underlying git command (availability over audit
//! completeness, per the design).
//!
//! ## Faithfulness (security-critical — the tests pin these)
//!
//! - **The enforcement gate is the single choke point.** [`Runner::guard`] installs
//!   a [`GateFunc`] that runs before EVERY git arg vector — passthrough AND each
//!   shortcut step alike (see [`Runner::exec_and_audit`], where the gate is invoked
//!   FIRST). A BLOCK stops execution before the backend runs (fail-closed) and
//!   returns the gate's code; a built-in shortcut therefore cannot bypass the
//!   machine/org policy.
//! - **Blocked attempts are still audited** (mode `"blocked"`) so a refused exfil
//!   leaves a tamper-evident trail even though git never ran.
//! - **The audit record stores the REDACTED argv** ([`redact::args`]); the backend
//!   runs the REAL, unmodified args.
//! - **Env redaction** ([`capture_env`]): only the git-relevant env subset
//!   (`SSH_AUTH_SOCK`, `PATH`, and every `GIT_`-prefixed var) is captured, and each
//!   value is credential-masked ([`redact::string`]) before it reaches the audit
//!   DB — a `GIT_CONFIG_PARAMETERS` carrying an `Authorization` header or a URL with
//!   userinfo must never persist raw.
//! - **Shortcut execution stops at the first non-zero step**; passthrough returns
//!   the backend exit code.
//!
//! ## Documented deviations
//!
//! - **`os_user` / `identity`.** Go reads `user.Current()` (login name + GECOS
//!   display name). Rust std has no user-database API and no new dependency is
//!   warranted, so `os_user` is approximated from the environment
//!   (`USERNAME`/`USER`/`LOGNAME`) and `identity` is left empty (no portable way to
//!   read the display name without libc/WinAPI). Neither field participates in any
//!   ported test; both are informational audit metadata. FLAGGED, not faked.
//! - **Enricher error channel.** Go's `Enrich` returns `(blob, error)` and the
//!   runner warns `"enrichment skipped: %v"` on error; but every real enricher
//!   "degrades to a nil error", so that branch never fires. The already-ported
//!   [`enrich::Enricher`] trait has no error channel (`enrich → Option<Vec<u8>>`),
//!   so the unreachable warning has no analog — `None` maps to Go's `(nil, nil)`
//!   "no enrichment" case exactly.
//! - **Failed spawn duration.** On a backend spawn failure Go returns
//!   `Result{ExitCode: -1, Duration: dur}`; the ported [`backend::Backend::run`]
//!   drops the duration on `Err` (informational only). The runner uses exit `-1`
//!   and a zero duration in that case, matching the exit code that governs control
//!   flow.

#![cfg(feature = "app")]

use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

use time::OffsetDateTime;

use crate::backend::Backend;
use crate::enrich::{self, Ctx, Enricher};
use crate::gitargs;
use crate::redact;
use crate::shortcut;
use crate::store::{Record, Store};

/// Which environment variables are recorded, by exact name. Values are
/// credential-masked before storage. Go `envCaptureExact`.
const ENV_CAPTURE_EXACT: &[&str] = &["SSH_AUTH_SOCK", "PATH"];

/// Which environment variables are recorded, by name prefix. `GIT_`-prefixed vars
/// — notably `GIT_CONFIG_PARAMETERS` — can carry an `Authorization` header or a URL
/// with userinfo that must not persist raw in the audit DB. Go `envCapturePrefix`.
const ENV_CAPTURE_PREFIX: &[&str] = &["GIT_"];

/// Decides whether an about-to-run git arg vector is permitted. Returns
/// `(code, true)` to BLOCK the command — git is never run — or `(_, false)` to
/// allow it.
///
/// It is the single enforcement choke point: every git vector the runner executes
/// (passthrough AND each shortcut step) passes through it, so a built-in shortcut
/// cannot bypass the machine/org policy. Go `type GateFunc func(ctx, args) (int, bool)`.
pub type GateFunc = Box<dyn Fn(&Ctx, &[String]) -> (i32, bool)>;

/// Executes git work against a resolved backend and audits it. Go `struct Runner`.
///
/// Borrows the audit [`Store`] (`'a`) rather than owning it, so a caller can keep
/// querying the same store after handing it to the runner (Go shares a `*store.Store`
/// pointer). A `None` store disables auditing with a per-invocation stderr warning.
pub struct Runner<'a> {
    backend: Backend,
    /// `None` disables auditing (Go: a nil `*store.Store`).
    store: Option<&'a Store>,
    enricher: Box<dyn Enricher>,
    warn: Box<dyn Write>,
    /// `None` means unguarded (Go: a nil `gate`).
    gate: Option<GateFunc>,

    os_user: String,
    identity: String,
    /// Resolved enforcement policy path, recorded per audit row.
    policy_path: String,
}

impl<'a> Runner<'a> {
    /// Builds a Runner. A `None` store disables auditing (with a stderr warning per
    /// invocation); resolution and exec still proceed so git stays usable. A `None`
    /// enricher becomes a no-op; a `None` warn stream defaults to stderr. Go `New`.
    pub fn new(
        backend: Backend,
        store: Option<&'a Store>,
        enricher: Option<Box<dyn Enricher>>,
        warn: Option<Box<dyn Write>>,
    ) -> Runner<'a> {
        let warn = warn.unwrap_or_else(|| Box::new(std::io::stderr()));
        let enricher = enricher.unwrap_or_else(enrich::noop);

        Runner {
            backend,
            store,
            enricher,
            warn,
            gate: None,
            os_user: current_os_user(),
            identity: current_identity(),
            policy_path: String::new(),
        }
    }

    /// Installs the enforcement gate run before every git vector — passthrough and
    /// each shortcut step alike. Without it the runner executes unguarded. This is
    /// what makes the machine/org policy non-bypassable via built-in shortcuts. Go
    /// `Guard`.
    pub fn guard(&mut self, g: GateFunc) {
        self.gate = Some(g);
    }

    /// Records the resolved enforcement policy path (empty when no policy is in
    /// effect) so every audited row shows which policy governed it — making a policy
    /// relocation forensically visible (SEC-2). Go `SetPolicyPath`.
    pub fn set_policy_path(&mut self, p: &str) {
        self.policy_path = p.to_string();
    }

    /// Forwards args verbatim to the backend and audits the call. Returns the
    /// backend exit code. Go `Passthrough`.
    pub fn passthrough(&mut self, ctx: &Ctx, args: &[String]) -> i32 {
        self.exec_and_audit(ctx, args, "passthrough", "")
    }

    /// Runs a built-in shortcut: logs the shortcut invocation itself, then runs each
    /// underlying git step (each independently audited as passthrough). Execution
    /// stops at the first non-zero step. Go `Shortcut`.
    pub fn shortcut(&mut self, ctx: &Ctx, sc: &shortcut::Shortcut, args: &[String]) -> i32 {
        if args.len() < sc.min_args {
            let usage = if sc.usage.is_empty() {
                sc.name
            } else {
                sc.usage
            };
            let _ = writeln!(self.warn, "gitc: usage: gitc {usage}");
            return 2;
        }

        // time.Now() serves Go as both wall clock (rec.TS) and monotonic source
        // (time.Since); Rust splits them into OffsetDateTime + Instant.
        let start_instant = Instant::now();
        let start_ts = OffsetDateTime::now_utc();
        let mut last = 0;

        let steps = (sc.steps)(args);
        for step in &steps {
            last = self.exec_and_audit(ctx, step, "passthrough", "");
            if last != 0 {
                break;
            }
        }

        // Record the shortcut invocation itself for full traceability, distinct from
        // the individual underlying git steps.
        let mut sc_args = Vec::with_capacity(1 + args.len());
        sc_args.push(sc.name.to_string());
        sc_args.extend(args.iter().cloned());

        let mut rec = self.base_record(&sc_args, "shortcut", sc.name);
        rec.ts = start_ts;
        rec.exit_code = last;
        rec.duration = start_instant.elapsed();
        self.write_audit(&rec);

        last
    }

    /// Runs one git arg vector and writes one audit row. The enforcement gate (if
    /// installed) runs FIRST: a blocked vector never reaches git, but the refused
    /// attempt IS recorded (mode `"blocked"`) so a forensic trail exists. Go
    /// `execAndAudit`.
    fn exec_and_audit(
        &mut self,
        ctx: &Ctx,
        args: &[String],
        mode: &str,
        shortcut_name: &str,
    ) -> i32 {
        // THE GATE HOOK — invoked before any backend run. `map` runs the gate and
        // drops the borrow of `self.gate` before we touch `&mut self` again.
        let gate_result = self.gate.as_ref().map(|g| g(ctx, args));
        if let Some((code, blocked)) = gate_result {
            if blocked {
                self.audit_blocked(args, code);
                return code;
            }
        }

        let mut rec = self.base_record(args, mode, shortcut_name);
        rec.ts = OffsetDateTime::now_utc();

        let (exit_code, duration) = match self.backend.run(args) {
            Ok(out) => (out.exit_code, out.duration),
            Err(e) => {
                let _ = writeln!(self.warn, "gitc: {e}");
                // Go: Result{ExitCode: -1, Duration: dur}; the ported backend drops
                // the duration on Err (see module docs).
                (-1, Duration::ZERO)
            }
        };

        // Help/usage/version invocations touch no repository state; run them but do
        // not record them, so the audit log stays a log of real git operations.
        if !auditable(args) {
            return exit_code;
        }

        rec.exit_code = exit_code;
        rec.duration = duration;

        // Enrichment is best-effort. Go warns on a (never-fired) error and otherwise
        // stores the blob; the ported Enricher trait has no error channel, so `None`
        // is Go's `(nil, nil)` no-enrichment case and simply leaves the field unset.
        if let Some(blob) = self.enricher.enrich(ctx, &rec.cwd) {
            rec.enrichment = Some(String::from_utf8_lossy(&blob).into_owned());
        }

        self.write_audit(&rec);

        exit_code
    }

    /// Records a policy-refused invocation (mode `"blocked"`) so a blocked exfil or
    /// secret-gated attempt leaves a tamper-evident trace even though git never ran.
    /// Argv is credential-masked like any other row; help and version are never
    /// gated so the `auditable` filter is a defensive no-op. Go `auditBlocked`.
    fn audit_blocked(&mut self, args: &[String], code: i32) {
        if !auditable(args) {
            return;
        }

        let mut rec = self.base_record(args, "blocked", "");
        rec.ts = OffsetDateTime::now_utc();
        rec.exit_code = code;

        self.write_audit(&rec);
    }

    /// Builds the common audit record fields for `args`. Go `baseRecord`.
    fn base_record(&self, args: &[String], mode: &str, shortcut_name: &str) -> Record {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        Record {
            os_user: self.os_user.clone(),
            identity: self.identity.clone(),
            cwd,
            // Store a credential-masked copy of argv (the backend still runs the real
            // args); a token in a clone URL must not persist in the audit DB.
            argv: redact::args(args),
            // Go returns a non-nil map (make), so an empty capture marshals to `{}`,
            // not `null`: keep `Some(_)` even when empty.
            env_subset: Some(capture_env()),
            backend: self.backend.kind.as_str().to_string(),
            backend_path: self.backend.path.to_string_lossy().into_owned(),
            mode: mode.to_string(),
            shortcut: shortcut_name.to_string(),
            policy_path: self.policy_path.clone(),
            ..Record::default()
        }
    }

    /// Best-effort audit write: a nil store or an insert failure warns on `warn` but
    /// never fails the git command. Go `writeAudit`.
    fn write_audit(&mut self, rec: &Record) {
        match self.store {
            None => {
                let _ = writeln!(
                    self.warn,
                    "gitc: audit log unavailable; invocation not recorded"
                );
            }
            Some(store) => {
                if let Err(e) = store.insert(rec) {
                    let _ = writeln!(self.warn, "gitc: audit write failed: {e}");
                }
            }
        }
    }
}

/// Reports whether an argv represents a real git operation worth recording. Bare
/// usage, help (`help`/`-h`/`--help`), and version queries are not. Go `auditable`.
fn auditable(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }

    for a in args {
        if a == "--help" || a == "-h" || a == "--version" {
            return false;
        }
    }

    match gitargs::subcommand_index(args) {
        None => false,
        Some(idx) => !matches!(args[idx].as_str(), "help" | "version"),
    }
}

/// Returns the git-relevant environment subset with credential-masked values (URL
/// userinfo and Authorization tokens stripped). Go `captureEnv`.
///
/// Go iterates `os.Environ()` ("KEY=VALUE" strings) and splits on the first `=`;
/// `std::env::vars_os` already yields split key/value pairs. Values are lossily
/// decoded to match Go's string handling.
fn capture_env() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for (key, val) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if match_env(&key) {
            let val = val.to_string_lossy();
            out.insert(key.into_owned(), redact::string(&val));
        }
    }

    out
}

/// Reports whether `key` is captured for the audit env subset. Go `matchEnv`.
fn match_env(key: &str) -> bool {
    for exact in ENV_CAPTURE_EXACT {
        if key == *exact {
            return true;
        }
    }

    for prefix in ENV_CAPTURE_PREFIX {
        if key.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Best-effort OS login name (Go `user.Current().Username`). See the module-level
/// deviation note: Rust std has no user-database API, so this reads the environment.
fn current_os_user() -> String {
    let key = if cfg!(windows) { "USERNAME" } else { "USER" };
    std::env::var(key)
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

/// Best-effort display name (Go `user.Current().Name`). No portable std source
/// exists, so this is empty (FLAGGED, see module docs). Go leaves it `""` on error.
fn current_identity() -> String {
    String::new()
}

// ── tests (ported from runner_test.go, gate_test.go, envredact_test.go) ──────
#[cfg(all(test, feature = "app"))]
mod tests {
    use super::*;
    use crate::backend::{Backend, Kind};
    use crate::shortcut::Shortcut;
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    // ── shared test helpers ─────────────────────────────────────────────────

    /// Serializes the tests that mutate the process-global environment (Go's
    /// `t.Setenv` is per-test; Rust std tests share the process and run in parallel).
    fn env_guard() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII env var setter/restorer (mirrors `t.Setenv` cleanup).
    struct EnvVarGuard {
        key: String,
        prev: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            EnvVarGuard {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    fn sv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn sink() -> Option<Box<dyn Write>> {
        Some(Box::new(std::io::sink()))
    }

    /// A stand-in for Go's zero-value `backend.Backend{}` (Kind ""), which the Rust
    /// `Kind` enum cannot represent. Only used where the gate blocks before any
    /// backend run, so the value is never executed.
    fn empty_backend() -> Backend {
        Backend {
            kind: Kind::System,
            path: PathBuf::new(),
        }
    }

    /// Minimal std-only temp dir (no `tempfile` dependency); Go `t.TempDir()`.
    struct TmpDir {
        path: PathBuf,
    }

    impl TmpDir {
        fn new() -> TmpDir {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "gitc-runner-test-{}-{}-{}",
                std::process::id(),
                nanos,
                n
            ));
            std::fs::create_dir_all(&path).unwrap();
            TmpDir { path }
        }

        fn join(&self, s: &str) -> PathBuf {
            self.path.join(s)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    // ── runner_test.go ──────────────────────────────────────────────────────

    // TestAuditable
    #[test]
    fn auditable_cases() {
        let cases: &[(&[&str], bool)] = &[
            (&[], false),
            (&["status"], true),
            (&["commit", "-m", "x"], true),
            (&["-c", "x=y", "push"], true),
            (&["--help"], false),
            (&["-h"], false),
            (&["--version"], false),
            (&["help", "commit"], false),
            (&["version"], false),
            (&["clone", "--help", "url"], false),
        ];

        for (args, want) in cases {
            let got = auditable(&sv(args));
            assert_eq!(got, *want, "auditable({args:?}) = {got}, want {want}");
        }
    }

    // TestBaseRecordRedactsCredentials
    #[test]
    fn base_record_redacts_credentials() {
        let r = Runner::new(
            Backend {
                kind: Kind::System,
                path: PathBuf::from("git"),
            },
            None,
            None,
            sink(),
        );

        let rec = r.base_record(
            &sv(&["clone", "https://user:s3cr3t@github.com/x.git"]),
            "passthrough",
            "",
        );

        assert_eq!(rec.argv.len(), 2, "argv = {:?}", rec.argv);
        assert_eq!(
            rec.argv[1], "https://user:***@github.com/x.git",
            "credential not redacted in the audit record: {:?}",
            rec.argv[1]
        );
        assert_eq!(rec.mode, "passthrough", "record mode wrong");
        assert_eq!(
            rec.backend,
            Kind::System.as_str(),
            "record backend wrong: {:?}",
            rec.backend
        );
    }

    // TestCaptureEnv
    #[test]
    fn capture_env_subset() {
        let _lock = env_guard();
        let _a = EnvVarGuard::set("GIT_AUTHOR_NAME", "alice");
        let _b = EnvVarGuard::set("SSH_AUTH_SOCK", "/tmp/s");
        let _c = EnvVarGuard::set("UNRELATED_SECRET", "leak");

        let env = capture_env();

        assert_eq!(
            env.get("GIT_AUTHOR_NAME").map(String::as_str),
            Some("alice"),
            "GIT_-prefixed var should be captured"
        );
        assert_eq!(
            env.get("SSH_AUTH_SOCK").map(String::as_str),
            Some("/tmp/s"),
            "exact-match var should be captured"
        );
        assert!(
            !env.contains_key("UNRELATED_SECRET"),
            "unrelated env var must not be captured"
        );
    }

    // ── gate_test.go ────────────────────────────────────────────────────────

    // TestGuardBlocksPassthrough — the gate runs before a passthrough git vector
    // and blocks it (git is never reached).
    #[test]
    fn guard_blocks_passthrough() {
        let mut r = Runner::new(empty_backend(), None, None, sink());

        let seen: Rc<RefCell<Vec<Vec<String>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_c = seen.clone();
        r.guard(Box::new(move |_ctx, args: &[String]| {
            seen_c.borrow_mut().push(args.to_vec());
            (7, true) // block everything
        }));

        let code = r.passthrough(&Ctx::background(), &sv(&["push", "origin"]));
        assert_eq!(
            code, 7,
            "blocked passthrough should return the gate's code 7"
        );

        let seen = seen.borrow();
        assert!(
            seen.len() == 1 && seen[0][0] == "push",
            "gate should see exactly the push vector, got {seen:?}"
        );
    }

    // TestGuardGatesShortcutSteps — SEC-1/H-25 regression: a built-in shortcut's
    // push step must funnel through the same gate as passthrough, blocked before any
    // backend run.
    #[test]
    fn guard_gates_shortcut_steps() {
        let push = Shortcut {
            name: "danger",
            short: "",
            min_args: 0,
            usage: "",
            steps: |_| {
                vec![vec![
                    "push".to_string(),
                    "origin".to_string(),
                    "main".to_string(),
                ]]
            },
        };

        let mut r = Runner::new(empty_backend(), None, None, sink());

        let seen: Rc<RefCell<Vec<Vec<String>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_c = seen.clone();
        r.guard(Box::new(move |_ctx, args: &[String]| {
            seen_c.borrow_mut().push(args.to_vec());
            (9, true)
        }));

        let code = r.shortcut(&Ctx::background(), &push, &[]);
        assert_eq!(
            code, 9,
            "blocked shortcut push step should return the gate's code 9"
        );

        let seen = seen.borrow();
        assert!(
            seen.len() == 1 && seen[0][0] == "push",
            "gate should see the shortcut's push step, got {seen:?}"
        );
    }

    // TestUnguardedRunnerHasNoGate — a freshly constructed runner is unguarded until
    // Guard is called (nil gate is skipped).
    #[test]
    fn unguarded_runner_has_no_gate() {
        let r = Runner::new(empty_backend(), None, None, sink());
        assert!(
            r.gate.is_none(),
            "a freshly constructed runner must be unguarded until guard() is called"
        );
    }

    // TestBlockedCommandIsAudited — a policy-refused command leaves a forensic audit
    // row even though git never ran.
    #[test]
    fn blocked_command_is_audited() {
        let tmp = TmpDir::new();
        let st = crate::store::open(tmp.join("audit.db")).expect("open");

        let mut r = Runner::new(empty_backend(), Some(&st), None, sink());
        r.guard(Box::new(|_ctx, _args| (1, true)));

        let code = r.passthrough(&Ctx::background(), &sv(&["push", "origin"]));
        assert_eq!(code, 1, "blocked push should return 1");

        let rows = st.raw_rows().expect("raw_rows");
        assert_eq!(
            rows.len(),
            1,
            "a blocked command must record exactly one audit row, got {}",
            rows.len()
        );
        assert!(
            rows[0].argv.contains("push"),
            "the blocked row must capture the refused argv, got {:?}",
            rows[0].argv
        );

        st.close().expect("close");
    }

    // ── envredact_test.go ───────────────────────────────────────────────────

    // TestCaptureEnvRedactsCredentials — SEC-8/H-35 regression: a GIT_ var carrying
    // an Authorization token must be masked before it reaches the audit DB.
    #[test]
    fn capture_env_redacts_credentials() {
        let _lock = env_guard();
        let _g = EnvVarGuard::set(
            "GIT_CONFIG_PARAMETERS",
            "'http.extraHeader=Authorization: Bearer SECRETTOKEN123'",
        );

        let v = capture_env();
        let v = v.get("GIT_CONFIG_PARAMETERS").cloned().unwrap_or_default();

        assert!(
            !v.contains("SECRETTOKEN123"),
            "Authorization token must be masked in captured env, got {v:?}"
        );
        assert!(
            v.contains("***"),
            "expected a mask marker in the captured value, got {v:?}"
        );
    }

    // TestCaptureEnvRedactsURLUserinfo — a credential embedded as URL userinfo.
    #[test]
    fn capture_env_redacts_url_userinfo() {
        let _lock = env_guard();
        let _g = EnvVarGuard::set("GIT_MIRROR", "https://user:hunter2@example.com/repo.git");

        let v = capture_env();
        let v = v.get("GIT_MIRROR").cloned().unwrap_or_default();

        assert!(
            !v.contains("hunter2"),
            "URL password must be masked, got {v:?}"
        );
    }
}
