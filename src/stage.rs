//! Pre/post stages around git core.
//!
//! `gitc` is git — git's own C is linked in and dispatched via [`crate`]'s
//! `ffi::cmd_main`. This module is the one seam around that dispatch: a **pre**
//! stage runs before git core and may refuse the command outright, a **post**
//! stage runs after it and observes the outcome.
//!
//! ```text
//!   argv ──► pre stages ──► init_git + cmd_main ──► post stages ──► exit
//!               │                                        ▲
//!               └── Flow::Block(code) ───────────────────►┘  (still observed)
//! ```
//!
//! ## Why the post stage runs from `atexit`, not from a plain call
//!
//! git's builtins routinely terminate the process from deep inside C — `die()`,
//! `usage()`, and most error paths call `exit()` and never return to `cmd_main`'s
//! caller. A post stage written as ordinary code after the FFI call would
//! therefore silently skip a large fraction of invocations, and specifically the
//! *failing* ones, which is precisely when an audit trail matters. So the post
//! stage is registered with the C runtime's `atexit` before git core is entered,
//! and it fires on both paths.
//!
//! **This is still not total coverage, and the gap is not papered over.** `atexit`
//! handlers do not run on `_exit()`, `abort()`, an uncaught fatal signal, or a
//! `TerminateProcess`. A missing post record means "gitc did not observe the end of
//! this command", never "this command did not run".
//!
//! **The exit status is not observable from `atexit`.** The C runtime does not pass
//! the status to handlers, so when git leaves via `exit()` the post stage receives
//! [`Outcome::Exited`] with no code rather than a fabricated one. When `cmd_main`
//! returns normally the real code is recorded first and the stage sees
//! [`Outcome::Returned`]. Distinguishing the two honestly is the point; guessing
//! `0` would make the audit log lie in exactly the direction that hides failures.
//!
//! ## Handler constraints (these are load-bearing)
//!
//! The trampoline runs during C teardown, so it:
//! - catches unwinding — a Rust panic must not cross back into the CRT;
//! - fires at most once, whichever path reached it;
//! - reads only state captured **before** git core ran (argv, start time, the
//!   built registry), because re-deriving it mid-teardown is what turns a
//!   diagnostic into a crash.
//!
//! ## Recursion
//!
//! Policy checks use the private backend executable, so they do not re-enter
//! gitc. [`GUARD_ENV`] remains reserved for configured helper processes, but its
//! presence is treated as an untrusted marker and fails closed; it is never a
//! permission to skip enforcement.
//!
//! ## Scope
//!
//! Stages wrap **git core only**. `gitc scan` / `gitc scrub` are gitc's own
//! commands, are handled in Rust before this seam, and are deliberately not staged
//! — a gate that refuses `git push` has no meaning applied to `gitc scan`.

use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Set in the environment of any git child a stage spawns. Its presence disables
/// the stage machinery in that child, breaking the recursion gitc↔git.
pub const GUARD_ENV: &str = "GITC_IN_STAGE";

/// Carries the git argv to an external stage command, newline-separated. Read by
/// [`policy::StageCmd`](crate::policy::StageCmd) programs.
pub const ARGV_ENV: &str = "GITC_STAGE_ARGV";

/// Carries the outcome to an external post-stage command: `returned:<code>`,
/// `blocked:<code>`, or `exited` (status not observable — see the module docs).
pub const OUTCOME_ENV: &str = "GITC_STAGE_OUTCOME";

/// What a pre stage decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Let git core run.
    Continue,
    /// Refuse the command with this exit code; git core is never entered.
    Block(i32),
}

/// How git core ended, as far as gitc can actually tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `cmd_main` returned this exit code.
    Returned(i32),
    /// A pre stage refused the command; git core never ran.
    Blocked(i32),
    /// git terminated the process itself (`die()`/`exit()`). **The status is not
    /// recoverable from an `atexit` handler** — this variant deliberately carries
    /// no code rather than inventing one.
    Exited,
}

impl Outcome {
    /// The exit code where one is known. `None` for [`Outcome::Exited`].
    pub fn code(&self) -> Option<i32> {
        match self {
            Outcome::Returned(c) | Outcome::Blocked(c) => Some(*c),
            Outcome::Exited => None,
        }
    }

    /// The audit `mode` this outcome maps to, matching the vocabulary
    /// [`crate::runner`] already writes (`"passthrough"` / `"blocked"`).
    pub fn mode(&self) -> &'static str {
        match self {
            Outcome::Returned(_) | Outcome::Exited => "passthrough",
            Outcome::Blocked(_) => "blocked",
        }
    }

    /// Wire form for [`OUTCOME_ENV`]: `returned:<code>`, `blocked:<code>`, or
    /// `exited`. Public because external stage programs parse it.
    pub fn wire(&self) -> String {
        match self {
            Outcome::Returned(c) => format!("returned:{c}"),
            Outcome::Blocked(c) => format!("blocked:{c}"),
            Outcome::Exited => "exited".to_string(),
        }
    }
}

/// Runs before git core and may refuse the command.
///
/// `argv` is the git argument vector **without** `argv[0]`, matching what
/// [`crate::runner::GateFunc`] receives, so a gate implementation is identical in
/// both the FFI and proxy worlds.
pub trait PreStage: Send + Sync {
    /// Short label for diagnostics.
    fn name(&self) -> &str;
    /// Decide whether git core may run.
    fn run(&self, argv: &[String]) -> Flow;
}

/// Runs after git core, on both the return and the `exit()` path.
///
/// Implementations must be teardown-safe: no panics, no unbounded work. They are
/// advisory — a post stage cannot change the exit code, because by the time it
/// runs the status is already committed.
pub trait PostStage: Send + Sync {
    /// Short label for diagnostics.
    fn name(&self) -> &str;
    /// Observe the finished command.
    fn run(&self, argv: &[String], outcome: Outcome, elapsed: Duration);
}

/// The installed stages. Built once, before git core is entered.
#[derive(Default)]
pub struct Registry {
    /// Pre stages, run in order; the first [`Flow::Block`] wins.
    pub pre: Vec<Box<dyn PreStage>>,
    /// Post stages, all run in order regardless of outcome.
    pub post: Vec<Box<dyn PostStage>>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

// State captured BEFORE git core runs, so the atexit trampoline reads only
// already-materialised values.
static ARGV: OnceLock<Vec<String>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
static CODE: AtomicI32 = AtomicI32::new(0);
static CODE_KNOWN: AtomicBool = AtomicBool::new(false);
static BLOCKED: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);
static FIRED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// C runtime `atexit`. Present in every libc/msvcrt gitc links against; using
    /// it avoids taking a `libc` dependency for one symbol.
    fn atexit(cb: extern "C" fn()) -> c_int;
}

/// Reports whether an internal-stage marker was supplied (see [`GUARD_ENV`]).
/// The marker is intentionally not treated as proof of trust.
pub fn suppressed() -> bool {
    std::env::var_os(GUARD_ENV).is_some()
}

/// Installs a registry explicitly. Returns `Err` with the registry back if one was
/// already installed. Tests and alternate front-ends use this; the binary relies on
/// [`default_registry`] via [`registry`].
pub fn install(r: Registry) -> Result<(), Registry> {
    REGISTRY.set(r)
}

/// The installed registry, building the default one on first use.
fn registry() -> &'static Registry {
    REGISTRY.get_or_init(default_registry)
}

/// The stages gitc ships with. Empty unless the `app` feature is compiled in —
/// without it there is no policy, no gate and no audit store to drive them.
fn default_registry() -> Registry {
    #[cfg(not(feature = "app"))]
    {
        Registry::default()
    }

    #[cfg(feature = "app")]
    {
        builtin::registry()
    }
}

/// Runs the pre stages. Returns the first [`Flow::Block`], else [`Flow::Continue`].
///
/// `argv` excludes `argv[0]`. A process carrying [`GUARD_ENV`] is rejected
/// fail-closed rather than being allowed around the policy stages.
pub fn run_pre(argv: &[String]) -> Flow {
    if suppressed() {
        // This marker is an implementation detail, not an authorization token.
        // Treating any user-supplied value as permission to skip enforcement would
        // make `GITC_IN_STAGE=1 git push` a trivial bypass.
        eprintln!("gitc: BLOCKED — internal stage marker cannot be supplied externally");
        BLOCKED.store(true, Ordering::SeqCst);
        record_exit(1);
        return Flow::Block(1);
    }

    for s in &registry().pre {
        if let Flow::Block(code) = s.run(argv) {
            BLOCKED.store(true, Ordering::SeqCst);
            record_exit(code);
            return Flow::Block(code);
        }
    }

    Flow::Continue
}

/// Captures the state the post stages will need and registers the `atexit`
/// trampoline. Call this BEFORE [`run_pre`] so a refused command is still observed.
///
/// A no-op when there are no post stages (nothing is registered with the CRT), when
/// already armed, or in a stage-spawned child.
pub fn arm_post(argv: &[String]) {
    if suppressed() || registry().post.is_empty() {
        return;
    }
    if ARMED.swap(true, Ordering::SeqCst) {
        return;
    }

    let _ = ARGV.set(argv.to_vec());
    let _ = START.set(Instant::now());

    // SAFETY: `post_trampoline` is a plain `extern "C" fn()` with C linkage and no
    // arguments — exactly the signature `atexit` requires.
    unsafe {
        atexit(post_trampoline);
    }
}

/// Records the exit code `cmd_main` returned, so the trampoline reports
/// [`Outcome::Returned`] instead of [`Outcome::Exited`].
pub fn record_exit(code: i32) {
    CODE.store(code, Ordering::SeqCst);
    CODE_KNOWN.store(true, Ordering::SeqCst);
}

/// The `atexit` callback. Must never unwind into the CRT and must never fire twice.
extern "C" fn post_trampoline() {
    if FIRED.swap(true, Ordering::SeqCst) {
        return;
    }

    // A panic here would cross an `extern "C"` boundary during teardown. Swallow
    // it: a broken post stage must not turn a successful git command into a crash.
    let _ = std::panic::catch_unwind(run_post_now);
}

/// Body of the trampoline, in a normal Rust frame so it may unwind into the
/// `catch_unwind` above.
fn run_post_now() {
    let argv = match ARGV.get() {
        Some(a) => a.as_slice(),
        None => return,
    };
    let elapsed = START.get().map(|s| s.elapsed()).unwrap_or_default();

    let outcome = if BLOCKED.load(Ordering::SeqCst) {
        Outcome::Blocked(CODE.load(Ordering::SeqCst))
    } else if CODE_KNOWN.load(Ordering::SeqCst) {
        Outcome::Returned(CODE.load(Ordering::SeqCst))
    } else {
        Outcome::Exited
    };

    for s in &registry().post {
        s.run(argv, outcome, elapsed);
    }
}

// ── built-in stages (need the app layer: policy, gate, audit store) ──────────
#[cfg(feature = "app")]
mod builtin {
    use super::*;
    use crate::policy::StageCmd;

    /// Builds the shipped registry: the enforcement gate as a pre stage, the audit
    /// writer as a post stage, and any external commands the machine policy names.
    ///
    /// The policy is read ONCE here — before git core runs — so no stage has to
    /// touch the filesystem during teardown.
    pub(super) fn registry() -> Registry {
        let mut r = Registry::default();

        r.pre.push(Box::new(GateStage));

        let (pre_cmds, post_cmds) = configured_commands();
        for c in pre_cmds {
            r.pre.push(Box::new(ExecStage { cmd: c }));
        }

        r.post.push(Box::new(AuditStage));
        for c in post_cmds {
            r.post.push(Box::new(ExecStage { cmd: c }));
        }

        r
    }

    /// The external stage commands from the machine policy, or empty when no policy
    /// is in effect. A policy that fails to LOAD yields no commands here; refusing
    /// the command itself is [`GateStage`]'s job, which reports the same error.
    fn configured_commands() -> (Vec<StageCmd>, Vec<StageCmd>) {
        crate::gates::policy_stage_commands()
    }

    /// The machine/org enforcement gate — the secret gate, the remote allowlist and
    /// the alias-injection check — as a pre stage.
    ///
    /// This is what makes the policy non-bypassable in the FFI binary: previously
    /// [`crate::gates::enforce_gates`] was only reachable from
    /// [`crate::appmain::main_entry`], which no shipped binary called.
    pub(super) struct GateStage;

    impl PreStage for GateStage {
        fn name(&self) -> &str {
            "gate"
        }

        fn run(&self, argv: &[String]) -> Flow {
            // Gate queries must use the managed/system backend, never this gitc
            // executable. That avoids recursive re-entry without relying on a
            // user-forgeable environment marker.
            let git = std::env::current_exe()
                .ok()
                .and_then(|self_path| {
                    crate::backend::resolve(
                        crate::provision::managed_git_path().as_deref(),
                        &self_path,
                    )
                    .ok()
                })
                .map(|b| b.path.to_string_lossy().into_owned());

            let Some(git) = git else {
                eprintln!("gitc: BLOCKED — no trusted Git backend available for policy checks");
                crate::repostate::record_gate(
                    self.name(),
                    "internal",
                    "block",
                    1,
                    subcommand(argv),
                );
                return Flow::Block(1);
            };

            let (code, blocked) = crate::gates::enforce_gates(argv, &git);

            // Note the verdict in the repo's advisory ledger. This is a NOTE, not
            // the decision: the decision was already made above from the
            // admin-owned policy, and nothing ever reads this back to decide.
            crate::repostate::record_gate(
                self.name(),
                "internal",
                if blocked { "block" } else { "allow" },
                code,
                subcommand(argv),
            );

            if blocked {
                Flow::Block(code)
            } else {
                Flow::Continue
            }
        }
    }

    /// The git subcommand in `argv`, or `""`. Used only for ledger labelling.
    fn subcommand(argv: &[String]) -> &str {
        crate::gitargs::subcommand_index(argv)
            .map(|i| argv[i].as_str())
            .unwrap_or("")
    }

    /// Writes one forensic audit row per git invocation.
    ///
    /// The store is opened inside `run` rather than held across git core: git may
    /// run for minutes, and holding a SQLite handle open for that whole window buys
    /// nothing but lock contention with concurrent gitc processes.
    pub(super) struct AuditStage;

    impl PostStage for AuditStage {
        fn name(&self) -> &str {
            "audit"
        }

        fn run(&self, argv: &[String], outcome: Outcome, elapsed: Duration) {
            if !auditable(argv) {
                return;
            }

            let st = match crate::store::open(crate::provision::audit_db_path()) {
                Ok(s) => s,
                // Availability over audit completeness, matching `runner`: a broken
                // audit DB warns, it never fails the git command.
                Err(e) => {
                    eprintln!("gitc: audit write skipped: {e}");
                    return;
                }
            };

            let rec = crate::store::Record {
                ts: time::OffsetDateTime::now_utc(),
                os_user: os_user(),
                cwd: std::env::current_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                // The audit row stores MASKED argv; git core ran the real one.
                argv: crate::redact::args(argv),
                backend: "ffi".to_string(),
                backend_path: std::env::current_exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                mode: outcome.mode().to_string(),
                // An unobservable status is recorded as -1, and `outcome.mode()`
                // plus the duration keep it distinguishable from a real -1. It is
                // NOT recorded as 0 — that would read as success.
                exit_code: outcome.code().unwrap_or(-1),
                duration: elapsed,
                policy_path: crate::gates::enforcement_policy_path(),
                ..crate::store::Record::default()
            };

            if let Err(e) = st.insert(&rec) {
                eprintln!("gitc: audit write failed: {e}");
            }
        }
    }

    /// Runs one external command from the machine policy.
    ///
    /// Used for both directions; as a pre stage a non-zero exit blocks git, as a
    /// post stage the code is ignored (the status is already committed).
    pub(super) struct ExecStage {
        pub(super) cmd: StageCmd,
    }

    impl ExecStage {
        /// Spawns the command with the recursion guard set, waits up to the
        /// configured timeout, and returns its exit code.
        ///
        /// `Err` is a *failure to run the stage* (spawn error or timeout) as
        /// distinct from the stage running and returning non-zero.
        fn exec(&self, argv: &[String], outcome: Option<Outcome>) -> Result<i32, String> {
            let (prog, rest) = match self.cmd.run.split_first() {
                Some(v) if !v.0.is_empty() => v,
                _ => return Err("empty `run`".to_string()),
            };

            let mut c = std::process::Command::new(prog);
            c.args(rest)
                .env(GUARD_ENV, "1")
                .env(ARGV_ENV, argv.join("\n"));
            if let Some(o) = outcome {
                c.env(OUTCOME_ENV, o.wire());
            }

            let mut child = c.spawn().map_err(|e| e.to_string())?;
            match wait_timeout(&mut child, self.cmd.timeout()) {
                Some(code) => Ok(code),
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    Err(format!("timed out after {:?}", self.cmd.timeout()))
                }
            }
        }
    }

    impl PreStage for ExecStage {
        fn name(&self) -> &str {
            &self.cmd.name
        }

        fn run(&self, argv: &[String]) -> Flow {
            let sub = subcommand(argv);
            match self.exec(argv, None) {
                Ok(0) => {
                    crate::repostate::record_gate(&self.cmd.name, "external", "allow", 0, sub);
                    Flow::Continue
                }
                Ok(code) => {
                    crate::repostate::record_gate(&self.cmd.name, "external", "block", code, sub);
                    eprintln!(
                        "gitc: BLOCKED by pre-stage {:?} (exit {code})",
                        self.cmd.name
                    );
                    Flow::Block(code)
                }
                // A pre stage that cannot run FAILS CLOSED. It was configured by an
                // administrator as a precondition for running git; treating "the
                // check did not run" as "the check passed" is how a policy becomes
                // decorative.
                Err(e) => {
                    crate::repostate::record_gate(&self.cmd.name, "external", "error", 1, sub);
                    eprintln!(
                        "gitc: BLOCKED — pre-stage {:?} could not run: {e}",
                        self.cmd.name
                    );
                    Flow::Block(1)
                }
            }
        }
    }

    impl PostStage for ExecStage {
        fn name(&self) -> &str {
            &self.cmd.name
        }

        fn run(&self, argv: &[String], outcome: Outcome, _elapsed: Duration) {
            // Post stages are advisory: git has already finished and its status is
            // committed, so a failure here is reported and nothing more.
            if let Err(e) = self.exec(argv, Some(outcome)) {
                eprintln!("gitc: post-stage {:?} failed: {e}", self.cmd.name);
            }
        }
    }

    /// Waits for `child` up to `limit`, returning its exit code or `None` on
    /// timeout. std has no `wait_timeout`, and the alternative — a thread plus a
    /// channel — is more machinery than a teardown path should carry.
    fn wait_timeout(child: &mut std::process::Child, limit: Duration) -> Option<i32> {
        let start = Instant::now();
        let mut nap = Duration::from_millis(1);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
                Ok(None) => {}
                Err(_) => return Some(-1),
            }
            if start.elapsed() >= limit {
                return None;
            }
            std::thread::sleep(nap);
            // Back off to 20ms so a slow stage does not spin a core.
            nap = (nap * 2).min(Duration::from_millis(20));
        }
    }

    /// Whether an argv is a real git operation worth an audit row. Mirrors
    /// [`crate::runner`]'s rule so both worlds record the same set.
    fn auditable(args: &[String]) -> bool {
        if args.is_empty() {
            return false;
        }
        for a in args {
            if a == "--help" || a == "-h" || a == "--version" {
                return false;
            }
        }
        match crate::gitargs::subcommand_index(args) {
            None => false,
            Some(i) => !matches!(args[i].as_str(), "help" | "version"),
        }
    }

    /// Best-effort OS login name, as [`crate::runner`] derives it.
    fn os_user() -> String {
        let key = if cfg!(windows) { "USERNAME" } else { "USER" };
        std::env::var(key)
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    fn sv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    struct Blocker(i32);
    impl PreStage for Blocker {
        fn name(&self) -> &str {
            "blocker"
        }
        fn run(&self, _argv: &[String]) -> Flow {
            Flow::Block(self.0)
        }
    }

    struct Counter(Arc<AtomicUsize>);
    impl PreStage for Counter {
        fn name(&self) -> &str {
            "counter"
        }
        fn run(&self, _argv: &[String]) -> Flow {
            self.0.fetch_add(1, Ordering::SeqCst);
            Flow::Continue
        }
    }

    /// Drives the pre chain directly (not via the process-global registry, which a
    /// parallel test run shares) so ordering is testable in isolation.
    fn drive(pre: &[Box<dyn PreStage>], argv: &[String]) -> Flow {
        for s in pre {
            if let Flow::Block(c) = s.run(argv) {
                return Flow::Block(c);
            }
        }
        Flow::Continue
    }

    #[test]
    fn first_block_wins_and_later_stages_do_not_run() {
        let n = Arc::new(AtomicUsize::new(0));
        let chain: Vec<Box<dyn PreStage>> = vec![
            Box::new(Counter(n.clone())),
            Box::new(Blocker(7)),
            Box::new(Counter(n.clone())),
        ];

        assert_eq!(drive(&chain, &sv(&["push"])), Flow::Block(7));
        assert_eq!(
            n.load(Ordering::SeqCst),
            1,
            "the stage after the blocking one must not run"
        );
    }

    #[test]
    fn empty_chain_continues() {
        assert_eq!(drive(&[], &sv(&["status"])), Flow::Continue);
    }

    /// The distinction the whole `atexit` design exists to preserve: a status we
    /// could not observe must never be reported as a successful 0.
    #[test]
    fn exited_carries_no_code() {
        assert_eq!(Outcome::Exited.code(), None);
        assert_eq!(Outcome::Returned(0).code(), Some(0));
        assert_eq!(Outcome::Blocked(3).code(), Some(3));
    }

    #[test]
    fn outcome_maps_to_runner_audit_modes() {
        assert_eq!(Outcome::Returned(0).mode(), "passthrough");
        assert_eq!(Outcome::Exited.mode(), "passthrough");
        assert_eq!(Outcome::Blocked(1).mode(), "blocked");
    }

    #[test]
    fn outcome_wire_forms_are_distinguishable() {
        assert_eq!(Outcome::Returned(2).wire(), "returned:2");
        assert_eq!(Outcome::Blocked(1).wire(), "blocked:1");
        assert_eq!(Outcome::Exited.wire(), "exited");
    }

    /// A stage-spawned child must not re-enter the stage machinery, or a gate that
    /// shells out to git would fork bomb.
    #[test]
    fn guard_env_fails_closed_instead_of_suppressing_pre_stages() {
        let prev = std::env::var_os(GUARD_ENV);
        std::env::set_var(GUARD_ENV, "1");
        let flow = run_pre(&sv(&["push", "origin"]));
        match prev {
            Some(v) => std::env::set_var(GUARD_ENV, v),
            None => std::env::remove_var(GUARD_ENV),
        }

        assert_eq!(
            flow,
            Flow::Block(1),
            "an externally marked child must be blocked, never allowed around the gate"
        );
    }

    #[test]
    fn arm_post_is_inert_in_a_guarded_child() {
        let prev = std::env::var_os(GUARD_ENV);
        std::env::set_var(GUARD_ENV, "1");
        arm_post(&sv(&["status"]));
        let armed = ARMED.load(Ordering::SeqCst);
        match prev {
            Some(v) => std::env::set_var(GUARD_ENV, v),
            None => std::env::remove_var(GUARD_ENV),
        }

        assert!(
            !armed,
            "arm_post must not register atexit in a guarded child"
        );
    }
}
