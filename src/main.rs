//! gitc — a drop-in `git` that IS git.
//!
//! git's own C source is compiled to objects and linked into this binary (see
//! `build.rs`). The process entry point is git's real `wmain` (compat/mingw.c,
//! reached via `wmainCRTStartup` because we link `-municode`), which runs all of
//! git's Windows startup and then calls `main(argc, argv)` with clean UTF-8 argv.
//! THIS crate provides that `main` (via `#![no_main]` + an exported
//! `extern "C" fn main`), replacing git's `common-main.c` `main()`. It does the
//! same two things git's own `main()` does — `init_git` then `cmd_main` — so the
//! git behaviour reached through it is 1:1 git.
//!
//! ## What gitc adds around the dispatch
//!
//! Three things happen outside git's dispatcher, and all three are deliberate:
//!
//! 1. **gitc's own commands.** `gitc scan` / `gitc scrub` are handled in Rust and
//!    never reach git.
//! 2. **Pre/post stages** ([`gitc::stage`]) wrap git core: a pre stage — the
//!    machine/org enforcement gate, plus any external commands the policy names —
//!    runs before `init_git`/`cmd_main` and may refuse the command; post stages run
//!    after, via `atexit` so they still fire when git leaves through `die()`.
//! 3. **One passthrough default:** a bare `git init` is rewritten to
//!    `git init --initial-branch=main`. This is the *only* case where the argv
//!    handed to git differs from the one the user typed, and an explicit `-b` /
//!    `--initial-branch` always suppresses it.
//!
//! Every other invocation reaches git with its original argv, unmodified.

// `no_main` only in a real build — git's `wmain` provides the entry and calls our
// exported `main`. Under `cargo test`, libtest owns `main`, so we drop `no_main`
// (and the exported `main` below) and let the harness run any unit tests.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

mod ffi;

#[cfg(not(test))]
use std::os::raw::{c_char, c_int};

/// The C `main` that git's `wmain` calls. `argv` is a NULL-terminated array of
/// UTF-8 C strings (argv[0] = program path), already prepared by `wmain`.
///
/// SAFETY: called by git's `wmain` with a valid `argc` / NULL-terminated `argv`;
/// the pointers stay valid for the duration of the call.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main(argc: c_int, argv: *mut *mut c_char) -> c_int {
    // A panic must NOT unwind across this `extern "C"` boundary — UB on older
    // rustc, a hard abort (skipping C stdio flush) on current. Catch it, emit a
    // diagnostic, and return git's usage/refusal code so control unwinds cleanly
    // back through git's wmain → wmainCRTStartup exit() (which flushes stdio).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(argc, argv))) {
        Ok(code) => code,
        Err(_) => {
            eprintln!("gitc: internal error (panic) — refusing");
            128
        }
    }
}

/// git startup + dispatch — `init_git(argv)` then `cmd_main(argc, argv)`, the two
/// halves of git's `common-main.c` `main()` — wrapped by gitc's pre/post stages.
///
/// The argv handed to git is the original, unmodified one. Stages observe and may
/// refuse; they never rewrite what git receives.
///
/// SAFETY: `argv` is git's own wmain-provided NUL-terminated argv, valid for the
/// duration of the call; `cmd_main` treats it as `*const`.
#[cfg(not(test))]
fn run(argc: c_int, argv: *mut *mut c_char) -> c_int {
    let args = collect_args(argc, argv);

    // gitc pseudo-commands (`gitc scan …` / `gitc scrub …`) are handled in Rust and
    // never reach git's dispatcher. They are NOT staged: the stages gate *git*, and
    // a policy that refuses `git push` has no meaning applied to `gitc scan`.
    #[cfg(any(feature = "scan", feature = "scrub"))]
    match args.get(1).map(String::as_str) {
        #[cfg(feature = "scan")]
        Some("scan") => return gitc::scancmd::run(&args[2..]),
        #[cfg(feature = "scrub")]
        Some("scrub") => return gitc::scrubcmd::run(&args[2..]),
        _ => {}
    }

    // Passthrough default: a bare `git init` becomes `git init --initial-branch=main`.
    // `None` means the argv is untouched and git gets its own pointers verbatim.
    #[cfg(feature = "app")]
    let rewritten = init_default_branch(&args);
    #[cfg(not(feature = "app"))]
    let rewritten: Option<Vec<String>> = None;

    // Stages see what git will ACTUALLY run, so the audit row records the real
    // command rather than the one the user typed.
    let effective: &[String] = rewritten.as_deref().unwrap_or(&args);
    let git_args: &[String] = effective.get(1..).unwrap_or(&[]);

    // Arm the post stages BEFORE the gate runs, so a refused command is still
    // observed: a blocked exfil attempt is exactly the event worth recording.
    gitc::stage::arm_post(git_args);

    if let gitc::stage::Flow::Block(code) = gitc::stage::run_pre(git_args) {
        // git core is never entered. The post stages still fire on the way out,
        // through the same atexit path, with Outcome::Blocked.
        return code;
    }

    let code = match rewritten {
        Some(ref owned) => dispatch_owned(owned),
        None => {
            let argv = argv as *const *const c_char;
            // SAFETY: git's own wmain-provided argv, valid for this call.
            unsafe {
                ffi::init_git(argv);
                ffi::cmd_main(argc, argv)
            }
        }
    };

    // Reached only when git returns rather than exiting from inside C. Recording
    // the real code here is what lets the post stage report Outcome::Returned
    // instead of Outcome::Exited — see the `stage` module docs.
    gitc::stage::record_exit(code);
    code
}

/// Default branch gitc gives a repository it initialises.
#[cfg(all(not(test), feature = "app"))]
const DEFAULT_INIT_BRANCH: &str = "main";

/// Rewrites `git init` to carry `--initial-branch=main`, or `None` to leave argv
/// alone.
///
/// Returns `None` — meaning "pass through untouched" — when the command is not
/// `init`, or when the user already chose a branch with `-b` / `--initial-branch`.
/// An explicit choice always wins; gitc supplies a default, it does not overrule.
///
/// Note this DOES take precedence over a user's `init.defaultBranch` config, since
/// a command-line flag outranks config. That matches the behaviour the Go
/// implementation shipped and `policy::init_needs_branch` was written for.
#[cfg(all(not(test), feature = "app"))]
fn init_default_branch(args: &[String]) -> Option<Vec<String>> {
    let git_args = args.get(1..)?;
    let idx = gitc::policy::init_needs_branch(git_args)?;

    let injected = gitc::policy::inject_initial_branch(git_args, idx, DEFAULT_INIT_BRANCH);
    let mut out = Vec::with_capacity(injected.len() + 1);
    out.push(args[0].clone());
    out.extend(injected);

    // An interior NUL cannot survive the trip back through a C argv. It is
    // impossible in a real argv, but if it ever occurred, dropping the default is
    // correct and silently truncating the user's arguments is not.
    if out.iter().any(|s| s.as_bytes().contains(&0)) {
        return None;
    }

    Some(out)
}

/// Runs git core against an argv gitc built, rather than the one `wmain` handed us.
///
/// git retains pointers into argv for the life of the process — exec-path
/// derivation in `init_git`, trace2 output, error messages — so the strings must
/// outlive this call. They are leaked deliberately: the allocation is one argv, and
/// the process exits immediately after `cmd_main` returns.
///
/// Callers screen out interior NULs before reaching here (see
/// [`init_default_branch`]), so the `Err` arm is unreachable by construction; it
/// refuses rather than truncating, because quietly altering a user's git arguments
/// is worse than not applying a default.
#[cfg(all(not(test), feature = "app"))]
fn dispatch_owned(args: &[String]) -> c_int {
    use std::ffi::CString;

    let owned: Vec<CString> = match args
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let owned: &'static [CString] = Box::leak(owned.into_boxed_slice());
    let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null()); // git's argv is NULL-terminated.
    let ptrs: &'static [*const c_char] = Box::leak(ptrs.into_boxed_slice());

    let argc = owned.len() as c_int;
    let argv = ptrs.as_ptr();

    // SAFETY: `argv` is a NULL-terminated array of `argc` valid, NUL-terminated
    // UTF-8 C strings with 'static lifetime — the same shape `wmain` provides.
    unsafe {
        ffi::init_git(argv);
        ffi::cmd_main(argc, argv)
    }
}

/// Copy the C `argv` (UTF-8, NULL-terminated) into owned Rust strings for gitc
/// pseudo-command dispatch and for the pre/post stages.
#[cfg(not(test))]
fn collect_args(argc: c_int, argv: *mut *mut c_char) -> Vec<String> {
    use std::ffi::CStr;
    let mut out = Vec::with_capacity(argc.max(0) as usize);
    if argv.is_null() {
        return out;
    }
    for i in 0..argc as isize {
        // SAFETY: argv has `argc` valid, NUL-terminated C-string pointers.
        let p = unsafe { *argv.offset(i) };
        if p.is_null() {
            break;
        }
        out.push(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned());
    }
    out
}
