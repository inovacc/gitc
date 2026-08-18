//! gitc — a drop-in `git` that IS git.
//!
//! git's own C source is compiled to objects and linked into this binary (see
//! `build.rs`). The process entry point is git's real `wmain` (compat/mingw.c,
//! reached via `wmainCRTStartup` because we link `-municode`), which runs all of
//! git's Windows startup and then calls `main(argc, argv)` with clean UTF-8 argv.
//! THIS crate provides that `main` (via `#![no_main]` + an exported
//! `extern "C" fn main`), replacing git's `common-main.c` `main()`. It does the
//! exact same two things git's own `main()` does — `init_git` then `cmd_main` —
//! so behavior is 1:1 git. There is no wrapper logic in front of the dispatch:
//! gitc is git, rebuilt as a Rust binary via the C ABI.

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

/// Faithful git startup + dispatch, the two halves of git's `common-main.c`
/// `main()`: `init_git(argv)` then `cmd_main(argc, argv)`. The original,
/// unmodified argv is passed straight through — gitc adds nothing in front of
/// git's dispatcher.
///
/// SAFETY: `argv` is git's own wmain-provided NUL-terminated argv, valid for the
/// duration of the call; `cmd_main` treats it as `*const`.
#[cfg(not(test))]
fn run(argc: c_int, argv: *mut *mut c_char) -> c_int {
    // gitc pseudo-commands (`gitc scan …` / `gitc scrub …`) are handled in Rust
    // and never reach git's dispatcher; everything else passes straight to real git.
    #[cfg(any(feature = "scan", feature = "scrub"))]
    {
        let args = collect_args(argc, argv);
        match args.get(1).map(String::as_str) {
            #[cfg(feature = "scan")]
            Some("scan") => return gitc::scancmd::run(&args[2..]),
            #[cfg(feature = "scrub")]
            Some("scrub") => return gitc::scrubcmd::run(&args[2..]),
            _ => {}
        }
    }
    let argv = argv as *const *const c_char;
    unsafe {
        ffi::init_git(argv);
        ffi::cmd_main(argc, argv)
    }
}

/// Copy the C `argv` (UTF-8, NULL-terminated) into owned Rust strings for gitc
/// pseudo-command dispatch.
#[cfg(all(not(test), any(feature = "scan", feature = "scrub")))]
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
