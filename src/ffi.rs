//! FFI bindings to git's own C entry points, linked in via `build.rs`.
//!
//! The process entry is git's OWN `wmain` (compat/mingw.c), which the CRT invokes
//! via `wmainCRTStartup` because we link with `-municode`. `wmain` performs all of
//! git's mandatory Windows startup — std-handle redirection, wide→UTF-8 argv/env
//! conversion, `setup_windows_environment()`, critical-section init, binary file
//! modes, `winansi_init()` — and THEN calls `main(argc, argv)` with clean UTF-8
//! argv. Our `main` (in `main.rs`) is that `main`: it replaces git's
//! `common-main.c` `main()`. `common-main.o` is therefore NOT linked (we provide
//! `main`); `wmain` lives in `mingw.o` inside the combined git archive.

use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    /// git's process setup (`common-init.c`): trace2 init, stdio sanitize,
    /// signal defaults, exec-path derivation from `argv[0]`, etc.
    pub fn init_git(argv: *const *const c_char);

    /// git's command dispatcher (`git.c`): parses the subcommand from `argv`
    /// and runs the corresponding builtin. Returns the process exit code.
    pub fn cmd_main(argc: c_int, argv: *const *const c_char) -> c_int;
}
