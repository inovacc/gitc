//! Port of Go `main.go` (package main) — gitc's root orchestration.
//!
//! gitc is a git binary: it replaces git on PATH and provides all git-related
//! functionality under one tool. It forwards ordinary git invocations (args,
//! stdin/stdout/stderr, exit code) to a git backend while recording an append-only
//! forensic audit trail, and it adds its own first-class commands — `git scan`,
//! `git scrub`, `git audit`, `git where`, `git install` — plus shortcuts
//! (`git sync`/`undo`/`log-graph`/`quick-commit`). Native names that would collide
//! with a real git subcommand are reached via the `git gitc <cmd>` namespace;
//! everything unrecognized passes through to real git.
//!
//! ## What is ported here vs. what is binary glue
//!
//! The testable orchestration — [`run`], [`run_meta`], [`run_update`], and the
//! [`has_help_flag`]/[`print_self_info`]/[`print_meta_help`] helpers — is ported
//! 1:1 and carries the `main_test.go` suite. The Go `func main()` top-level is a
//! thin dispatch (arg0 shell-launcher check, a `signal.NotifyContext`, `os.Exit`);
//! its arg0 dispatch is reproduced in [`main_entry`], but two pieces stay the
//! binary's responsibility and are FLAGGED, not faked:
//!
//! - **HTTP client construction.** Go built `net/http` inline; per the pair pack
//!   the HTTP layer is an injected [`HttpClient`] (as already done for `selfupdate`
//!   / `provision` / `backendupdate`), so `run`/`run_meta`/`run_update`/`main_entry`
//!   take `http: &dyn HttpClient`. The concrete client lives in the binary wiring.
//! - **Signal-cancelled context.** Go built a `signal.NotifyContext(Interrupt,
//!   SIGTERM)`; std has no signal handling without a dependency, so the cancel
//!   token ([`Ctx`]) is supplied by the caller (the binary wires the handler).

use crate::selfupdate::HttpClient;
use crate::store::Store;
use crate::{
    auditcmd, backend, backendupdate, cmdtree, doctor, enrich, enrich::Ctx, gates, installer,
    policy, provision, router, runner, scancmd, scrubcmd, selfupdate, shell, shortcut, store,
};

/// gitc's own version. Go declared `var version = "dev"`, overridden at build time
/// via `-ldflags "-X main.version=..."`; the Rust-idiomatic equivalent is a
/// build-time env override (`GITC_VERSION`), defaulting to `"dev"` bug-for-bug.
pub const VERSION: &str = match option_env!("GITC_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// The Go `main()` top-level dispatch, minus the binary-only glue (real HTTP
/// client construction, signal-cancel context, `os.Exit`). Given the program's
/// `arg0`, the CLI `args` (arguments after the program name), an injected HTTP
/// client, and a cancel token, returns the process exit code.
///
/// When invoked under the name `sh`/`bash` (via an installed shim), gitc acts as a
/// launcher for the managed backend's shell instead of the git proxy — this arg0
/// dispatch IS reproduced. FLAG: the Go `signal.NotifyContext` is not built here
/// (std lacks signal handling without a dep); the binary supplies `ctx`.
pub fn main_entry(arg0: &str, args: &[String], ctx: &Ctx, http: &dyn HttpClient) -> i32 {
    if let Some(name) = shell::shell_name(arg0) {
        return shell::run_shell(&name, args);
    }
    run(ctx, args, http)
}

/// The foreground command flow: classify the invocation, open the (best-effort)
/// audit store, dispatch a gitc-native command, or resolve a backend and run the
/// passthrough/shortcut through the audited, gated runner. Faithful port of Go
/// `run`.
pub fn run(ctx: &Ctx, args: &[String], http: &dyn HttpClient) -> i32 {
    backendupdate::clean_shim_backups();

    let shortcuts = shortcut::all();
    let dec = router::classify(args, &shortcuts);

    // Audit store is best-effort: if it can't open, git still runs (the runner
    // warns per invocation). Meta commands may need it read-only. The Store closes
    // on Drop at the end of this function (Go's `defer st.Close()`).
    let st = match store::open(provision::audit_db_path()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("gitc: audit log unavailable: {e}");
            None
        }
    };

    if dec.kind == router::Kind::Meta {
        return run_meta(ctx, &dec.args, st.as_ref(), http);
    }

    // On ordinary git usage, surface any pending update notice and lazily kick off
    // a throttled background update check — never blocking this command.
    if std::env::var_os("GITC_BACKGROUND").is_none() {
        backendupdate::print_and_clear_notice();
        backendupdate::maybe_spawn_background_update();
    }

    // Passthrough and shortcuts require a resolved backend. Fail fast before any
    // exec if none is available.
    let self_path = std::env::current_exe().unwrap_or_default();

    let mut stderr = std::io::stderr();
    let b = match provision::resolve_or_provision(http, &self_path, &mut stderr) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gitc: {e}");
            return 1;
        }
    };

    // Extract what the runner move would otherwise take away: the backend git path
    // (for enrichment + the gate closure) and the init-branch capability probe.
    let git_path = b.path.to_string_lossy().into_owned();
    let supports_initial_branch = b.supports_initial_branch();

    let mut r = runner::Runner::new(
        b,
        st.as_ref(),
        Some(enrich::new_exec(&git_path)),
        None,
    );

    // Enforce the machine/org policy (secret gate, remote allowlist) at the single
    // choke point the runner funnels every git vector through — so built-in
    // shortcuts (which expand to push/commit steps) are gated exactly like
    // passthrough and cannot bypass enforcement. A blocked command never reaches
    // git. The backend path lets the allowlist resolve named/default remotes.
    let gate_git_path = git_path.clone();
    r.guard(Box::new(move |_ctx, args| {
        gates::enforce_gates(args, &gate_git_path)
    }));

    // Record which enforcement policy governed this process on every audit row
    // (SEC-2), so a policy relocation is forensically visible. Resolved once — the
    // machine-dir path is stable for the process.
    let policy_path = gates::enforcement_policy_path();
    if !policy_path.is_empty() {
        r.set_policy_path(&policy_path);
    }

    match dec.kind {
        router::Kind::RunShortcut => {
            // `shortcut` is only meaningful for RunShortcut (guaranteed by classify).
            let sc = dec.shortcut.expect("RunShortcut decision carries a shortcut");
            r.shortcut(ctx, sc, &dec.args)
        }
        _ => {
            let mut passthrough_args = dec.args;
            // New repos default to `main`, not `master`, unless the user chose a
            // branch. Only inject when the backend git supports the flag.
            if let Some(idx) = policy::init_needs_branch(&passthrough_args) {
                if supports_initial_branch {
                    passthrough_args =
                        policy::inject_initial_branch(&passthrough_args, idx, "main");
                }
            }
            r.passthrough(ctx, &passthrough_args)
        }
    }
}

/// Handles gitc's own commands. They are reachable first-class as `git <cmd>` (for
/// names that don't collide with real git) and always via the explicit
/// `git gitc <cmd>` namespace. Bare `git gitc` prints gitc self-info. Faithful port
/// of Go `runMeta`.
///
/// Go took a nilable `*store.Store`; here `st` is `Option<&Store>`, and the
/// `audit` case reproduces Go `auditcmd.Run`'s nil guard at this call site (the
/// ported `auditcmd::run` requires a live `&Store`).
pub fn run_meta(ctx: &Ctx, args: &[String], st: Option<&Store>, http: &dyn HttpClient) -> i32 {
    let cmd = args.first().map(String::as_str).unwrap_or("");

    // `git <cmd> --help` shows that command's usage (from the cmdtree catalog)
    // rather than falling through to run it.
    if !cmd.is_empty() && cmd != "help" && has_help_flag(&args[1..]) {
        return cmdtree::run(&["-c".to_string(), cmd.to_string()]);
    }

    match cmd {
        "" | "help" => {
            print_self_info();
            print_meta_help();
            0
        }
        "version" => {
            println!("gitc {VERSION}");
            0
        }
        "where" => {
            let self_path = std::env::current_exe().unwrap_or_default();
            match backend::resolve(provision::managed_git_path().as_deref(), &self_path) {
                Ok(b) => {
                    println!("backend: {} ({})", b.path.display(), b.kind);
                    println!("audit:   {}", provision::audit_db_path().display());
                    0
                }
                Err(e) => {
                    eprintln!("gitc: {e}");
                    1
                }
            }
        }
        "audit" => match st {
            Some(s) => auditcmd::run(&args[1..], s),
            None => {
                eprintln!("gitc: audit log unavailable");
                1
            }
        },
        "install" => {
            let apply = args[1..].iter().any(|a| a == "--apply");
            match installer::installer::install(apply) {
                Ok(res) => {
                    println!("shim git: {}", res.shim_git.display());
                    if !res.backend_path.as_os_str().is_empty() {
                        println!("delegates to: {}", res.backend_path.display());
                    } else {
                        println!("git backend: none yet — provisioned on the first git command (Windows) or via `git fetch-git`");
                    }
                    if res.path_applied {
                        println!("PATH updated for the current user; restart your shell to activate.");
                    } else {
                        println!("{}", res.instruction);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("gitc: {e}");
                    1
                }
            }
        }
        "uninstall" => match installer::installer::uninstall() {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("gitc: {e}");
                1
            }
        },
        // Go `scrubcmd.Run(ctx, args[1:])`; the ported `scrubcmd::run` takes no
        // cancel token, so `ctx` is intentionally unused here.
        "scrub" => {
            let _ = ctx;
            scrubcmd::run(&args[1..])
        }
        "scan" => scancmd::run(&args[1..]),
        "fetch-git" => provision::fetch_git(http, &args[1..]),
        "update" => run_update(&args[1..], http),
        "doctor" => doctor::run(
            doctor::Config {
                version: VERSION.to_string(),
                managed_git_path: provision::managed_git_path(),
                audit_db_path: provision::audit_db_path(),
            },
            &args[1..],
        ),
        "cmdtree" => cmdtree::run(&args[1..]),
        // `git gitc sh` / `git gitc bash` — launch the managed backend's shell. The
        // installed sh.exe/bash.exe shims reach this same logic by name.
        "sh" | "bash" => shell::run_shell(cmd, &args[1..]),
        "backend-update" => backendupdate::run_backend_update(http),
        _ => {
            eprintln!("gitc: unknown command {cmd:?}");
            print_meta_help();
            2
        }
    }
}

/// Implements `git update`: check the gitc GitHub releases for a newer version
/// (`--check`) or download and replace this binary in place (`--apply`). With no
/// flag it checks and, if an update exists, tells the user to pass `--apply`.
/// Faithful port of Go `runUpdate` (ctx dropped; `http` injected).
pub fn run_update(args: &[String], http: &dyn HttpClient) -> i32 {
    let mut check = false;
    let mut apply = false;

    for a in args {
        match a.as_str() {
            "--check" => check = true,
            "--apply" => apply = true,
            _ => {
                eprintln!("git update: unknown flag {a:?}");
                return 2;
            }
        }
    }

    // `selfupdate::check` always yields `Some(info)` on success (the `Option` is a
    // surface shape; see its docs) — `Ok(None)` is unreachable, treated as up to date.
    let info = match selfupdate::check(VERSION, http) {
        Ok(Some(info)) => info,
        Ok(None) => return 0,
        Err(e) => {
            eprintln!("git update: {e}");
            return 1;
        }
    };

    println!("current: {}\nlatest:  {}", info.current, info.latest);

    if !info.has_update {
        println!("gitc is up to date.");
        return 0;
    }

    println!("a newer release is available: {}", info.latest);

    if check || !apply {
        println!("run `git update --apply` to install it.");
        return 0;
    }

    let self_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("git update: locate self: {e}");
            return 1;
        }
    };

    println!("downloading {}...", info.asset.name);

    if let Err(e) = selfupdate::apply(&info.asset, &self_path, http) {
        eprintln!("git update: {e}");
        return 1;
    }

    println!("updated to {}: {}", info.latest, self_path.display());

    0
}

/// Reports whether `args` request help for a meta command. Faithful port of Go
/// `hasHelpFlag`.
pub fn has_help_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// Shows gitc's identity: version, resolved git backend, audit DB. Faithful port of
/// Go `printSelfInfo`.
pub fn print_self_info() {
    println!("gitc {VERSION} — git wrapper with forensic audit, secret scan, history scrub");

    let self_path = std::env::current_exe().unwrap_or_default();
    if let Ok(b) = backend::resolve(provision::managed_git_path().as_deref(), &self_path) {
        println!("git backend: {} ({})", b.path.display(), b.kind);
    }

    println!("audit log:   {}", provision::audit_db_path().display());
}

/// Lists gitc's native commands. Faithful port of Go `printMetaHelp` (written to
/// stderr, matching the Go source).
pub fn print_meta_help() {
    eprintln!("\ngitc commands (each also as `git gitc <cmd>`):");
    eprintln!("  git scan [path]         detect secrets (exit 1 if any found)");
    eprintln!("  git scrub [opts]        rewrite history: purge paths / redact text (--force to apply)");
    eprintln!("  git audit [N] [--wide]  show the last N audited invocations (compact; --wide=full)");
    eprintln!("  git where               show resolved git backend and audit DB path");
    eprintln!("  git doctor              health-check install, backend, PATH shim, audit DB");
    eprintln!("  git update [--check|--apply]     self-update gitc from GitHub releases");
    eprintln!("  git fetch-git [--latest|--list|--busybox]  download a git backend");
    eprintln!("                          (--busybox bundles a shell for git hooks)");
    eprintln!("  git install [--apply]   install the PATH shim (--apply prepends PATH)");
    eprintln!("  git uninstall           remove the PATH shim");
    eprintln!("  git cmdtree [-b|--json] show the full command tree");
    eprintln!("  git gitc sh|bash [args] launch the managed backend's shell (also the sh/bash shims)");
    eprintln!("  git sync|undo|log-graph|quick-commit    built-in shortcuts");
    eprintln!("  git gitc version        print gitc's own version");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfupdate::{HttpError, HttpResponse};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// An [`HttpClient`] that fails on any call — the tested meta paths (version,
    /// help, unknown, `scan --help`, `gitc version`, `update --nope`) never touch
    /// the network, so a real client is unnecessary and undesirable in tests.
    struct NoNet;
    impl HttpClient for NoNet {
        fn get(&self, _url: &str, _accept: &str) -> Result<HttpResponse, HttpError> {
            Err(HttpError {
                message: "no network in tests".to_string(),
            })
        }
    }

    // ── TestHasHelpFlag ─────────────────────────────────────────────────────
    #[test]
    fn has_help_flag_cases() {
        assert!(has_help_flag(&argv(&["-h"])), "-h should be detected");
        assert!(
            has_help_flag(&argv(&["x", "--help"])),
            "--help should be detected"
        );
        assert!(
            !has_help_flag(&argv(&["status", "-w"])),
            "no help flag present"
        );
    }

    // ── TestRunMetaVersion ──────────────────────────────────────────────────
    #[test]
    fn run_meta_version() {
        let ctx = Ctx::background();
        assert_eq!(
            run_meta(&ctx, &argv(&["version"]), None, &NoNet),
            0,
            "version exit"
        );
    }

    // ── TestRunMetaBareAndHelp ──────────────────────────────────────────────
    #[test]
    fn run_meta_bare_and_help() {
        let ctx = Ctx::background();
        assert_eq!(run_meta(&ctx, &[], None, &NoNet), 0, "bare runMeta");
        assert_eq!(run_meta(&ctx, &argv(&["help"]), None, &NoNet), 0, "help");
    }

    // ── TestRunMetaUnknownCommand ───────────────────────────────────────────
    #[test]
    fn run_meta_unknown_command() {
        let ctx = Ctx::background();
        assert_eq!(
            run_meta(&ctx, &argv(&["definitely-not-a-command"]), None, &NoNet),
            2,
            "unknown meta command exit"
        );
    }

    // ── TestRunMetaHelpFlagShowsUsage ───────────────────────────────────────
    #[test]
    fn run_meta_help_flag_shows_usage() {
        // `git scan --help` renders the cmdtree usage rather than running scan
        // (which would need a backend), so it is safe with a nil store.
        let ctx = Ctx::background();
        assert_eq!(
            run_meta(&ctx, &argv(&["scan", "--help"]), None, &NoNet),
            0,
            "scan --help exit"
        );
    }

    // ── TestRunUpdateUnknownFlag ────────────────────────────────────────────
    #[test]
    fn run_update_unknown_flag() {
        // The flag parse rejects an unknown flag (exit 2) before any network call.
        assert_eq!(
            run_update(&argv(&["--nope"]), &NoNet),
            2,
            "update --nope exit"
        );
    }

    // ── TestRunRoutesMetaCommand ────────────────────────────────────────────
    #[test]
    fn run_routes_meta_command() {
        // Route `git gitc version` through run(): it opens the audit store, sees a
        // Meta decision, and dispatches to run_meta — no backend required. Serialize
        // on the process-global env the store path + background flag ride on.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ENV_LOCK.lock().unwrap();

        let saved_db = std::env::var_os("GITC_AUDIT_DB");
        let saved_bg = std::env::var_os("GITC_BACKGROUND");

        let mut db = std::env::temp_dir();
        db.push(format!("gitc_appmain_audit_{}.db", std::process::id()));
        std::env::set_var("GITC_AUDIT_DB", &db);
        std::env::set_var("GITC_BACKGROUND", "1"); // suppress the background update spawn

        let ctx = Ctx::background();
        let code = run(&ctx, &argv(&["gitc", "version"]), &NoNet);

        match saved_db {
            Some(v) => std::env::set_var("GITC_AUDIT_DB", v),
            None => std::env::remove_var("GITC_AUDIT_DB"),
        }
        match saved_bg {
            Some(v) => std::env::set_var("GITC_BACKGROUND", v),
            None => std::env::remove_var("GITC_BACKGROUND"),
        }
        let _ = std::fs::remove_file(&db);

        assert_eq!(code, 0, "run(gitc version)");
    }

    // ── TestPrintSelfInfoAndHelpDoNotPanic ──────────────────────────────────
    #[test]
    fn print_self_info_and_help_do_not_panic() {
        // The Go test redirects stdout/stderr to a temp file; here we only assert
        // the printers don't panic (they exercise backend resolution).
        print_self_info();
        print_meta_help();
    }

    // ── main_entry arg0 dispatch (Go main()'s shellName branch) ─────────────
    #[test]
    fn main_entry_routes_meta_and_shell() {
        let ctx = Ctx::background();
        // arg0 "gitc" with `gitc version` routes through run() -> run_meta -> 0.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_db = std::env::var_os("GITC_AUDIT_DB");
        let saved_bg = std::env::var_os("GITC_BACKGROUND");
        let mut db = std::env::temp_dir();
        db.push(format!("gitc_appmain_me_{}.db", std::process::id()));
        std::env::set_var("GITC_AUDIT_DB", &db);
        std::env::set_var("GITC_BACKGROUND", "1");

        let code = main_entry("gitc", &argv(&["gitc", "version"]), &ctx, &NoNet);

        match saved_db {
            Some(v) => std::env::set_var("GITC_AUDIT_DB", v),
            None => std::env::remove_var("GITC_AUDIT_DB"),
        }
        match saved_bg {
            Some(v) => std::env::set_var("GITC_BACKGROUND", v),
            None => std::env::remove_var("GITC_BACKGROUND"),
        }
        let _ = std::fs::remove_file(&db);

        assert_eq!(code, 0, "main_entry(gitc, [gitc version]) should route to meta");
    }
}
