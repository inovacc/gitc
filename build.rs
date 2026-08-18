//! Link git's own compiled C objects into this Rust binary via the C ABI.
//!
//! We reuse the artifacts produced by building `git.exe` from git's C source
//! (msys2 UCRT64 gcc, `NO_RUST=1` — the traditional pure-C build). The FFI seam
//! is `cmd_main` (in `git.o`); startup setup is `init_git` (in `libgit.a`).
//!
//! Strategy: merge git's own objects into ONE static archive and let rustc link
//! it in the normal library position, so GNU ld resolves the git objects' CRT /
//! zlib / stack-protector symbols against the compiler's default libs (which
//! appear later on the link line). Passing the loose objects as trailing
//! `rustc-link-arg`s instead puts them *after* those default libs and single-pass
//! ld drops the symbols — the combined archive avoids that entirely, and ld
//! reprocesses a single archive until stable so intra-git circular refs resolve.
//!
//! What we merge (mirrors git's own `LINK git.exe` recipe), and what we DON'T:
//!   - `git.o`         -> contains `cmd_main` (the dispatch entry)     [MERGE]
//!   - `builtin/*.o`   -> every `cmd_<verb>` git.o's table references  [MERGE]
//!   - `libgit.a`      -> the bulk git library (incl. `init_git`)      [MERGE]
//!   - system libs     -> ws2_32 ntdll pcre2-8 z iconv advapi32        [LINK -l]
//!   - `common-main.o` -> defines `main()` — Rust owns main()          [EXCLUDE]
//!
//! Overridable env vars (all have local-machine defaults):
//!   GITC_GIT_SRC_DIR    git object dir (has git.o, libgit.a, builtin/*.o)
//!   GITC_UCRT64_LIB     UCRT64 lib dir (has libz.a, libpcre2-8.a, ...)
//!   GITC_AR             `ar` archiver to use (default: msys2 UCRT64 `ar`)

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// git's C source is VENDORED as a submodule at `vendor/git`, so the crate builds
/// from its own tree with no machine-local checkout. Resolved relative to
/// `CARGO_MANIFEST_DIR` (see `git_src_dir`), never as an absolute path.
const VENDORED_GIT_SUBDIR: &str = "vendor/git";
/// Default msys2 UCRT64 lib dir (standard install location). Override with
/// `GITC_UCRT64_LIB` when your msys2 lives elsewhere.
const DEFAULT_UCRT64_LIB: &str = r"C:\msys64\ucrt64\lib";
/// Default msys2 UCRT64 `ar` — the SAME toolchain that built git. Override with
/// `GITC_AR`.
const DEFAULT_AR: &str = r"C:\msys64\ucrt64\bin\ar.exe";

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-gnu") {
        // The git objects are mingw/gnu ABI; only the GNU target can link them.
        // The pure-Rust LIBRARY still builds/checks on any host — so instead of
        // failing the whole crate, skip the C link step here. The `gitc` BINARY
        // links only on `*-windows-gnu` (build there to produce a real git).
        println!(
            "cargo:warning=gitc: git-FFI binary links git's mingw/gnu C objects and \
             only builds on *-windows-gnu (got `{target}`); skipping the C link step \
             (the library builds normally). For the binary: \
             cargo build --release --target x86_64-pc-windows-gnu"
        );
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    let git_dir = git_src_dir(&manifest_dir);
    let ucrt64_lib = PathBuf::from(
        env::var("GITC_UCRT64_LIB").unwrap_or_else(|_| DEFAULT_UCRT64_LIB.to_string()),
    );
    let ar = env::var("GITC_AR").unwrap_or_else(|_| DEFAULT_AR.to_string());
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // The git C source/artifacts may be absent in this environment (the
    // `vendor/git` submodule is a gitlink that isn't checked out, or git hasn't
    // been built yet). The pure-Rust LIBRARY does not need them, so — as on the
    // non-gnu branch — skip the C link with a warning instead of failing the crate.
    // This lets `cargo zigbuild --lib` / `cargo check` succeed even on the gnu
    // target; the BINARY still needs the objects and will fail to link without them.
    if !git_dir.join("Makefile").exists() {
        println!(
            "cargo:warning=gitc: no git source at {} (submodule `{}` not checked out) — \
             skipping the C link step; the library builds. To link the BINARY, check out \
             the submodule and build git first (README §Build).",
            git_dir.display(),
            VENDORED_GIT_SUBDIR
        );
        return;
    }

    let git_o = git_dir.join("git.o");
    let libgit_a = git_dir.join("libgit.a");
    if !(git_o.exists() && libgit_a.exists()) {
        println!(
            "cargo:warning=gitc: git C artifacts (git.o/libgit.a) not built in {} — \
             skipping the C link step; the library builds. Build git first (README §Build: \
             `make NO_RUST=1 ... git.exe`) to link the BINARY.",
            git_dir.display()
        );
        return;
    }

    println!("cargo:rerun-if-changed={}", git_o.display());
    println!("cargo:rerun-if-changed={}", libgit_a.display());
    println!("cargo:rerun-if-changed=build.rs");
    for v in ["GITC_GIT_SRC_DIR", "GITC_UCRT64_LIB", "GITC_AR"] {
        println!("cargo:rerun-if-env-changed={v}");
    }

    // Collect the loose objects to merge: git.o + every builtin/*.o. git.c's
    // commands[] table references all of them; EXCLUDE common-main.o (top-level,
    // not under builtin/, and never added here).
    let mut objects: Vec<PathBuf> = vec![git_o];
    collect_objects(&git_dir.join("builtin"), &mut objects);

    // Build the combined archive via an `ar` MRI script (stdin) — no command-line
    // length limit, and `addlib` splices in all of libgit.a's members.
    let combined = out_dir.join("libgitall.a");
    let _ = std::fs::remove_file(&combined);
    let mut script = String::new();
    script.push_str(&format!("create {}\n", combined.display()));
    script.push_str(&format!("addlib {}\n", libgit_a.display()));
    for obj in &objects {
        script.push_str(&format!("addmod {}\n", obj.display()));
    }
    script.push_str("save\nend\n");

    run_ar_script(&ar, &script);
    assert!(
        combined.exists(),
        "ar did not produce {}",
        combined.display()
    );

    // Link with -municode so the CRT entry is `wmainCRTStartup`, which calls
    // git's own `wmain` (in mingw.o) to run all Windows startup and then call our
    // `main`. This also makes the CRT populate `_wpgmptr` (git's exec-path source).
    println!("cargo:rustc-link-arg=-municode");

    // Link the combined git archive (normal library position) + system libs.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=gitall");
    println!("cargo:rustc-link-search=native={}", ucrt64_lib.display());

    // System libs git.exe links (git's own recipe) + advapi32.
    //   pcre2-8/z/iconv -> DYNAMIC: git's objects reference the dllimport form,
    //     leaving a RUNTIME dependency on libpcre2-8-0.dll / zlib1.dll /
    //     libiconv-2.dll.
    //   ws2_32/ntdll    -> git's networking + NT syscalls.
    //   advapi32        -> SID/ACL security APIs, GetUserNameW, RtlGenRandom;
    //     used by compat/mingw.c, compat/simple-ipc/ipc-win32.c, wrapper.c.
    for lib in ["ws2_32", "ntdll", "pcre2-8", "z", "iconv", "advapi32"] {
        println!("cargo:rustc-link-lib={lib}");
    }
}

/// Resolve git's source dir: `GITC_GIT_SRC_DIR` if set (relocation escape hatch),
/// otherwise the vendored submodule inside this crate's own tree.
fn git_src_dir(manifest_dir: &Path) -> PathBuf {
    match env::var("GITC_GIT_SRC_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => manifest_dir.join(VENDORED_GIT_SUBDIR),
    }
}

/// Prepend `prog`'s own directory to the child's `PATH` so a pinned-path
/// toolchain binary can still load its sibling DLLs (`cc1`, `libwinpthread`, …),
/// which are resolved by PATH search regardless of the driver's own path.
fn with_own_dir_on_path(cmd: &mut Command, prog: &str) {
    let Some(dir) = Path::new(prog).parent() else {
        return;
    };
    if dir.as_os_str().is_empty() {
        return; // a bare name (e.g. an overriding `ar`) — leave PATH alone.
    }
    let existing = env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![dir.to_path_buf()];
    dirs.extend(env::split_paths(&existing));
    if let Ok(joined) = env::join_paths(dirs) {
        cmd.env("PATH", joined);
    }
}

/// Push every `*.o` under `dir` (recursively) into `out`.
fn collect_objects(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read git builtin dir {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_objects(&path, out);
        } else if path.extension().is_some_and(|e| e == "o") {
            out.push(path);
        }
    }
}

/// Feed an MRI script to `ar -M` via stdin.
fn run_ar_script(ar: &str, script: &str) {
    let mut cmd = Command::new(ar);
    with_own_dir_on_path(&mut cmd, ar);
    let mut child = cmd
        .arg("-M")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn `{ar} -M`: {e} (is the mingw `ar` on PATH?)"));
    child
        .stdin
        .take()
        .expect("ar stdin")
        .write_all(script.as_bytes())
        .expect("write ar script");
    let status = child.wait().expect("wait for ar");
    assert!(status.success(), "`{ar} -M` failed with {status}");
}
