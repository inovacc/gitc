# gitc — Requirements

`gitc` ships two things with very different requirements:

- **The library** (`src/lib.rs`: `gitobj`/`gitpack`/`gitindex`/`gitwalk`/`gitargs`
  + optional `filterrepo`) is pure Rust — it builds and tests on **any** host with
  only `flate2` (and `regex` under the `scrub` feature). Nothing below applies to
  it: `cargo build` / `cargo test` just work.

- **The binary** (`src/main.rs`) is a drop-in `git` that IS git — git's own C is
  compiled to objects and linked in via the C ABI. Everything below is about
  building and running that binary. It is Windows-x64 / msys2-UCRT64 only.

## 1. What it is (architecture)

The process entry chain is **git's own**; Rust only owns the `main` git's `wmain`
calls:

```
wmainCRTStartup           (CRT, selected by -municode)
  └─ wmain()              (git, compat/mingw.c) — ALL Windows startup:
       │                    redirect std handles, wide→UTF-8 argv/env,
       │                    setup_windows_environment(), critical-section init,
       │                    _fmode=_O_BINARY, winansi_init(), console ctrl handler
       └─ main(argc, argv) (OURS — src/main.rs, #[no_mangle] extern "C")
            ├─ init_git(argv)            (git, common-init.c)
            └─ cmd_main(argc, argv)      (git, git.c) → builtin dispatch
```

Key decisions:

- **`#![no_main]` + exported `extern "C" fn main`** — git's `wmain` must run first
  (it initializes static critical sections + console state). We let `wmain` run and
  make our function BE the `main` it calls. `common-main.o` (git's own `main`) is
  therefore NOT linked.
- **`-municode`** — makes the CRT entry `wmainCRTStartup` (which calls git's
  `wmain`) and populates `_wpgmptr`, git's Windows exec-path source. Without it
  git's startup never runs and `git_get_exec_path` NULL-derefs.
- **Combined static archive (`libgitall.a`)** — `build.rs` merges `git.o` + all
  `builtin/*.o` + `libgit.a` members into ONE archive linked via
  `rustc-link-lib=static`, so single-pass GNU ld resolves git's internal circular
  refs (loose trailing objects would be dropped).

## 2. Build-time requirements (binary)

### 2.1 Toolchains

| Requirement | Detail |
|---|---|
| **msys2 UCRT64** | GCC toolchain that builds git and links this crate. `gcc -dumpmachine` → `x86_64-w64-mingw32`. Its `bin/` must be on `PATH` at build time (provides `gcc`, `ar`, `dlltool`, GNU `ld`). |
| **msys2 packages** | `diffutils` (git's `GIT-VERSION-GEN` needs `cmp`), `mingw-w64-ucrt-x86_64-pcre2` (git wants `pcre2.h`), `mingw-w64-ucrt-x86_64-curl` (git's HTTPS transport — see §2.2). `pacman -S --needed diffutils mingw-w64-ucrt-x86_64-pcre2 mingw-w64-ucrt-x86_64-curl` |
| **Rust GNU target** | `rustup target add x86_64-pc-windows-gnu`. The git objects are mingw/gnu ABI; the default msvc target CANNOT link them. `build.rs` skips the C-link step on any non-`*-windows-gnu` target (so the library still builds there). |

### 2.2 Built git artifacts (the FFI inputs)

Check out the vendored submodule first:

```sh
git submodule update --init --recursive vendor/git
```

Then build git from its C source with the **pure-C** configuration (`NO_RUST=1`).
From `vendor/git`, in the msys2 UCRT64 shell:

```sh
make -j4 MSYSTEM=MINGW64 NO_RUST=1 NO_OPENSSL=1 NO_EXPAT=1 \
        NO_GETTEXT=1 NO_TCLTK=1 NO_PERL=1 NO_PYTHON=1 git.exe git-remote-http.exe
```

- `MSYSTEM=MINGW64` (make override, not the env) sidesteps git's
  `config.mak.uname` not recognizing `UCRT64`.
- Building `git.exe` (not just `libgit.a`) proves the objects form a complete,
  self-consistent link unit.
- **`NO_CURL=1` is deliberately ABSENT.** With it, git builds no HTTP transport and
  no `git-remote-http.exe`, so every https `clone`/`fetch`/`pull` dies with
  `git: 'remote-https' is not a git command`. `NO_OPENSSL=1` stays: curl brings its
  own TLS.
- `git-remote-http.exe` is a SEPARATE executable git spawns from its exec-path; it
  is NOT linked into this crate — building it here only produces it (installed at
  run time, §3).

This produces, in `vendor/git`: **`git.o`** (contains `cmd_main`), **~130×
`builtin/*.o`**, **`libgit.a`** (contains `init_git`, `wmain`, curl-backed
`http.o`/`remote-curl.o`), and **`git-remote-http.exe`**. `common-main.o` is built
but intentionally NOT linked by us.

### 2.3 Build command

```powershell
# UCRT64 bin on PATH so cargo's gnu linker finds gcc/ar; then:
cargo build --release --target x86_64-pc-windows-gnu
```

`.cargo/config.toml` sets the gnu-target linker to the msys2 UCRT64 gcc and
`-Clink-self-contained=no` (use the system CRT, consistent with git's objects).
rustc's own link step invokes the gnu linker independently of `build.rs`, so
UCRT64 `bin/` must be on `PATH` or the build fails at link with
`ld returned N exit status`.

### 2.4 Configurable env vars (build.rs)

All default to standard msys2 paths; override to relocate:

| Env var | Default | Purpose |
|---|---|---|
| `GITC_GIT_SRC_DIR` | `vendor/git` (in-tree) | git object dir (`git.o`, `libgit.a`, `builtin/*.o`). |
| `GITC_UCRT64_LIB` | `C:\msys64\ucrt64\lib` | UCRT64 lib dir (`libz.a`, `libpcre2-8.a`, `libiconv.a`, …). |
| `GITC_AR` | `C:\msys64\ucrt64\bin\ar.exe` | the mingw `ar` used to build the combined archive. |

(gitc compiles no C shim of its own — there is no `GITC_CC`.)

## 3. Run-time requirements (binary)

- **Windows x64 (UCRT).** Imports UCRT (`api-ms-win-crt-*`), `kernel32`, `ntdll`,
  `ws2_32`, `advapi32`, `bcryptprimitives`, `userenv` — all OS-provided.
- **Three msys2 DLLs on `PATH` (or beside `gitc.exe`):** `libpcre2-8-0.dll`,
  `zlib1.dll`, `libiconv-2.dll`. git's objects reference these via dllimport, so
  they are dynamic. Ship them alongside the exe for a self-contained deploy, or
  keep msys2 UCRT64 `bin/` on `PATH`.
- **HTTPS transport (REQUIRED for https remotes).** git resolves `RUNTIME_PREFIX`
  from its own exe, so a binary at `<prefix>\bin\gitc.exe` (or a copy renamed
  `git.exe`) looks for helpers in `<prefix>\libexec\git-core`. Install there, from
  the §2.2 build:
  - `git-remote-http.exe`, copied a second time as **`git-remote-https.exe`** (git
    ships one binary under several helper names; spawned by URL scheme).
  - Its non-system DLL closure (`ldd git-remote-http.exe | grep ucrt64`) — ~18 DLLs
    (`libcurl-4`, `libcrypto-3-x64`, `libssl-3-x64`, `libssh2-1`, `libnghttp2-14`,
    `libbrotli*`, `libidn2-0`, `libpsl-5`, `libzstd`, `zlib1`, …) beside the helper,
    or msys2 UCRT64 `bin/` on `PATH`.
  - **CA bundle** at `<prefix>\libexec\etc\ssl\certs\ca-bundle.crt` (copy from
    `…\ucrt64\etc\ssl\certs\ca-bundle.crt`). Without it every https fetch fails with
    `error adding trust anchors from file: …`. The path is relative to the HELPER's
    prefix (`libexec\`), not the binary's.
  - Unlike the gated original, gitc has no gate — so **`GIT_EXEC_PATH` also works**:
    point it at a dir containing the helpers instead of installing under
    `<prefix>\libexec\git-core`.
- **git templates (optional):** without a template tree gitc prints a harmless
  `templates not found in <prefix>\share\git-core\templates` warning on every
  `clone`/`init`. Silence it with `make -C templates` (plain `make templates` is a
  no-op) and copy `templates/blt/.` to `<prefix>\share\git-core\templates`.

## 4. Deploying as a drop-in `git`

Rename `gitc.exe` → `git.exe`, place it in an existing git install's `bin/` (so it
inherits that install's `libexec/git-core`, templates, and DLLs), and put that
directory first on `PATH`. Every `git …` then runs gitc, which is git.

## 5. Verified behavior (binary)

Full local lifecycle through the binary (git's C underneath): `--version`, `init`,
`config`, `add`, `commit`, `log`, `status`, `branch`, `rev-parse` — all correct,
exit codes faithful.

## Licensing

The library links no git C and is BSD-3-Clause. The binary statically incorporates
git's own C (`vendor/git`, git/git), which is GPL-2.0 — so the distributed binary
is governed by git's license. See `vendor/git/COPYING`.
