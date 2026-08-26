# gitc
<!-- rev:003 (RFC 3339) 2026-08-25T23:00:00Z -->

> Git you can trust when the repository matters.

`gitc` is a Git-compatible developer tool for individuals and teams that want
normal Git workflows with security checks, history remediation, and a forensic
audit trail built in. It is written in Rust, works offline, and is designed to
be installed as the `git` command users already know.

## Why gitc?

- **Drop-in Git experience** — existing Git commands, scripts, hooks, and CI
  continue to work through the bundled Git-for-Windows backend.
- **Secret protection** — scan working trees, staged content, history, and
  outgoing changes before sensitive material leaves the repository.
- **Safe history remediation** — remove paths, redact content, or rewrite
  author/committer identities behind backups, dry-runs, ref scoping, and
  rollback support.
- **Forensic auditability** — record command activity and security decisions in
  a tamper-evident local audit log without sending repository data to a service.
- **Rust foundation** — memory-safe native code with pure-Rust readers for Git
  objects, packs, indexes, and reachable history.

## Get started

### Windows installer

Download the latest `gitc` installer from the [Releases](https://github.com/inovacc/gitc/releases)
page. The installer places `gitc` first on `PATH`, bundles the Git-for-Windows
runtime and helpers, and keeps that runtime private as the backend used by
history rewriting and transport commands.

After installation:

```powershell
git --version
git doctor
git where
```

### Build from source

```powershell
git clone https://github.com/inovacc/gitc.git
cd gitc
git submodule update --init --recursive vendor/git
cargo build --release --target x86_64-pc-windows-gnu
```

The complete Windows packaging flow is documented in
[packaging/windows/README.md](packaging/windows/README.md).

## Everyday workflows

Use ordinary Git commands as usual:

```text
git status
git add .
git commit -m "ship it"
git push
```

Run security workflows when needed:

```text
git scan                         # scan the working tree
git scan history                 # inspect reachable history
git scrub plan                  # preview remediation findings
git scrub identity --match-email old@example.com --name Maintainer --email maintainer@example.com
git install --apply              # install/update the PATH shim
```

Rewrites are intentionally guarded. `gitc` creates a local backup before a
rewrite, supports `--plan` and `--dry-run`, and requires explicit overrides for
unsafe repository states. Always review the plan before publishing rewritten
history.

## Product scope

`gitc` is for local development workstations, CI runners, and controlled build
environments where Git compatibility and security visibility need to coexist.
It does not upload source code, secrets, or audit data. Provider-specific policy
and enforcement can be enabled through the optional application feature.

## Library

Pure Rust, no external service — git formats parsed directly. **With no features
enabled** the only dependency is `flate2` (zlib inflate); the optional features
each pull in more.

| module | what it does | feature |
|---|---|---|
| `gitobj`   | read git objects by id — loose first, then packed | — |
| `gitpack`  | read objects from packfiles (`.git/objects/pack/*.{idx,pack}`) | — |
| `gitindex` | parse `.git/index` and enumerate the staged blobs | — |
| `gitwalk`  | enumerate the blobs reachable from a set of commits | — |
| `gitargs`  | a minimal git argv parser | — |
| `filterrepo` | a `git filter-repo` port for history rewriting | `scrub` |
| `scan`, `scancmd` | secret detection over the object readers | `scan` |
| `gates`, `policy`, `stage`, `store`, … | the enforcement + audit layer | `app` |

| feature | pulls in |
|---|---|
| `scan` | the vendored `crates/betterleaks` detection engine (18 crates) |
| `scrub` | `regex`, plus `scan` |
| `app` | the full application layer — SQLite (`rusqlite`, bundled C), `ratatui`, archive decoders, `serde`, `time`, … ≈ 16 direct dependencies, plus `scan` and `scrub` |

```
cargo test                              # library unit tests (no features)
cargo test --features app --lib         # the full suite — 331 tests
cargo build --features scrub
```

## Binary — git via FFI

git's process entry on Windows is its own `wmain` (`compat/mingw.c`), reached via
`wmainCRTStartup` because the binary is linked with `-municode`. `wmain` performs
all of git's mandatory Windows startup and then calls `main(argc, argv)` with
clean UTF-8 argv. This crate **provides that `main`** (via `#![no_main]` + an
exported `extern "C" fn main`), replacing git's `common-main.c` `main()`. Our
`main` does what git's does — `init_git(argv)` then `cmd_main(argc, argv)` — so
the git behaviour reached through it is 1:1 git.

Three things happen *around* that dispatch, and nothing else does:

1. **gitc's own commands** — `gitc scan` / `gitc scrub` are handled in Rust and
   never reach git.
2. **Pre/post stages** (`src/stage.rs`, feature `app`) — the machine-policy gate
   runs before `cmd_main` and may refuse the command; the audit writer runs after
   it, via `atexit` so it still fires when git leaves through `die()`.
3. **One passthrough default** — a bare `git init` becomes
   `git init --initial-branch=main`. An explicit `-b` suppresses it.

Every other invocation reaches git with its original argv, unmodified.

```
src/main.rs   the exported extern "C" main → stages → init_git → cmd_main
src/ffi.rs    the two FFI declarations (init_git, cmd_main)
src/stage.rs  the pre/post seam around the dispatch
build.rs      merges git.o + builtin/*.o + libgit.a into one archive and links it
vendor/git    git's C source, as a submodule (github.com/git/git)
```

`common-main.o` is deliberately NOT linked (Rust owns `main`); git's `wmain`
lives in `mingw.o` inside the combined git archive.

### Build (binary)

The binary links git's own mingw/gnu-ABI objects, so it **must** be built for a
`*-windows-gnu` target with the msys2 UCRT64 toolchain (the same one that builds
git). The library builds on any host; only the binary needs this.

1. **Toolchain** — install [msys2](https://www.msys2.org/) and the UCRT64 gcc:
   ```
   pacman -S mingw-w64-ucrt-x86_64-gcc
   rustup target add x86_64-pc-windows-gnu
   ```
   **Note:** the linker block in `.cargo/config.toml` is currently **commented
   out**, so a fresh clone gets no linker configuration from it. Either uncomment
   it or set `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER` to your gcc path.

2. **git source** — check out the vendored submodule:
   ```
   git submodule update --init --recursive vendor/git
   ```

3. **Build git's C objects** once, in the msys2 UCRT64 shell — note `curl` is
   required (HTTPS transport) so `NO_CURL` is deliberately absent:
   ```
   cd vendor/git
   make -j4 MSYSTEM=MINGW64 NO_RUST=1 NO_OPENSSL=1 NO_EXPAT=1 \
        NO_GETTEXT=1 NO_TCLTK=1 NO_PERL=1 NO_PYTHON=1 git.exe git-remote-http.exe
   ```
   This produces `git.o`, `builtin/*.o`, `libgit.a` (the FFI inputs), and the
   separate `git-remote-http.exe` (installed at run time for https).

4. **Build gitc**:
   ```
   cargo build --release --target x86_64-pc-windows-gnu
   ```

   The runtime needs `libpcre2-8-0.dll` / `zlib1.dll` / `libiconv-2.dll` on PATH,
   and — for **https remotes** — `git-remote-http(s).exe` + its DLL closure + a CA
   bundle installed under the binary's `libexec/git-core`. See **[REQUIREMENTS.md](REQUIREMENTS.md)**
   for the complete build- and run-time spec (toolchain, artifacts, HTTPS helper,
   templates, and the `GITC_*` build env overrides).

## Licensing

The Rust code in this repository is BSD-3-Clause. The built **binary** statically
incorporates git's own C source (`vendor/git`, git/git), which is **GPL-2.0** —
so the distributed binary is governed by git's license. See `vendor/git/COPYING`.
The **library** links no git C and is BSD-3-Clause on its own.
