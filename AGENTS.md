# AGENTS.md
<!-- rev:003 -->

Canonical cross-tool agent instructions for **gitc** — a **Rust** drop-in `git` that *is*
git: git's own C source is compiled and linked into the binary via the C ABI, so ordinary
git commands are 1:1 git. Around that core gitc adds a secret scanner (`gitc scan`), a
history scrubber (`gitc scrub`), a non-bypassable machine/org policy gate, and an
append-only, tamper-evident forensic audit trail.

> **This project was ported from Go and the Go implementation has been removed.** The
> original lives on the `go-main` branch (`5685cad`) and nowhere else. `internal/*`,
> `go.mod`, Task/golangci/goreleaser configs no longer exist — if a doc or comment
> mentions them, it is describing the retired implementation, not this tree. Module
> doc-comments that say "Port of Go `internal/x`" are deliberate provenance notes.

Architecture: `docs/ARCHITECTURE.md` (**stale — still describes the Go tree; see BUGS**);
decisions: `docs/adr/` (**all 7 are Go-era**); port lineage: `PORT-TRACK.md`,
`PORT-GLOSSARY.md`, `PORT-PROVENANCE.json`.

## Project shape

- **Crate:** `gitc` (bin + lib), `src/lib.rs` + `src/main.rs`. Rust 2021.
- **The binary is git.** `src/main.rs` provides the C `main` that git's own `wmain`
  calls, then runs `ffi::init_git` + `ffi::cmd_main` (`src/ffi.rs`). `build.rs` compiles
  git's C from the `vendor/git` submodule. **It links only on `x86_64-pc-windows-gnu`** —
  `cargo build` on the default msvc host fails at link with unresolved `init_git`/
  `cmd_main`. The *library* builds anywhere.
- **Three things run outside git's dispatcher**, all in `src/main.rs::run`:
  1. `gitc scan` / `gitc scrub` — handled in Rust, never reach git.
  2. Pre/post stages (`src/stage.rs`) — the policy gate and audit writer.
  3. One passthrough default: bare `git init` → `git init --initial-branch=main`.
- **Modules** (`src/*.rs`): `gitobj`/`gitpack`/`gitwalk`/`gitindex` (pure-Rust readers for
  git's on-disk formats), `filterrepo/` (clean-room `git filter-repo` port), `scan`/
  `scancmd`, `scrubcmd`, `gates` + `policy` (enforcement), `runner` + `store` (audit),
  `stage`, `repostate`, `backend`, `provision`, `gitwin`, `installer/`, `selfupdate`,
  `settings`, `paths`, `redact`, `enrich`, `router`, `shortcut`, `cmdtree`, `doctor`,
  `auditcmd`, `appmain`, `shell`, `backendupdate`, `origin`, `uuidv7`, `gitargs`.
- **Vendored workspace:** `crates/betterleaks/` — a 17-crate port of the gitleaks
  detection engine. It is a **separate cargo workspace** referenced by path, so root
  `cargo test` and `cargo llvm-cov` do **not** reach it.
- **Features (all off by default):** `scan`, `scrub` (implies `scan`), `app` (the ported
  application layer; implies both). A bare `cargo build` compiles only the git readers.
- **Audit storage:** bundled SQLite (`rusqlite`, WAL) with a per-row hash chain
  (`gitc audit --verify`), under `%LOCALAPPDATA%\gitc\audit\`.

## Build / test / lint

There is no task runner — use cargo directly. Set `CARGO_TARGET_DIR` outside the repo if
another process may be building concurrently (lock contention reads as a build failure).

```bash
cargo test --features app --lib          # the suite (331 tests)
cargo clippy --features app --all-targets
cargo build --release --target x86_64-pc-windows-gnu   # the ONLY target the binary links on
cargo llvm-cov --lib --features scrub --summary-only   # coverage (root crate only)
```

Building the binary additionally needs git's C objects built once from `vendor/git` in an
msys2 UCRT64 shell — see `README.md` / `REQUIREMENTS.md`. `cargo-tarpaulin` does not work
on Windows; use `cargo-llvm-cov`.

## Code style

Idiomatic Rust; match the surrounding module's density and naming. Project-specific:

- **This is a faithful port.** Where a module mirrors a Go original, keep the structure
  and name the deviation in a doc comment rather than silently improving it. Flag, don't
  fake — the existing "Documented deviations" sections are the pattern.
- All ordinary git behaviour comes from linked git — never reimplement plumbing or
  porcelain. `filterrepo/` and the pure-Rust object readers are the deliberate exceptions.
- The **self-invocation guard** matters more here than it did in Go: gitc *is* git, so
  anything that shells out to git re-enters this binary. `stage::GUARD_ENV` breaks that
  recursion; any change to backend resolution or stage spawning needs a test proving it
  cannot recurse.
- **Audit writes never block or fail the underlying git command** — a write failure
  degrades to a stderr warning (availability over audit completeness).
- The enforcement gate runs at a single choke point per world: `runner::exec_and_audit`
  (proxy) and `stage::GateStage` (FFI binary). Do not add a git-exec path that bypasses it.

## Security (this is the product)

- **Enforcement is the goal, not just detection.** `policy.json` resolves from a machine
  dir (`%ProgramData%\gitc` / `/etc/gitc`), not the agent-relocatable user env, and drives
  the secret gate, the remote allowlist, and any external pre/post stage commands. Gates
  **fail closed** — malformed, unresolvable or ambiguous state blocks rather than allows.
  A pre-stage that cannot run blocks.
- **Never trust a repo-writable file for a decision.** `.git/gitc/state.json`
  (`src/repostate.rs`) is advisory *only*: anyone who can write the repo can edit it, so
  no gate reads it. The authoritative trail is the machine-scoped audit DB.
- **No secret value is ever persisted.** `redact` masks URL userinfo and Authorization
  tokens in stored argv and env; leak records store truncated-SHA-256 fingerprints and
  have no field capable of holding a secret. Keep it that way by construction, not by
  review.
- Downloads (git backend, self-update) and repo URLs are **sha256-pinned and verified**;
  verification fails closed.
- When changing a gate, a remote/secret classification, or the audit record, add a
  regression test — non-bypassability is the whole value proposition.

## Known state (read before trusting a doc)

- `docs/ARCHITECTURE.md` and all 7 ADRs still describe the Go implementation.
- `crates/betterleaks/BUGS.md` **BUG-001 is OPEN and CRITICAL**: the port silently misses
  335 secrets the Go original detects (a NUL binary-heuristic in
  `crates/betterleaks/sources/src/file.rs:346`, replicated at four more sites). A test at
  `sources/src/file_tests.rs:35-47` currently asserts the buggy behaviour is correct.
- **There is no CI.** `.github/` held Go-only workflows and was removed with the Go tree;
  a Rust gate has to be written from scratch.
- A full audit lives in `docs/.project/harden/` (gitignored, local-only).

## PR / commit conventions

Conventional-commit messages (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`).
No AI attribution in trailers. Work on a branch → PR → squash-merge on protected `main`.
Follow the global git-commit rules in the user's `~/.claude/AGENTS.md`.
