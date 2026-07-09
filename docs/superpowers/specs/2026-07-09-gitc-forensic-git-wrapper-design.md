# gitc — Forensic Git Wrapper Design

## Purpose

`gitc` is a Go CLI that sits transparently between the user/shell and the real
`git` binary. It forwards every invocation (args, stdin/stdout/stderr, exit code)
to a real git backend while recording an append-only forensic audit trail of
every command run: what, when, where, by whom, and with what result. It also
bundles a small set of common git shortcuts as first-class subcommands, which
are logged the same way as passthrough commands.

## Non-goals

- Not a git reimplementation. All actual version-control logic is delegated to
  a real git backend (built-from-source binary, optional libgit2 for
  enrichment).
- Not a policy/permission enforcement layer (no blocking of commands) — this
  design is observability/forensics only, not access control.
- No redaction of logged data (explicit user decision — see Security below).

## Architecture

Two backends, different jobs:

1. **git-from-source (exec backend, primary/required)** — `git/git` (upstream,
   https://github.com/git/git) is vendored as a git submodule under
   `third_party/git/`. A Taskfile target (`task git:build`) builds it via its
   normal `make` build (requires a C toolchain — MSYS2/MinGW-w64 on Windows,
   build-essential on Linux, Xcode CLT on macOS) into
   `internal/vendor-build/git/bin/git` (or `git.exe`). This build step runs at
   `gitc` **build/release time**, not at end-user runtime — the shipped
   `gitc`/`git.exe` binary is a plain static Go binary with no cgo dependency
   from this backend. At runtime, `gitc` execs this vendored binary as the
   passthrough backend for all raw git commands. Rationale: satisfies "build
   our own git from source" literally; sidesteps the fact that upstream
   `git/git` has no stable public C API to cgo-link against — its only
   supported integration surface is its compiled executables.

   Fallback: if the vendored build is unavailable at runtime (e.g. a
   from-source build wasn't produced), `gitc` resolves a compatible system
   `git` already on PATH (see self-invocation guard below) and execs that
   instead, still fully logged. This keeps the tool usable before the vendored
   build pipeline is wired up.

2. **libgit2 (cgo backend, additive/optional)** — `github.com/libgit2/libgit2`
   via `git2go` Go bindings, linked via cgo. Used **only** to enrich audit
   records with structured programmatic data (parsed status, diff stat,
   commit/log objects) alongside the raw exec-backend result — it is never
   the passthrough path and never replaces backend 1. If cgo/libgit2 is
   unavailable at build time, this enrichment is silently skipped (structured
   fields stay null); the tool remains fully functional as an exec-only
   forensic wrapper. This is the reason `gitc` requires a C toolchain to
   *build* (not to run) even beyond the git-from-source step.

### Self-invocation guard

`gitc` ships as `git.exe`/`git` in its own directory, which is placed earlier
in `PATH` than any real git install (see Shadowing below). To avoid the
wrapper re-resolving `git` from PATH and execing itself recursively:

- On startup, `gitc` resolves its own absolute executable path
  (`os.Executable()`).
- When searching PATH for a "system git" fallback, it walks `PATH` entries in
  order, skips any candidate whose resolved absolute path equals its own (or
  whose file is byte-identical / same inode as itself), and picks the first
  remaining `git`/`git.exe` match.
- The resolved absolute backend path (vendored build, or discovered system
  git) is cached in `gitc`'s config so subsequent runs don't need to
  re-resolve PATH every invocation.
- If no non-self git binary is found and the vendored build is also missing,
  `gitc` fails fast with a clear error (no silent no-op).

### Shadowing mechanism

Shadowing is PATH-precedence, not file overwrite: `gitc`'s own install
directory (containing `git.exe`) is placed earlier in the user's `PATH` than
any other git install, so shell/tool invocations of `git` resolve to the
wrapper first. No files under an existing Git-for-Windows install are
modified. The installer/setup step (out of scope for this scaffold's generated
code — a follow-up doc) is responsible for PATH ordering.

## Forensic audit log

- **Storage:** SQLite, initialized via `sequa init` (migrations under
  `internal/store/migrations/`). Location: `%LOCALAPPDATA%\gitc\audit\gitc.db`
  (Windows) / `~/.local/share/gitc/audit/gitc.db` (Linux/macOS), configurable
  via `--config`.
- **Fields per invocation:** timestamp (UTC, RFC3339), user (OS username +
  resolved identity if available), cwd, full argv (raw, unredacted), a
  filtered environment subset (documented allowlist of git-relevant vars:
  `GIT_*`, `SSH_AUTH_SOCK`, `PATH`; still logged raw/unfiltered in content —
  "subset" refers to *which* vars are captured, not modification of their
  values), which backend served the call (vendored-build / system-git),
  whether it was passthrough or a built-in shortcut, exit code, wall-clock
  duration, and (when the libgit2 backend is available) a structured JSON
  blob of enrichment data (e.g. files changed, insertion/deletion counts).
- **Write model:** append-only (INSERT only, no UPDATE/DELETE from the CLI
  itself) for forensic integrity.
- **No redaction (explicit decision):** raw args/env/output are logged
  verbatim, including anything a user passes on the command line (e.g.
  embedded credentials in a remote URL, tokens in `-c` config overrides).
  **Caveat documented here and in README:** this means secrets can land in the
  audit DB. Mitigation is left to filesystem-level access control, not the
  application: the DB file should be created with restrictive permissions
  (0600 / owner-only ACL on Windows) and the audit directory should not be
  synced to shared/cloud locations. This is a recorded risk acceptance, not an
  oversight.

## Built-in shortcuts

Starter set, each a first-class Cobra subcommand (not passthrough), each
logged like any other invocation, extensible later via a user config file
(`~/.config/gitc/shortcuts.yaml` or platform equivalent):

- `gitc sync` — fetch + rebase (onto upstream tracking branch) + push.
- `gitc undo` — soft reset of the last commit (keeps changes staged).
- `gitc log-graph` — `git log --graph --oneline --decorate --all` styled view.
- `gitc quick-commit` — `git add -A` + `git commit -m "<msg>"` in one step.

Each shortcut is implemented as a thin composition of calls into the exec
backend (never reimplements git logic), so its underlying git operations are
*also* individually logged, giving full traceability from shortcut invocation
down to the literal git commands it issued.

## Passthrough behavior

Any argv `gitc` doesn't recognize as a built-in shortcut or its own management
commands is treated as a direct git passthrough: forwarded verbatim to the
resolved backend binary via `exec.Command`, with stdin/stdout/stderr wired
through unmodified and the child's exit code propagated as `gitc`'s own exit
code. This must be indistinguishable from calling real git for every git
command not explicitly overridden as a shortcut.

## Error handling

- Backend resolution failure (no vendored build, no non-self system git) →
  fail fast with actionable error message before attempting any exec.
- Audit log write failure → logged to stderr as a warning; the underlying git
  command still executes and its result still returned to the user (forensic
  logging must never block or break normal git usage). This is a deliberate
  availability-over-completeness tradeoff for the audit trail.
- libgit2 enrichment failure → silently degrades to null structured fields;
  never fails the overall invocation.

## Testing

- Unit tests for argv routing (shortcut vs passthrough dispatch).
- Unit tests for self-invocation guard path resolution (mocked PATH/self-exe
  scenarios).
- Integration test that runs `gitc` against a scratch git repo and asserts the
  audit DB gains exactly one row per invocation with correct fields.
- Golden-file test for `log-graph` and other shortcut output shape.

## Toolchain / build requirements (documented, not enforced by generated code)

Building `gitc` from source requires:
- Go toolchain (for `gitc` itself).
- A C toolchain (MSYS2/MinGW-w64 on Windows, gcc/clang elsewhere) — needed for
  (a) building vendored `git/git` and (b) cgo-linking `git2go`/libgit2.
- `git` itself (to fetch the `third_party/git` submodule) and `make`.

This is a build-time requirement for whoever compiles `gitc`; end users of a
prebuilt `gitc` binary need no C toolchain at runtime.

## Project metadata

- **Name:** gitc
- **Module:** `github.com/dyammarcano/gitc` — chosen over the `inovacc`
  umbrella default because this is a personal forensic tool, not part of the
  inovacc scaffolding ecosystem (per the module-crafting guidance: offer the
  author's own account when the project isn't an umbrella tool).
- **Archetype:** cli
- **Layout:** single
- **Toggles:** `--config` on (backend paths, audit DB location, redaction
  policy — even though default is off — and shortcut definitions all need to
  be user-configurable).
- **Integrations:** `--sql sqlite` (audit log store via `sequa`).
- **License:** BSD-3.

## Open follow-ups (tracked, not blocking this scaffold)

- Installer/PATH-ordering mechanism (how `gitc`'s directory gets placed ahead
  of real git in PATH) — separate from the generated CLI code, needs its own
  design.
- `third_party/git` submodule pinning + Taskfile `git:build` target — to be
  authored as an early implementation task, not emitted by the generic
  scaffold.
- git2go/libgit2 cgo wiring — added as a real dependency once the base
  passthrough + audit-log flow is working end-to-end.
