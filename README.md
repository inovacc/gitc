# gitc
<!-- rev:001 -->

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)
![Use](https://img.shields.io/badge/use-internal%20%C2%B7%20corporate-8A2BE2)

> A drop-in **`git` for AI agent harnesses.** gitc transparently replaces `git`
> so autonomous AI coding agents can't route around it — a **non-bypassable,
> forensically-audited gate** that *blocks* agents from publishing secrets or
> reaching unapproved remotes.

## Purpose — a leak-prevention gate for AI agents

gitc exists for one job: **stop AI coding agents from publishing sensitive
information through git, and record everything they do.**

AI agents increasingly run `git` autonomously inside corporate codebases. gitc
installs *as* `git` (a PATH-precedence shim), so an agent's every `git` call
flows through it and can't be bypassed. That makes gitc a single, enforceable
control point where you can:

- **Audit** — an append-only, **tamper-evident** (hash-chained) forensic log of
  every git invocation an agent runs (what, when, where, args, environment,
  result). Credentials in URLs/auth headers are masked in the record.
- **Detect** — `git scan` flags secrets (gitleaks ruleset) in the working tree
  or in the audit log (`--audit`).
- **Remediate** — `git scrub` purges secrets/paths from history.
- **Gate** — enforced pre-commit/pre-push gates that **block** an agent from
  committing/pushing detected secrets or reaching unapproved remotes, driven by
  a machine/org `policy.json` the agent can't override.

Because the agent talks to what it believes is `git`, these controls apply
without its cooperation.

## Quickstart

```bash
# 1. Install the PATH shim so `git` resolves to gitc (transparent, audited).
gitc gitc install --apply        # Windows: prepends the shim dir to your user PATH
#                                  (omit --apply to just print the PATH step to run)
# then restart your shell

# 2. Use git exactly as before — every invocation is logged.
git status
git commit -m "message"          # forwarded to real git, recorded in the audit log

# 3. gitc's own commands, first-class.
git scan                         # detect secrets in the working tree (exit 1 if found)
git audit                        # last invocations (compact); --wide for full; --verify the chain
git doctor                       # health-check the install, backend, PATH shim, audit DB
git update --apply               # self-update from GitHub releases (sha256-verified)
```

On a **fresh Windows machine with no git**, `install` still succeeds and the
first `git` command **auto-provisions** a pinned, sha256-verified git backend —
no manual setup. On Linux/macOS, gitc uses the system git.

Before the shim is installed the binary is named `gitc`, so run its commands as
`gitc gitc <cmd>` (e.g. `gitc gitc install`). Once on PATH as `git`, they run as
`git <cmd>`.

## Commands

gitc-native commands are first-class (`git <cmd>`); anything not listed passes
through to real git and is audited. Names that collide with real git (`clean`,
`version`) are reached via the `git gitc <cmd>` namespace. `git <cmd> --help`
prints a command's usage.

| Command | Description |
|---------|-------------|
| `git scan [path]` | Detect secrets (gitleaks); exit 1 if any found. `--strict` fails on unreadable files; `--audit` scans the audit DB's argv/env |
| `git scrub [opts]` | Rewrite history: purge paths / redact text. Plan-by-default; `--force` applies, `--dry-run` previews |
| `git audit [N]` | Last N invocations, compact. `--wide` full record; `--verify` checks the tamper-evident hash chain |
| `git doctor` | Health-check: shim, PATH shadowing, backend resolves + executes, audit DB |
| `git update [--check\|--apply]` | Self-update from GitHub releases (verifies sha256 + size before swap) |
| `git fetch-git [--latest\|--list]` | Download a git backend (in-code sha256-pinned MinGit by default) |
| `git where` | Resolved git backend + audit DB path |
| `git install [--apply]` / `git uninstall` | Install / remove the PATH shim |
| `git cmdtree [-b\|-c NAME\|--json]` | Show the full command tree |
| `git sync` / `undo` / `log-graph` / `quick-commit <msg>` | Built-in shortcuts |
| `git gitc [version]` | gitc self-info / its own version |

## Enforcement (policy.json)

Drop a `policy.json` in the gitc data dir (`%LOCALAPPDATA%\gitc\policy.json`;
`~/.local/share/gitc/` on XDG) to turn gitc from *detection* into *enforcement*.
gitc reads it **read-only** — a git flag can't override it. An absent file means
no enforcement.

```json
{
  "version": 1,
  "secretGate":      { "enabled": true, "mode": "block" },
  "remoteAllowlist": { "enabled": true, "hosts": ["github.com/inovacc"] }
}
```

- **secretGate** — runs a working-tree secret scan before a `commit`/`push` and
  **refuses** (non-zero, git never runs) on any finding. `mode: "warn"` reports
  but proceeds.
- **remoteAllowlist** — blocks `push`/`fetch`/`clone`/`pull`/`remote` to a host
  (or `host/owner`) not listed. It resolves named and default remotes
  (`git push origin`, bare `git push`) to their real URL, so the allowlist can't
  be sidestepped with a configured remote.

## Git backend

At runtime gitc execs a real git, resolving in this order:

1. `GITC_GIT_BACKEND` — an explicit path override.
2. The **active managed git** recorded in `settings.json`.
3. The first non-self `git` on PATH.
4. On a git-less **Windows** machine: **auto-provision** the pinned MinGit.

Managed installs live under `%LOCALAPPDATA%\gitc\app/<uuidv7>/<version>/`
(side-by-side, immutable); `settings.json` points at the active one, so updates
are an atomic pointer flip with the previous kept for rollback and older
installs GC'd. The pinned MinGit manifest (URL + sha256 per platform) is baked
into the binary as Go source — not a swappable data file — and every download is
sha256-verified. A throttled, single-flight background check keeps the backend
current without blocking commands. `git gitc where` / `git doctor` show what
resolved. On Linux/macOS, gitc uses the system git (git-for-windows is
Windows-only).

## Defaults

- **New repositories default to `main`.** `git init` (proxied through gitc)
  without an explicit branch injects `--initial-branch=main` (when the backend
  git supports it, >= 2.28); an explicit `-b`/`--initial-branch` is respected.

## Secret handling

- The audit log records git argv and a git-relevant environment subset; **URL
  userinfo and Authorization tokens are masked** in the stored record (the
  backend still runs the real args). The DB lives under the user-scoped data
  dir; hash-chaining makes deletion/edits detectable (`git audit --verify`).
- **Detect:** `git scan` (working tree) / `git scan --audit` (the audit DB).
- **Remove from history:** `git scrub` (a clean-room Go port of
  [git-filter-repo](https://github.com/newren/git-filter-repo)).

## Build & test

```bash
task build      # or: go build ./...
task test       # or: go test ./...
```

## Scope & contributing

gitc is an **internal, corporate-focused** tool: design and roadmap follow
enterprise leak-prevention needs for AI-agent harnesses. It is **open source
(BSD-3-Clause) — fork and contribute welcome** — but tailored for corporate
requirements and offered *as-is*. See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026 inovacc.
