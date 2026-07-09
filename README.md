# gitc

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)
![Use](https://img.shields.io/badge/use-internal%20%C2%B7%20corporate-8A2BE2)
![Status](https://img.shields.io/badge/status-WIP-orange)

> A drop-in **`git` for AI agent harnesses.** gitc transparently replaces `git`
> so autonomous AI coding agents can't route around it — giving you a
> **non-bypassable, forensically-audited gate** to stop agents from publishing
> secrets or sensitive corporate data.

## Purpose — a leak-prevention gate for AI agents

gitc exists for one job: **stop AI coding agents from publishing sensitive
information through git, and record everything they do.**

AI agents increasingly run `git` autonomously inside corporate codebases. gitc
installs *as* `git` (a PATH-precedence shim), so an agent's every `git` call
flows through it and can't be bypassed. That makes gitc a single, enforceable
control point where you can:

- **Audit** — an append-only forensic log of every git invocation an agent runs
  (what, when, where, args, environment, result).
- **Detect** — `git scan` flags secrets (gitleaks ruleset) before they leave.
- **Remediate** — `git scrub` purges secrets/paths from history.
- **Gate** *(roadmap)* — hard pre-commit/pre-push gates that **block** an agent
  from committing/pushing detected secrets or reaching unapproved remotes.

Today gitc ships the audit trail + `scan` + `scrub`; the enforcing hard gates
are the active direction (see [docs/ROADMAP.md](docs/ROADMAP.md)). Because the
agent talks to what it believes is `git`, these controls apply without the
agent's cooperation.

## Quickstart

```bash
# 1. Build gitc
task build                       # or: go build -o gitc .

# 2. Install the PATH shim so `git` resolves to gitc (transparent, audited)
gitc gitc install --apply        # Windows: prepends the shim dir to your user PATH
#                                  (omit --apply to just print the PATH step to run)
# then restart your shell

# 3. Use git exactly as before — every invocation is now logged
git status
git commit -m "message"          # forwarded to real git, recorded in the audit log

# 4. gitc's own commands, first-class
git scan                         # detect secrets in the working tree (exit 1 if found)
git audit 20                     # show the last 20 audited invocations
git scrub --path secrets.env --invert-paths --force   # purge a file from all history
git sync                         # fetch + rebase + push
git gitc where                   # resolved git backend + audit DB path
git gitc                         # gitc self-info + full command list
```

Before the shim is installed the binary is named `gitc`, so run its commands as
`gitc <cmd>` (e.g. `gitc gitc install`, `gitc scan`). Once installed on PATH as
`git`, the same commands run as `git <cmd>`. `git scrub` prints a plan and
refuses to touch history unless you pass `--force` (or `--dry-run` to preview).

## Commands

gitc-native commands are first-class (`git <cmd>`); anything not listed here
passes through to real git and is audited. Names that collide with real git
(`clean`, `version`) are reached via the `git gitc <cmd>` namespace instead.

| Command | Description |
|---------|-------------|
| `git scan [path]` | Detect secrets (gitleaks ruleset); exit 1 if any found — CI-usable |
| `git scrub [opts]` | Rewrite history: purge paths / redact text. Plan-by-default; `--force` applies, `--dry-run` previews |
| `git audit [N]` | Show the last N audited invocations (default 20) |
| `git where` | Show the resolved git backend and audit DB path |
| `git install [--apply]` | Install the PATH shim (`--apply` prepends PATH) |
| `git uninstall` | Remove the PATH shim |
| `git fetch-git [--latest\|--list]` | Download a git backend (pinned MinGit by default; sha256-verified) |
| `git sync` | fetch + rebase onto upstream + push |
| `git undo` | Soft-reset the last commit (keeps changes staged) |
| `git log-graph` | Decorated commit graph across all refs |
| `git quick-commit <msg>` | `git add -A` + `git commit -m <msg>` |
| `git gitc` | gitc self-info (version, backend, audit path) + command list |
| `git gitc version` | gitc's own version (real `git version` still passes through) |

`git scrub` flags: `--path <p>` (repeatable), `--invert-paths`, `--replace-text <file>`,
`--prune auto\|always\|never`, `--dry-run`, `--force`.

## Build

```bash
task build      # or: go build ./...
```

## Test

```bash
task test       # fast tests
task test:full  # full suite
```

## Git backend

At runtime gitc execs a real git, resolving the backend in this order:

1. `GITC_GIT_BACKEND` — an explicit path override.
2. A **downloaded git** in the gitc cache (see `fetch-git` below).
3. The first non-self `git` on PATH.

On Windows with no git available, download one:

```bash
git fetch-git            # pinned MinGit from git_release.json — sha256-verified
git fetch-git --latest   # newest git-for-windows release (via the releases API)
git fetch-git --list     # list recent git-for-windows releases
```

`fetch-git` pulls a prebuilt **MinGit** from the
[git-for-windows](https://github.com/git-for-windows/git/releases) releases,
verifies it against the hash pinned in [`git_release.json`](git_release.json)
(embedded in the binary at build time), and unpacks it into
`%LOCALAPPDATA%\gitc\git\<version>\`. `git gitc where` shows which backend
resolved. On Linux/macOS, use the system git (git-for-windows is Windows-only).

## Defaults

- **New repositories default to `main`.** When you run `git init` (proxied
  through gitc) without choosing a branch, gitc injects `--initial-branch=main`
  so new repos start on `main` instead of `master`. An explicit `-b`/
  `--initial-branch` is always respected, and the flag is only added when the
  backend git supports it (>= 2.28).

## Secret handling & remediation

gitc records git argv and a git-relevant environment subset **raw and
unredacted** by design, so secrets can land in the audit DB (protect it with
owner-only filesystem permissions). Detect and remove secrets with the
companion toolchain documented in [docs/REFERENCES.md](docs/REFERENCES.md):

- **Detect:** `git scan [path]` runs the embedded
  [gitleaks](https://github.com/gitleaks/gitleaks) ruleset over the working tree
  and reports redacted findings (exit 1 if any are found, so it works as a CI
  gate). Detection only — it never mutates. Use it alongside `git scrub`,
  which removes detected secrets from history.
- **Remove from history:**
  [git-filter-repo](https://github.com/newren/git-filter-repo)
  ([tutorial](https://andrewlock.net/rewriting-git-history-simply-with-git-filter-repo)),
  [BFG Repo-Cleaner](https://github.com/rtyley/bfg-repo-cleaner)

Further planned integrations (a pre-flight secret gate, an audit-DB scrub tool)
are tracked in [docs/BACKLOG.md](docs/BACKLOG.md).

## Scope & contributing

gitc is an **internal, corporate-focused** tool: its design and roadmap are
driven by enterprise leak-prevention needs for AI-agent harnesses, not
general-purpose git tooling. It is provided **open source (BSD-3-Clause) — you
are welcome to fork and contribute** — but it is tailored for corporate
requirements and offered *as-is*; priorities follow those needs. If a change
fits that mission, PRs are welcome.

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026 inovacc.
