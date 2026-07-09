# gitc

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-WIP-orange)

> A **git binary replacement** — a transparent, forensic proxy in front of real
> git. It forwards every command while keeping an append-only audit trail of
> what ran, when, where, and with what result, and adds first-class commands:
> secret scanning (`git scan`), history scrubbing (`git scrub`), and shortcuts
> (`git sync`/`undo`/`log-graph`/`quick-commit`).

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

At runtime gitc execs a real git: it prefers a **vendored git built from
source** (`third_party/git`, pinned at v2.55.0) and falls back to the first
non-self `git` on PATH. Build the vendored backend with:

```bash
task git:submodule   # fetch git/git @ v2.55.0 (once)
task git:build       # compile into internal/vendor-build/git/ (needs a C toolchain)
```

`git gitc where` shows which backend resolved. The default `git:build` flags
target a bare MinGW sysroot and produce a **core git without HTTPS transport**
(no curl) — fine for local/ssh operations and for exercising the pipeline; on a
full toolchain (Git-for-Windows SDK, Linux, macOS) run
`task git:build GIT_MAKE_FLAGS=""` for a fully-featured build.

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

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026 dyammarcano.
