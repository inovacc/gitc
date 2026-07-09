# gitc

> A cli application built on [mantle](https://github.com/inovacc/mantle).

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
