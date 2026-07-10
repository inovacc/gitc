# Roadmap
<!-- rev:003 -->

gitc's mission: a **non-bypassable, forensically-audited gate for AI coding
agents** — stop agents leaking secrets/sensitive data through git (see the
README "Purpose" section).

## Shipped

### Core proxy & forensics
- **Transparent git shadow** — installs as `git` (PATH-precedence shim); every
  git call flows through gitc and can't be routed around.
- **Forensic audit log** — append-only SQLite record of every real git
  invocation (help/usage/version are run but not logged). `git audit` is
  compact by default, `--wide` for the full record.
- **Tamper-evident audit chain** — each row folds in the previous row's sha256
  (`prev_hash`/`row_hash`); `git audit --verify` detects a deleted or edited row.
- **Credential redaction** — URL userinfo and Authorization tokens are masked in
  the stored argv (the backend still runs the real args).

### Detection & remediation
- **Secret detection** — `git scan` (embedded gitleaks ruleset); exit 1 on
  findings (CI-usable); skips vendored/dependency dirs; `--strict`; `--audit`
  scans the captured argv/env in the audit DB.
- **History remediation** — `git scrub` (clean-room git-filter-repo port):
  purge paths / redact text across all history, plan-by-default.

### Enforcement gates — the mission
- **Policy config** — `policy.json` (`internal/policy`): a machine/org policy
  gitc reads read-only and a git flag can't override. Absent ⇒ no enforcement.
- **Pre-commit/push secret gate** — blocks (refuses, non-zero) a `commit`/`push`
  when a working-tree scan finds anything; the command never reaches git.
- **Remote allow-listing** — blocks `push`/`fetch`/`clone`/`pull`/`remote` to a
  URL whose host/owner is not on the approved list.

### Managed git backend & updates (ADR 0004 / 0005)
- **Self-provisioned MinGit** — `git fetch-git`; the pinned, sha256-verified
  manifest lives in Go source (`gitwin.Pinned`), not a swappable data file. On a
  git-less Windows machine the first git command **auto-provisions** it (only
  when no system git exists; other platforms use system git).
- **settings.json resolution** — UUIDv7 side-by-side installs under `app/<uuid>/`;
  activation is an atomic pointer flip (`previous ← active`); old installs GC'd.
- **Lazy background updater** — throttled, single-flight, detached check on
  ordinary git usage; only the verified pinned channel is auto-applied.
- **Pinned upstream URLs** — the two repo URLs are sha256-pinned constants
  (`internal/origin`), verified fail-closed before any network call.

### Self-management & DX
- **`git update`** — self-update from GitHub releases, verified (sha256 + size)
  before the in-place swap; background check surfaces a notice.
- **`git doctor`** (health check), **`git cmdtree`**, **`git install`/`uninstall`**.

### Hardening & release
- Hardening runbook **H-01…H-11, H-14** — supply-chain integrity, bounded
  timeouts, network retry, graceful Ctrl-C, and a CI gate (`vet` + `-race` +
  coverage + pinned golangci-lint v2.12.2).
- Go 1.26.5; strict lint (0 findings). goreleaser release for 6 targets.

## Test coverage

Total **45.8%** (`go test -cover ./...`).

| Package | % | | Package | % |
|---------|---|---|---------|---|
| gitargs/redact/router/shortcut | 100.0 | | store | 62.3 |
| uuidv7 | 95.8 | | filterrepo | 61.9 |
| origin | 93.3 | | paths | 61.9 |
| enrich | 76.6 | | installer | 57.9 |
| policy | 76.7 | | gitwin | 48.9 |
| scan | 70.8 | | backend | 48.1 |
| settings | 68.8 | | runner | 46.1 |
| selfupdate | 45.4 | | main | 3.1 |

## Next

- [ ] Raise coverage toward **≥ 70%** (now 45.8%) — the 0%-covered packages are
      cleared; `main` (3%) is the remaining gap, testable via table-driven
      `run()` routing tests with a fake backend.
- [ ] Context threading (H-12 store, H-13 filterrepo) — deferred low-leverage
      hardening ([BACKLOG.md](BACKLOG.md)); makes Ctrl-C cancel scrub's internal
      git calls and audit writes.
- [x] Secret-gate **mode** (`policy.secretGate.mode: block|warn`) — warn reports
      findings and proceeds; block (default) refuses. (Per-severity thresholds
      aren't feasible — gitleaks findings carry no severity.)
- [x] Remote allowlist for **named + default remotes** — resolves `git push
      origin` (and a bare `git push`) to the actual remote URL before vetting,
      closing the URL-only bypass.
- [ ] Context threading (H-12/H-13) and `gitwin` download retry (deferred
      hardening — see [BACKLOG.md](BACKLOG.md)).

## Later

- [ ] Fully-featured vendored git build (HTTPS/curl) on supported toolchains.
- [ ] git2go/libgit2 enrichment backend (optional).
