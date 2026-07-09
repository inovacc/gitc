# Roadmap
<!-- rev:001 -->

gitc's mission: a **non-bypassable, forensically-audited gate for AI coding
agents** — stop agents leaking secrets/sensitive data through git (see the
README "Purpose" section).

## Shipped

- **Transparent git shadow** — installs as `git` (PATH-precedence shim); the
  agent's every git call flows through gitc and can't be routed around.
- **Forensic audit log** — append-only SQLite record of every invocation
  (args, env subset, cwd, backend, exit, duration, repo-state enrichment).
- **Secret detection** — `git scan` (embedded gitleaks ruleset); exit 1 on
  findings (CI-usable).
- **History remediation** — `git scrub` (clean-room git-filter-repo port):
  purge paths / redact text across all history, plan-by-default.
- **Self-provisioned git backend** — `git fetch-git` downloads a prebuilt,
  sha256-pinned MinGit from git-for-windows (ADR 0004); no build toolchain.
- **Release** — goreleaser publishes download binaries for 6 targets.

## Test coverage

Total **43.9%** (`go test -cover ./...`).

| Package | % | | Package | % |
|---------|---|---|---------|---|
| router | 100.0 | | scan | 9.8 |
| policy | 96.0 | | installer | 0.0 |
| store | 74.4 | | paths | 0.0 |
| enrich | 62.2 | | runner | 0.0 |
| filterrepo | 62.0 | | shortcut | 0.0 |
| backend | 48.1 | | main | 0.0 |
| gitwin | 15.7 | | | |

Raising the 0%-covered packages toward a **≥ 70%** total is tracked in
[IMPLEMENTATION_TASKS.md](IMPLEMENTATION_TASKS.md) (TST-1..6).

## Next — the hard gates (leak prevention)

The audit + scan + scrub are the building blocks; the enforcement is the goal.

- [x] **Pre-push / pre-commit secret gate** — `enforceGates` runs `scan` inline
      before a passthrough `commit`/`push` and **blocks** (non-zero, refuses)
      when secrets are found; the command never reaches git. (policy.json opt-in)
- [x] **Remote allow-listing** — blocks `push`/`fetch`/`clone`/`pull`/`remote`
      to a URL whose host/owner is not on the approved list.
- [x] **Policy config** — `policy.json` (`internal/policy`): a machine/org
      enforcement policy (secret gate, remote allowlist) gitc reads read-only and
      a git flag can't override. Absent ⇒ no enforcement (opt-in).
- [ ] **Audit-log secret scan** (`git scan --audit`) — scan captured argv/env in
      the audit DB for secrets recorded raw.
- [ ] **Tamper-evident audit log** — hash-chained / append-only-enforced records.

## Later

- [ ] Fully-featured vendored git build (HTTPS/curl) on supported toolchains.
- [ ] git2go/libgit2 enrichment backend (optional).
- [x] Scan: skip vendored/dependency dirs by default (.git/.svn/.hg/node_modules/vendor/third_party).
- [ ] Meta commands on the audited path.
