# Milestones
<!-- rev:002 -->

Version milestones for gitc. Coverage figures are total statement coverage at
the time of the milestone (`go test -cover ./...`).

## v0.1.0 — Foundation ✅ (released)

The forensic git proxy and its command surface.

- Transparent git shadow (PATH shim) + self-invocation guard.
- Append-only SQLite forensic audit log with repo-state enrichment.
- `git scan` (gitleaks secret detection) and `git scrub` (clean-room
  git-filter-repo Go port: path removal + text redaction).
- Shortcuts: `sync`, `undo`, `log-graph`, `quick-commit`.
- New repos default to `main`.
- goreleaser release publishing raw download binaries (6 targets).

## v0.2.0 — Self-provisioning + hardening ✅ (released)

- **MinGit backend**: `git fetch-git` downloads a sha256-pinned MinGit from
  git-for-windows (embedded `git_release.json`); build-from-source submodule
  removed (ADR 0004).
- First-class command surface (`git scan`/`scrub`/…; no doubled `gitc gitc`).
- Repositioned as an AI-agent leak-prevention gate; migrated to the **inovacc**
  org (module `github.com/inovacc/gitc`).
- **Strict golangci-lint compliance** (0 findings); dead scaffold code + mantle
  dependency removed.
- **Go 1.26.5** (clears CVE GO-2026-5856); shim self-overwrite fix.
- Coverage: **43.9%**.

## v0.3.0 — Hard gates + managed-update architecture ✅

The audit + scan + scrub building blocks became *enforcement* — the core
leak-prevention mission — alongside a verified self-update architecture.

- **Enforcement gates** (`policy.json`, read-only, agent can't override):
  block-on-secret gate for `commit`/`push`; remote allow-listing for
  `push`/`fetch`/`clone`/`pull`/`remote`.
- **Audit integrity**: tamper-evident hash chain (`git audit --verify`);
  `git scan --audit`; credential redaction in stored argv; compact/`--wide`
  views; help/version no longer logged.
- **Managed git + updates (ADR 0005)**: `settings.json` backend resolution;
  UUIDv7 side-by-side installs with atomic activation + GC; lazy, single-flight,
  detached background updater (verified pinned channel); sha256-pinned upstream
  repo URLs (`internal/origin`); pinned MinGit manifest moved into Go source.
- **Self-management**: `git update` (verified sha256+size self-update),
  `git doctor`, `git cmdtree`.
- **Hardening H-01…H-11, H-14**: supply-chain integrity, bounded timeouts,
  network retry, graceful Ctrl-C, CI race/lint/coverage gate (pinned
  golangci-lint v2.12.2).
- Coverage: **42.9%** (target ≥ 70% carried to v0.4.0).

## v0.4.0 — Depth (next)

- [ ] Coverage **≥ 70%** — `runner`, `installer`, `shortcut`, `main` are thin.
- [ ] Secret-gate severity threshold (warn vs block per finding).
- [ ] Remote allowlist for **named remotes** (resolve `git push origin`).
- [ ] Deferred hardening: context threading (H-12/H-13), `gitwin` download retry.
