# Milestones
<!-- rev:001 -->

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

## v0.3.0 — Hard gates (next)

Turn the audit + scan + scrub building blocks into *enforcement* — the core
leak-prevention mission (see [ROADMAP.md](ROADMAP.md), tasks in
[IMPLEMENTATION_TASKS.md](IMPLEMENTATION_TASKS.md)).

- [ ] Pre-push / pre-commit secret gate — **block** (not warn) on detection.
- [ ] Remote allow-listing — block push/fetch/clone to unapproved hosts.
- [ ] Machine/org policy file the agent can't override.
- [ ] `git scan --audit` — scan the audit DB's captured argv/env.
- [ ] Tamper-evident (hash-chained) audit log.
- [ ] Coverage target: **≥ 70%** (raise the 0%-covered packages: installer,
      paths, runner, shortcut, main).
