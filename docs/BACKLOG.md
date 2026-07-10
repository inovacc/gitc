# Backlog

## Secret detection & history remediation

Context: gitc logs git argv/env raw and unredacted by design, so secrets can
land in a repo's history and in the audit DB. The tools catalogued in
[REFERENCES.md](REFERENCES.md) form the detect → remove toolchain. Candidate
integrations:

- **`git scan` — gitleaks integration — DONE (working-tree scan).** Wraps
  gitleaks as an external Go dependency (`github.com/zricethezav/gitleaks/v8`,
  embedded default ruleset) via `internal/scan`; `git scan [path]` scans
  the working tree, prints redacted findings, and exits 1 if any are found (CI
  gate). Detection only — never mutates. Follow-up: the `--audit` flag to scan
  the audit DB's captured argv/env is still a stub (working-tree scan shipped
  first).
- **Pre-flight secret gate (opt-in).** Optionally run a gitleaks check before
  passing through commit/push, warning (not blocking by default) when a secret
  is about to be committed or would be recorded raw in the audit log.
- **History remediation — DONE (`git scrub`).** Native, single-binary
  history rewriting via the clean-room `internal/filterrepo` port of
  git-filter-repo (ADR 0003): purge paths (`--path`/`--invert-paths`) and redact
  text (`--replace-text`) across all history. Plan-by-default; `--force` applies,
  `--dry-run` previews. Supersedes the earlier "print the upstream commands"
  idea — gitc now does the rewrite itself, safely guarded.
- **Audit-DB redaction/scrub tool (separate from the CLI).** Since the CLI is
  append-only for forensic integrity, provide an out-of-band admin utility to
  scrub known-leaked secrets from historical audit rows, mirroring the
  filter-repo/BFG model for the audit store.

## Hardening — deferred (low leverage)

From the hardening audit (`docs/analysis/HARDENING-RUNBOOK.md`), consciously
deferred as low value / high churn:

- **H-12 — thread `context` through `store.Insert`/`Tail`.** Audit writes are
  tiny local SQLite ops already serialized under `SetMaxOpenConns(1)`; caller
  cancellation adds little. Low priority.
- **H-13 — propagate `context` into `filterrepo` `gitOutput`/`gitExitCode` and
  the exported helpers.** High signature churn across the parity-ported API for
  fast, foreground scrub git calls. Partly mitigated: `main` now threads a
  signal-cancelled ctx into `filterrepo.Run` (H-14).
- **Audit-DB Windows ACL hardening** (from H-10). The DB already lives under the
  user-scoped `%LOCALAPPDATA%\gitc`; explicit owner-only ACLs are a marginal add.
- **Network retry for `internal/gitwin`** downloads (H-11 covered `selfupdate`
  only). MinGit zip streaming would need range-resume to retry correctly.

## Other

- Vendored git-from-source backend: fetch `third_party/git` submodule and run
  `task git:build` (needs a C toolchain). System-git fallback works meanwhile.
- git2go/libgit2 enrichment backend as an alternative to the exec-parse
  enricher (optional acceleration; interface seam already exists).

## Deprecations & security follow-ups

- **Per-user `policy.json` location — DEPRECATED (removal 2026-09-01).** Enforcement
  policy now resolves from the machine dir (`%ProgramData%\gitc\policy.json` /
  `/etc/gitc/policy.json`) first, since the per-user `%LOCALAPPDATA%`/`XDG_DATA_HOME`
  path is agent-relocatable (SEC-2/H-27). The per-user path still works as a
  fallback and logs a deprecation warning; migrate policies to the machine dir.
  An `ENFORCE` marker in the machine dir makes a missing policy fail closed.
- **Record the resolved policy path in the audit record (SEC-2 follow-up).**
  `resolvePolicy` already returns the path it used; persisting it per audit row so
  a policy relocation is forensically visible needs a store schema migration
  (new `resolved_policy_path` column) + runner plumbing. Deferred from H-27.

- **Configured (pre-set) git alias resolution (SEC-6 residual).** H-30 blocks
  command-line `-c alias.<name>=<gated-verb>` injection. A pre-configured alias
  (`git config alias.p push` then `git p`) still evades gate classification.
  Resolving configured aliases via `git config --get alias.<sub>` needs
  built-in-shadow awareness (git ignores aliases named like a built-in), else it
  false-positives on a benign `alias.status`. Deferred.

- **git-svn / bundle / fast-export exfil surfaces (SEC-5 residual).** H-31 added
  send-pack + http-push to the remote allowlist. `git svn dcommit` targets a
  config-based svn-remote (no positional URL) and `git bundle create <file>` /
  `git fast-export` exfil to a LOCAL file — neither fits a host allowlist. Gating
  them needs a separate "local exfil / svn-remote" policy dimension. Deferred.
