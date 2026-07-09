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

## Other

- Vendored git-from-source backend: fetch `third_party/git` submodule and run
  `task git:build` (needs a C toolchain). System-git fallback works meanwhile.
- git2go/libgit2 enrichment backend as an alternative to the exec-parse
  enricher (optional acceleration; interface seam already exists).
