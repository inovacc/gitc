# Implementation Tasks
<!-- rev:001 -->

Granular tasks toward the v0.3.0 hard gates ([MILESTONES.md](MILESTONES.md)) and
coverage. Effort: S ≤ half day · M ≈ 1–2 days · L > 2 days.

## Domain: Enforcement gates

| ID | What | Files | Effort | Depends |
|----|------|-------|--------|---------|
| GATE-1 | Pre-commit/pre-push secret gate: run `scan` inline before passthrough `commit`/`push`; block (non-zero, refuse) on findings unless bypassed | `main.go`, `internal/runner/runner.go`, `internal/policy/` | M | — |
| GATE-2 | Severity threshold + opt-in policy for GATE-1 (warn vs block) | `internal/policy/`, `internal/config` | S | GATE-1 |
| GATE-3 | Remote allow-listing: block `push`/`fetch`/`clone` to hosts not on an approved list | `internal/policy/`, `main.go` | M | POL-1 |

## Domain: Policy

| ID | What | Files | Effort | Depends |
|----|------|-------|--------|---------|
| POL-1 | Machine/org policy file (gates, allowed remotes, redaction) loaded read-only; agent cannot override | `internal/policy/policy.go`, `internal/paths/` | M | — |

## Domain: Audit

| ID | What | Files | Effort | Depends |
|----|------|-------|--------|---------|
| AUD-1 | `git scan --audit`: scan captured argv/env in the audit DB for secrets | `main.go`, `internal/scan/`, `internal/store/query.go` | S | — |
| AUD-2 | Tamper-evident audit log: hash-chain each row (prev-hash column) | `internal/store/store.go`, `migrations/` | M | — |

## Domain: Testing / coverage (target ≥ 70%)

| ID | What | Files | Effort | Depends |
|----|------|-------|--------|---------|
| TST-1 | `internal/paths` unit tests (data/config/cache/shim/managed paths per GOOS) | `internal/paths/paths_test.go` | S | — |
| TST-2 | `internal/shortcut` tests (Steps for each shortcut) | `internal/shortcut/shortcut_test.go` | S | — |
| TST-3 | `internal/runner` tests (passthrough/shortcut dispatch + audit write) with a fake backend | `internal/runner/runner_test.go` | M | — |
| TST-4 | `internal/installer` tests (shim path, sameExe skip, manual instruction) | `internal/installer/installer_test.go` | M | — |
| TST-5 | `internal/gitwin` tests (Unzip zip-slip guard, manifest parse, sha256 verify) — raise from 16% | `internal/gitwin/*_test.go` | M | — |
| TST-6 | `main` routing tests via `run()` (table-driven, fake backend/env) | `main_test.go` | M | — |

## Notes

- Enforcement (GATE-*) is the product's core; POL-1 unblocks GATE-3.
- Coverage 0% packages: installer, paths, runner, shortcut, main → TST-1..6.
- Cross-refs: GATE-1/GATE-3/POL-1/AUD-2 map to the ROADMAP "hard gates" phase.
