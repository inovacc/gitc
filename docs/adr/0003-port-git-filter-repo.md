# 0003 — Port git-filter-repo (subset) from Python to Go

- **Status:** Proposed
- **Date:** 2026-07-09
- **Deciders:** dyammarcano
- **Related:** [docs/REFERENCES.md](../REFERENCES.md), [docs/BACKLOG.md](../BACKLOG.md), [0002 — integrate gitleaks](0002-internalize-gitleaks.md)

## Context

The requested "internalize" of `github.com/newren/git-filter-repo` is **not** a
Go dependency internalization: git-filter-repo is a single ~5,000-line **Python**
module (`git_filter_repo.py`), not a Go module. Consuming its capability in gitc
means a **clean-room port** of the behavior we need, not a clone-and-vendor.

This is the *removal* half of gitc's secret-mitigation story (the `gitc gitc
clean` guidance item in the backlog): when a secret was committed to a repo gitc
audited, rewrite history to purge it.

## 5.1 Summary

| Field | Value |
|-------|-------|
| Upstream | `github.com/newren/git-filter-repo` (ref `da90cb2`) |
| Language | Python 3 — single file `git_filter_repo.py` (~4,993 lines) |
| License | MIT (main script; repo also contains a GPL copy — port from the MIT-licensed behavior only) |
| Portability | Not a Go module — clean-room reimplementation required |
| gitc need | A **subset**: remove path(s) from all history; replace secret text across all history |

## 5.2 Why a subset, not a 1:1 port

The full 5k-line tool handles every edge case: commit/blob/tag/reset callbacks,
mailmap, `.git/info/grafts` & replace refs, LFS, reencoding, analysis reports,
`--partial`, incremental reruns, and a Python callback API. gitc needs only two
operations (matching what REFERENCES.md/BACKLOG advertise):

1. **Remove a path from all history** (`--path X --invert-paths` equivalent).
2. **Replace/redact literal secret strings across all history**
   (`--replace-text` equivalent).

Both reduce to the same well-defined mechanism git itself exposes.

## 5.3 Mechanism (how git-filter-repo works, and how the port will)

git-filter-repo drives git's own plumbing:

```
git fast-export --all --signed-tags=strip --tag-of-filtered-object=rewrite ...
   | <transform the fast-export stream>
   | git fast-import --force
```

The port implements a **fast-export stream processor** in Go:

- Spawn `git fast-export` on the target repo, read its stream.
- Parse the stream into records (blob, commit, reset, tag, done). This is a
  line-oriented, length-prefixed `data <n>` format — a few hundred lines of Go.
- Apply filters: drop `M` file-change lines whose path matches (path removal);
  substitute matched byte sequences in blob payloads (text replacement).
- Emit the transformed stream to `git fast-import --force`.
- Post-process: expire reflogs and `git gc` so purged objects are unreachable
  (mirrors filter-repo's cleanup), and refuse to run on a repo with uncommitted
  changes / a non-fresh clone (filter-repo's safety stance).

This is the tractable core; the long tail of filter-repo features is explicitly
out of scope for v1.

## 5.4 Proposed package layout

```
internal/filterrepo/
  stream.go     // fast-export/fast-import record parser + writer
  filter.go     // path-removal and text-replacement transforms
  run.go        // orchestrate export|transform|import + gc/reflog cleanup + safety guards
  filterrepo_test.go
```

Exposed via a guidance-first meta command (destructive — never automatic):

- `gitc gitc clean --path <path>` — remove a path from all history.
- `gitc gitc clean --replace-text <file>` — redact matched strings.
- Default to **print the plan / require an explicit `--force`**, consistent with
  gitc's "guide the operator, don't silently rewrite history" stance.

## 5.6 Risk assessment

- **License:** port from the **MIT** implementation (`COPYING.mit`); do not copy
  the GPL-licensed variant. Clean-room from documented behavior + the MIT source;
  add attribution to git-filter-repo. MIT is compatible with gitc's BSD-3.
- **Correctness/danger:** history rewriting is destructive and irreversible.
  Mitigations: operate only on a repo with a clean working tree; require
  `--force`; recommend a backup/fresh clone first; extensive golden tests
  comparing output to real `git fast-export`/`fast-import`.
- **Scope creep:** the full tool is huge. Freeze v1 at path-removal +
  text-replacement; track further parity as backlog.
- **Alternative considered — shell out to real git-filter-repo / BFG:** simplest,
  but adds a Python or JVM runtime dependency and defeats the single-binary
  goal. The Go port keeps gitc self-contained.

## 5.7 Recommended strategy — Fork & adapt (clean-room subset port)

Reimplement the two needed operations natively in Go via the fast-export stream
mechanism. Do **not** vendor Python; do **not** attempt a full 1:1 port.

## 5.8 Execution plan (phased)

1. **Phase 1 — stream I/O:** implement and test the fast-export record
   parser/writer against real `git fast-export` output (golden fixtures).
2. **Phase 2 — path removal:** drop matching `M`/`D` file ops; re-emit; verify a
   file disappears from all history on a scratch repo.
3. **Phase 3 — text replacement:** substitute literal/`regex` matches in blob
   payloads; verify secrets are redacted across history.
4. **Phase 4 — safety + cleanup:** clean-tree guard, `--force`, reflog expiry +
   `git gc`; refuse unsafe runs.
5. **Phase 5 — command surface:** `gitc gitc clean ...`, audited like any other
   invocation; docs in REFERENCES.md.

Each phase is independently testable and shippable.

## Consequences

- gitc gains native, single-binary history-scrubbing for the common
  secret-removal case, complementing gitleaks detection (0002).
- Full git-filter-repo parity is explicitly not a goal; users needing exotic
  rewrites are still pointed to upstream git-filter-repo / BFG (REFERENCES.md).
