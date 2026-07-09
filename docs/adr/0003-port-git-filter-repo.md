# 0003 — Port git-filter-repo (subset) from Python to Go

- **Status:** Accepted — subset fully delivered (Phases 1–4)
- **Date:** 2026-07-09
- **Deciders:** dyammarcano
- **Related:** [docs/REFERENCES.md](../REFERENCES.md), [docs/BACKLOG.md](../BACKLOG.md), [0002 — integrate gitleaks](0002-internalize-gitleaks.md), [.port-track.json](../../internal/filterrepo/.port-track.json)

## Implementation status (2026-07-09) — DELIVERED

The full subset (path removal + text replacement) is clean-room ported and
wired, produced via `/dep:porting` (port-mapper → fanned-out port-porter fleet →
verify). Package `internal/filterrepo/` — 14 units, ~3,690 LOC incl. tests —
reimplemented from git-filter-repo (MIT); no source copied. GPL2 test harness not
ported.

- **Phase 1 — codec** (`bytesutil`, `pathquoting`, `idmap`, `records`, `parser`):
  byte-level round-trip parity vs real `git fast-export`/`fast-import` (commit
  count + tree hashes; binary/NUL blobs, quoted paths).
- **Phase 2 — path removal** (`pathspec`, `pathfilter`, `commitfilter`): path
  select/rename/invert + prune-empty (auto/always/never) with parent remap.
- **Phase 3 — text replacement** (`replacetext`, `blobfilter`): literal/regex/
  glob rules, binary-skip.
- **Phase 4 — orchestration** (`gitutils`, `sanity`, `cleanup`, `pipeline`) +
  the `git scrub` command (plan-by-default; `--force` applies; `--dry-run`
  previews). The rewrite execs the resolved real git, never the gitc shim.

**Verified:** `go build`/`vet`/`gofmt` clean; end-to-end tests on real git purge
a path from all history (`git fsck` clean, other history intact) and redact a
secret across all blobs. Per-unit status + deviations in
[`internal/filterrepo/.port-track.json`](../../internal/filterrepo/.port-track.json).

**Known limitations (recorded, not blocking):** prune emptiness is *structural*
(no live-tree comparison); genuine merges are never pruned (no full
AncestryGraph — minimal parent-remap used); regexes are RE2 (backrefs/lookaround
in patterns error at construction; `--replace-text` regex replacement is
literal); niche sanity checks (case-fold ref collisions, stash/unpushed/
multi-worktree) not ported. See `.port-track.json` for the full list.

## Context

The requested "internalize" of `github.com/newren/git-filter-repo` is **not** a
Go dependency internalization: git-filter-repo is a single ~5,000-line **Python**
module (`git_filter_repo.py`), not a Go module. Consuming its capability in gitc
means a **clean-room port** of the behavior we need, not a clone-and-vendor.

This is the *removal* half of gitc's secret-mitigation story (the `git scrub`
guidance item in the backlog): when a secret was committed to a repo gitc
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

- `git scrub --path <path>` — remove a path from all history.
- `git scrub --replace-text <file>` — redact matched strings.
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
5. **Phase 5 — command surface:** `git scrub ...`, audited like any other
   invocation; docs in REFERENCES.md.

Each phase is independently testable and shippable.

## Consequences

- gitc gains native, single-binary history-scrubbing for the common
  secret-removal case, complementing gitleaks detection (0002).
- Full git-filter-repo parity is explicitly not a goal; users needing exotic
  rewrites are still pointed to upstream git-filter-repo / BFG (REFERENCES.md).
