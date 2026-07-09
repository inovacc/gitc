# 0002 — Integrate gitleaks secret detection

- **Status:** Proposed
- **Date:** 2026-07-09
- **Deciders:** dyammarcano
- **Related:** [docs/REFERENCES.md](../REFERENCES.md), [docs/BACKLOG.md](../BACKLOG.md), [0003 — port git-filter-repo](0003-port-git-filter-repo.md)

## Context

gitc logs git argv and a git-relevant environment subset **raw and unredacted**
(see the design spec), so secrets can land in a repo's history and in the audit
DB. The backlog proposes a `gitc gitc scan` command for the *detection* half of
the mitigation story. gitleaks is the de-facto tool for that and is written in
Go, so it is a candidate for `/dep:internalize`.

## Decision drivers

- Detection rules must stay **current** — new secret patterns ship upstream
  regularly. Anything that freezes the ruleset degrades over time.
- gitc is a small, focused binary; we do not want to absorb gitleaks' 10k-line
  CLI or a large maintenance surface.
- License must be compatible with gitc (BSD-3-Clause).

## 5.1 Summary

| Field | Value |
|-------|-------|
| Module | `github.com/zricethezav/gitleaks/v8` (repo `github.com/gitleaks/gitleaks`) |
| Ref inspected | `4c232b5` (shallow clone) |
| Total Go files (non-test) | ~15,449 LOC |
| Reusable library core | `detect` 2,483 · `config` 818 · `report` 618 · `sources` 1,154 · `regexp` 30 LOC |
| CLI (excluded) | `cmd` 10,267 LOC |
| `internal/` packages | none (all packages are importable) |
| License | MIT (compatible with BSD-3-Clause) |
| Notable deps | `wasilibs/go-re2` (regex engine, pulls a wazero WASM runtime), `mholt/archives`, `BobuSumisu/aho-corasick`, `Masterminds/sprig`, `spf13/{cobra,viper}`, `rs/zerolog` |

## 5.2 What we actually need

For `gitc gitc scan`, the required surface is the **detection engine + rule
config + findings**:

- `config` — load the default ruleset (`config.DefaultConfig` / embedded
  `gitleaks.toml`) and user overrides.
- `detect` — `detect.NewDetector(cfg)`, then `DetectString` / `DetectFiles`
  (working tree / arbitrary string) → `[]report.Finding`.
- `report` — the `Finding` type consumed above.
- `sources` — only if we scan git history rather than the working tree.

`cmd` (the CLI) is **not** needed.

## 5.3 Recommended strategy — Keep external (add as a dependency), NOT vendor

Per the internalize decision matrix, the right call here is **Keep external**:

- **Rule freshness:** vendoring freezes the secret-detection ruleset. Detection
  quality then rots unless we manually re-sync — exactly the failure mode we
  want to avoid for a security feature. As an external dep, `go get -u` refreshes
  rules.
- **Transitive weight:** the detection core drags in `go-re2` (+ wazero),
  `mholt/archives`, `aho-corasick`, and sprig. Copying those too is a large,
  low-value maintenance surface; copying only gitleaks' own packages and keeping
  those as deps gains nothing over importing gitleaks directly.
- **License:** MIT allows either approach; it is not the deciding factor.

Vendoring is only justified if gitc must ship with **zero external modules** —
not a current requirement.

### Fallback (only if zero-external-deps becomes a hard rule): Subset copy

Copy `config`, `detect`, `report`, `sources`, `regexp` into
`pkg/gitleaks/` and rewrite imports to `github.com/dyammarcano/gitc/pkg/gitleaks/*`.
This still requires `go-re2`, `aho-corasick`, `sprig`, and `mholt/archives` as
external deps (they are not gitleaks' own code), so the "internalization" is
partial. Track ruleset drift manually via `/dep:update`.

## 5.4 Import rewrite map (fallback subset-copy only)

```
github.com/zricethezav/gitleaks/v8/config  → github.com/dyammarcano/gitc/pkg/gitleaks/config
github.com/zricethezav/gitleaks/v8/detect  → github.com/dyammarcano/gitc/pkg/gitleaks/detect
github.com/zricethezav/gitleaks/v8/report  → github.com/dyammarcano/gitc/pkg/gitleaks/report
github.com/zricethezav/gitleaks/v8/sources → github.com/dyammarcano/gitc/pkg/gitleaks/sources
github.com/zricethezav/gitleaks/v8/regexp  → github.com/dyammarcano/gitc/pkg/gitleaks/regexp
```

## 5.6 Risk assessment

- **License:** MIT ⊂ compatible with BSD-3. Preserve the MIT `LICENSE` and
  copyright if any files are copied.
- **Maintenance:** very actively maintained; rules change often → argues for
  external dependency, against vendoring.
- **Complexity:** `go-re2` can build in pure-Go (wazero WASM) mode — no CGO
  required — but adds binary size. Confirm the pure-Go build tag so gitc stays
  cgo-free.
- **Version freeze risk:** the core reason to NOT internalize.

## 5.8 Execution plan (recommended: external dependency)

1. `go get github.com/zricethezav/gitleaks/v8@latest`.
2. Add `internal/scan`: wrap `config.DefaultConfig` + `detect.NewDetector`,
   exposing `ScanString(s) []Finding` and `ScanDir(path) []Finding`.
3. Add meta command `gitc gitc scan [path]` (detection-only; never mutates)
   that runs the detector over the working tree and/or recent audit-log argv/env,
   printing findings. Wire it in `runMeta`.
4. Confirm the pure-Go `go-re2` build (no CGO); verify `go build`/`vet`/`test`.
5. Optionally add an opt-in pre-flight gate before passthrough `commit`/`push`.

Cleanup: remove `.tmp/gitleaks` when done.

## Consequences

- Adds one direct module dependency and its transitive tree (notably a WASM
  regex runtime), in exchange for always-current secret detection with no
  vendoring maintenance.
- If `zero external deps` later becomes a hard requirement, revisit with the
  subset-copy fallback above.
