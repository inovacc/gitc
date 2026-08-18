# PORT-TRACK — Go → Rust (gitc)

Ledger for the faithful 1:1, test-first port of the Go `gitc` implementation
(`go-main`, `5685cad`) to Rust. One line per module. Resume at the first module not
marked `verified`. Trust this ledger + `git log` over memory.

## Already present (independent equivalent ports — reuse, not re-port)

- `filterrepo` / `gitargs` / `scan` / `scancmd` / `scrubcmd` / betterleaks `detect`:
  ported from upstream (git-filter-repo, gitleaks), behaviorally equivalent to the
  Go peers. Provenance differs from go-main; drift-tracked against upstream, not here.

## App layer (ported from go-main, behind `--features app`)

Wave 0 (leaves). Wave order: paths→redact→uuidv7→shortcut→origin→enrich→backend→
policy→settings→store→installer/shim. Then W1 cmdtree/router/doctor/selfupdate/
gitwin/installer/runner/auditcmd/gates, W2 provision, W3 shell/backendupdate, W4 main.

| Module | State | Tests | Deps added | Parity |
|---|---|---|---|---|
| `uuidv7` | verified | 2 | `getrandom` | PASS (test-parity; conductor-run) |
| `paths` | verified | 4 | — (std) | PASS |
| `redact` | verified | 2 | `regex` | PASS |
| `shortcut` | verified | 3 | — (std) | PASS |
| `origin` | verified | 4 | `sha2` | PASS |
| `policy` | verified | 10 | `serde`, `serde_json` | PASS (Go `go test` baseline + ported tests both green) |
| `gitargs::subcommand_index` | verified | 1 | — | PASS (dependency gap filled for policy/router) |
| `installer/shim` | verified | 1 | — (assets) | PASS (embedded PE launchers; MZ magic) |
| `enrich` | verified | 4 | — (std + serde) | PASS (Go baseline green) |
| `backend` | verified | 5 | — (std) | PASS (Go baseline green) |
| `settings` | verified | 7 | `time` | PASS (Go baseline green) |
| `cmdtree` | verified | 3 | — (serde) | PASS (Go baseline green) |
| `router` | verified | 24 | — (std) | PASS (Go baseline green) |

| `selfupdate` | verified | 8 | — (HttpClient trait; ureq deferred) | PASS (Go baseline green) |
| `store` | verified | 10 | `rusqlite` (bundled) | PASS (hash-chain byte-exact; Go baseline green) |

| `doctor` | verified | 4 | — (std) | PASS (Go baseline green) |
| `gitwin` | verified | 23 | `zip`,`tar`,`bzip2` | PASS (Go baseline green; zig cc cross-compiles the C) |
| `installer` | verified | 7 | — (std) | PASS (Go baseline green; Windows shims/PATH) |
| `runner` | verified | 9 | — (std) | PASS (Go baseline green; gate fail-closed + env redaction) |
| `gates` | verified | 19 | — (reuses detect via scan) | PASS (Go baseline green; fail-closed enforcement) |

| `provision` | verified | 6 | — (std) | PASS (Go baseline green) |
| `auditcmd` | verified | 3 | `ratatui`,`crossterm` | PASS (Go baseline green; pure Model/Update) |

**Progress: 21 / 24 port-units verified.** Waves 0–2 COMPLETE. Remaining: `shell`,
`backendupdate`, `main` (root orchestration). Full app suite = 189 tests. Go
`go test` = parity baseline; all app modules cross-compile under
`cargo zigbuild --target x86_64-pc-windows-gnu`.

## Dependencies added

- `getrandom` 0.2 (feature `app`) — OS CSPRNG for UUIDv7; Go used `crypto/rand`,
  Rust std has no secure RNG. Alternative: platform FFI — rejected as error-prone.
- `regex` 1 (already an optional dep; added to `app`) — Go `regexp` (redact URL/auth
  masking). std has no regex.
- `sha2` 0.10 (feature `app`) — Go `crypto/sha256` (origin URL pins; audit hash-chain
  to come). Crypto is not in std.

## Deviations / gaps

- `uuidv7`: Go test used `regexp`; ported as an explicit canonical-format check to
  avoid a test-only regex dep — same contract, no behavior change.

## Pending (from the PORT-PLAN, dependency order — filled by the analyst)

_root: main.go, shell.go, gates.go, backendupdate.go, tools.go, detached_*.go_
_internal: auditcmd, backend, cmdtree, doctor, enrich, gitwin, installer, origin,
paths, policy, provision, redact, router, runner, selfupdate, settings, shortcut, store_
