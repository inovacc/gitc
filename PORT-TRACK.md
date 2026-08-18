# PORT-TRACK — Go → Rust (gitc)

Ledger for the faithful 1:1, test-first port of the Go `gitc` implementation
(`go-main`, `5685cad`) to Rust. One line per module. Resume at the first module not
marked `verified`. Trust this ledger + `git log` over memory.

## Already present (independent equivalent ports — reuse, not re-port)

- `filterrepo` / `gitargs` / `scan` / `scancmd` / `scrubcmd` / betterleaks `detect`:
  ported from upstream (git-filter-repo, gitleaks), behaviorally equivalent to the
  Go peers. Provenance differs from go-main; drift-tracked against upstream, not here.

## App layer (ported from go-main, behind `--features app`)

| Module | State | Tests | Deps added | Parity |
|---|---|---|---|---|
| `uuidv7` | verified | 2 | `getrandom` | PASS (test-parity; conductor-run) |

## Dependencies added

- `getrandom` 0.2 (feature `app`) — OS CSPRNG for UUIDv7; Go used `crypto/rand`,
  Rust std has no secure RNG. Alternative considered: platform FFI (BCrypt / urandom)
  — rejected as error-prone. Logged.

## Deviations / gaps

- `uuidv7`: Go test used `regexp`; ported as an explicit canonical-format check to
  avoid a test-only regex dep — same contract, no behavior change.

## Pending (from the PORT-PLAN, dependency order — filled by the analyst)

_root: main.go, shell.go, gates.go, backendupdate.go, tools.go, detached_*.go_
_internal: auditcmd, backend, cmdtree, doctor, enrich, gitwin, installer, origin,
paths, policy, provision, redact, router, runner, selfupdate, settings, shortcut, store_
