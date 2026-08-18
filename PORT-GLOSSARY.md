# PORT-GLOSSARY — Go → Rust (gitc)

Shared type-name map + naming/error-style decisions every module porter reads and
appends. Keeps modules ported in independent contexts coherent (same idioms, same
cross-module types). Source: the Go implementation on `go-main` (`5685cad`).
Target: this Rust project.

## Cross-language conventions (apply everywhere)

| Concern | Decision |
|---|---|
| Go `error` | `Result<T, E>` with a per-module error enum; propagate with `?`. Public errors implement `std::error::Error` + `Display`. No `thiserror` unless a module's error set is large enough to justify (log it). |
| Go `(T, error)` | `Result<T, E>`; non-error multi-return → a tuple or a named struct. |
| Go `nil` / nil-able pointer | `Option<T>` / `Option<Box<T>>`. Never a sentinel. |
| Go zero value | `Default::default()` or `Option::None` — never assume implicit zeroing. |
| Go `defer` | RAII (`Drop`) or a scope guard; LIFO order preserved. |
| goroutine + channel | `std::thread` + `std::sync::mpsc` (crossbeam only if `select`-heavy, logged). |
| `context.Context` | explicit params; cancellation via an `Arc<AtomicBool>` / token, not a Tokio facsimile. |
| package-global mutable state | `OnceLock` / passed state — no `static mut`. |
| naming | Go `Capitalized`→`pub`; Go `MixedCaps`→Rust `snake_case` fns, `CamelCase` types; acronyms lowercased in snake_case (`OID`→`oid`). |
| Go `init()` | `OnceLock` or an explicit init call — no implicit module init. |

## Sanctioned dependencies (std-first; add only when forced, log here)

| Capability | Crate | Why std can't |
|---|---|---|
| _(to be filled per the PORT-PLAN — candidates below)_ | | |
| SQLite audit store (internal/store) | `rusqlite` (candidate) | std has no SQL engine |
| JSON config/records | `serde` + `serde_json` (candidate) | std has no JSON |
| UUIDv7 (internal/uuidv7) | hand-port preferred (small, self-contained) | — |
| HTTP download (gitwin/backend/selfupdate) | `ureq` or `reqwest` (candidate) | std has no HTTP client |
| tar/bz2 extraction (gitwin) | crate (candidate) | std has no bz2 |

## Already-present Rust modules (independent equivalent ports — reuse, don't re-port)

These were ported from the upstream sources (git-filter-repo, gitleaks) rather than
from this Go tree, but are behaviorally equivalent and are the dependency other
modules build on. Use their EXACT ported types.

| Rust module | Role | Go peer (equivalent) |
|---|---|---|
| `src/filterrepo/**` | history-rewrite pipeline | `internal/filterrepo` |
| `src/gitargs.rs` | git argv parsing | `internal/gitargs` |
| `src/scan.rs` | secret scan over objects | `internal/scan` |
| `src/scancmd.rs` | `gitc scan` surface | `internal/scancmd` |
| `src/scrubcmd.rs` | `gitc scrub` surface | `internal/scrubcmd` |
| `crates/betterleaks/**` | detection engine (gitleaks port) | (embedded gitleaks) |
| `src/git{index,obj,pack,walk}.rs` | pure-Rust git object readers | (Rust-only; no Go peer) |

## Per-module type identities (append as modules are ported)

_(module → key public types, so dependents use the same names)_
