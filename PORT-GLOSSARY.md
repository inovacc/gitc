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

### `policy` (Go `internal/policy` → `src/policy.rs`, feature `app`)

| Go | Rust |
|---|---|
| `Policy` struct (`Version`,`SecretGate`,`RemoteAllow`) | `pub struct Policy { version: i64, secret_gate: SecretGate, remote_allow: RemoteAllowlist }` — `#[serde(default)]` + field renames `secretGate`/`remoteAllowlist`; `Deserialize` only (Go never marshals). |
| `SecretGate` (`Enabled`,`Commands`,`Mode`) | `pub struct SecretGate { enabled: bool, commands: Vec<String>, mode: String }`; `blocks()` = `mode != "warn"`. |
| `RemoteAllowlist` (`Enabled`,`Hosts`) | `pub struct RemoteAllowlist { enabled: bool, hosts: Vec<String> }`. |
| `LoadPolicy(path) (Policy, error)` | `pub fn load_policy(path: &Path) -> Result<Policy, policy::Error>`; missing file → `Ok(Policy::default())`. `Error::{Io, Parse{path,source}}` — `Parse` Display `parse policy <path>: <err>`. |
| `p.SecretGateApplies(args)` | `Policy::secret_gate_applies(&self, args: &[String]) -> bool` |
| `p.RemoteRefs(args) ([]string, bool)` | `Policy::remote_refs(&self, args: &[String]) -> (Vec<String>, bool)` — `(refs, uses_default)`; Go `nil` → empty `Vec`. |
| `p.RemoteAllowed(remote)` | `Policy::remote_allowed(&self, remote: &str) -> bool` |
| `IsRemoteURL(s)` | `pub fn is_remote_url(s: &str) -> bool` |
| `InitNeedsBranch(args) (int, bool)` | `pub fn init_needs_branch(args: &[String]) -> Option<usize>` (Go's `ok=false` → `None`). |
| `InjectInitialBranch(args, idx, branch)` | `pub fn inject_initial_branch(args: &[String], init_idx: usize, branch: &str) -> Vec<String>` |

### `backend` (Go `internal/backend` → `src/backend.rs`, feature `app`)

| Go | Rust |
|---|---|
| `Kind` (`KindManaged`/`KindSystem`, string) | `pub enum Kind { Managed, System }`; `as_str()`/`Display` → `"managed"`/`"system"`. |
| `ErrNoBackend` | `pub enum Error { NoBackend, Exec(std::io::Error) }`; `NoBackend` Display = verbatim Go message. |
| `Backend` struct (`Kind`,`Path`) | `pub struct Backend { kind: Kind, path: PathBuf }`. |
| `Result` (`ExitCode`,`Duration`) | `pub struct RunOutput { exit_code: i32, duration: Duration }` (renamed to not shadow `std::Result`). |
| `Resolve(managedPath, selfPath)` | `pub fn resolve(managed: Option<&Path>, self_path: &Path) -> Result<Backend, Error>`; empty/`None` managed → skip; self-guard skips self. |
| `b.SupportsInitialBranch(ctx)` | `Backend::supports_initial_branch(&self) -> bool` (ctx dropped). |
| `b.Run(ctx, args)` | `Backend::run(&self, args: &[String]) -> Result<RunOutput, Error>`; non-zero exit → `Ok`, spawn failure → `Err(Exec)`. |

Deviations (documented, acceptable): Windows `os.SameFile` inode fallback not reproduced (unstable on stable std) — resolved-path + case-insensitive compare covers the self-guard; `context.Context` dropped (pack rule).

### `gitargs` addition (dependency gap resolved)

| Go | Rust |
|---|---|
| `gitargs.SubcommandIndex(args) int` (`-1` if none) | `crate::gitargs::subcommand_index(argv: &[String]) -> Option<usize>` — scans from `argv[0]` (git args WITHOUT program name), skips leading globals + their values; `--` ends options. Uses a dedicated `SUBCOMMAND_VALUE_GLOBALS` set matching Go `valueGlobals` (NOT the broader `VALUE_OPTS`, which also carries `--attr-source`). |

### `settings` (Go `internal/settings` → `src/settings.rs`, feature `app`)

| Go | Rust |
|---|---|
| `Settings`/`Backend`/`Update` structs | same names; serde `#[serde(default)]`, renames `backendLastCheck`/`gitcLastCheck`, `omitempty`→`skip_serializing_if="String::is_empty"`; `version: i64`. |
| `Default/Load/LoadOrInit/Save` | `settings::default()`, `load(&Path)` (missing→`Error::Io`/`NotFound`), `load_or_init`, `save(&Path,&Settings)` atomic temp+rename. |
| `Update.IntervalDuration/DueSince` | `Update::interval_duration()->Duration`, `Update::due_since(&self,last:&str,now: time::OffsetDateTime)->bool`. |
| `WithLock/Mutate/acquireLock` | `with_lock`, `mutate`; advisory lockfile via `create_new` + Drop-release (10s stale / 5s timeout / 2ms spin). |
| `time` (Duration string + RFC3339) | Go duration-string subset hand-ported (`parse_go_duration`/`format_go_duration`); RFC3339 via the `time` crate. |

### `cmdtree` (Go `internal/cmdtree` → `src/cmdtree.rs`, feature `app`)

| Go | Rust |
|---|---|
| `cmdtree.Run(args) int` | `crate::cmdtree::run(args: &[String]) -> i32` — exit 2 parse-err, 1 unknown-node/json-err, 0 ok. |
| `cmdNode`/`cmdFlag` (JSON catalog) | module-private `CmdNode`/`CmdFlag` `#[derive(Serialize)]`; `type`→`type_` rename, `Subcommands`→`commands`, `omitempty`→skip. Not exported (Go exports only `Run`). |

### `router` (Go `internal/router` → `src/router.rs`, feature `app`)

| Go | Rust |
|---|---|
| `Kind` (`Passthrough`/`RunShortcut`/`Meta`) | `pub enum Kind { Passthrough, RunShortcut, Meta }` (`Copy`+`PartialEq`). |
| `GitcToken = "gitc"` | `pub const GITC_TOKEN: &str = "gitc"`. |
| `Decision` (by-value `Shortcut`) | `pub struct Decision<'a> { kind, shortcut: Option<&'a Shortcut>, args }` — borrows the shortcut (identity by name); explicit `'a`. |
| `Classify(args, shortcuts)` | `pub fn classify<'a>(args: &[String], shortcuts: &'a [Shortcut]) -> Decision<'a>`. |
