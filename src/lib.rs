//! gitc — a git toolkit in Rust.
//!
//! This crate ships two things:
//!
//! - **This library** — pure-Rust readers for git's on-disk formats: loose and
//!   packed objects ([`gitobj`] / [`gitpack`]), the index ([`gitindex`]), blob
//!   enumeration over the object graph ([`gitwalk`]), and a minimal git argv
//!   parser ([`gitargs`]); plus an optional `git filter-repo` port
//!   ([`filterrepo`], behind the `scrub` feature) for history rewriting. No
//!   external service, no gate — just git formats in Rust.
//!
//! - **The binary** (`src/main.rs`) — a drop-in `git` that IS git: git's own C
//!   source is compiled in via the C ABI and dispatched through `cmd_main`
//!   (see the binary's `ffi` module + `build.rs`).

pub mod gitargs;
pub mod gitindex;
pub mod gitobj;
pub mod gitpack;
pub mod gitwalk;

/// Ported Go application layer (from the go-main Go implementation), behind `app`.
/// RFC 9562 UUIDv7 generation (Go `internal/uuidv7`).
#[cfg(feature = "app")]
pub mod uuidv7;

/// Platform-specific gitc paths — data/config/shim/audit locations (Go `internal/paths`).
#[cfg(feature = "app")]
pub mod paths;

/// Mask credentials in argv/strings before audit logging (Go `internal/redact`).
#[cfg(feature = "app")]
pub mod redact;

/// Built-in convenience commands as git arg-vector compositions (Go `internal/shortcut`).
#[cfg(feature = "app")]
pub mod shortcut;

/// Pinned upstream repo URLs guarded by sha256 (Go `internal/origin`).
#[cfg(feature = "app")]
pub mod origin;

/// Machine/org enforcement policy (secret gate + remote allowlist) and gitc's
/// passthrough defaults like the initial branch (Go `internal/policy`).
#[cfg(feature = "app")]
pub mod policy;

/// The gitc installer — currently the embedded Windows launcher shim
/// (Go `internal/installer/shim`); full shadow-installer lands later.
#[cfg(feature = "app")]
pub mod installer;

/// Audit-record enrichment via `git status --porcelain=v2` (Go `internal/enrich`).
#[cfg(feature = "app")]
pub mod enrich;

/// Resolve the real git backend (managed/system) with a self-invocation guard
/// (Go `internal/backend`).
#[cfg(feature = "app")]
pub mod backend;

/// On-disk settings.json: active backend pointer + update throttle, atomic writes
/// under an advisory lock (Go `internal/settings`).
#[cfg(feature = "app")]
pub mod settings;

/// JSON-driven meta command-tree renderer/dispatch (Go `internal/cmdtree`).
#[cfg(feature = "app")]
pub mod cmdtree;

/// Classify an argv into passthrough / shortcut / meta (Go `internal/router`).
#[cfg(feature = "app")]
pub mod router;

/// Checksum-gated self-update: GitHub release check + verified binary swap
/// (Go `internal/selfupdate`). HTTP is injected via a trait (no bundled client).
#[cfg(feature = "app")]
pub mod selfupdate;

/// The append-only forensic audit DB: migrations + tamper-evident hash chain
/// (Go `internal/store`).
#[cfg(feature = "app")]
pub mod store;

/// One-shot health check of the gitc install + backend + shim + audit DB
/// (Go `internal/doctor`).
#[cfg(feature = "app")]
pub mod doctor;

/// Managed-git (MinGit) provisioning: GitHub releases, verified download, zip/
/// tar.bz2 extraction with traversal guards (Go `internal/gitwin`).
#[cfg(feature = "app")]
pub mod gitwin;

/// gitc's execution core: passthrough/shortcut exec + enforcement gate + audit
/// insert + env redaction (Go `internal/runner`).
#[cfg(feature = "app")]
pub mod runner;

/// Adversarial / fuzz coverage over the untrusted-input git parsers (goal §50).
#[cfg(test)]
mod fuzz_tests;

/// Secret scanner over a repo's git objects (the gitleaks/betterleaks `detect`
/// engine + the readers above). Behind the `scan` feature.
#[cfg(feature = "scan")]
pub mod scan;

/// The `gitc scan` command surface (dispatch, modes, reporting, exit codes).
/// Behind the `scan` feature. A library entry point — returns the exit code.
#[cfg(feature = "scan")]
pub mod scancmd;

/// A `git filter-repo` port for history rewriting. Behind the `scrub` feature.
#[cfg(feature = "scrub")]
pub mod filterrepo;

/// The `gitc scrub` command surface (history remediation: path/replace/secret/
/// rollback, with plan/dry-run/backup/verify). Behind the `scrub` feature.
#[cfg(feature = "scrub")]
pub mod scrubcmd;
