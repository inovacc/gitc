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
