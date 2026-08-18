//! Port of Go `sources` — CORE only (M8 in `PORT-PLAN.md`).
//!
//! **Scope, and why it stops here.** `detect` references exactly five things
//! from this package — `Fragment`, `Source`, `SkipFunc`, the `Attr*` keys, and
//! `InnerPathSeparator` — which is 189 Go LOC across `source.go`, `fragment.go`,
//! `attribute.go` and one const in `file.go`. Everything else in `sources` is
//! the SCANNERS (git, filesystem, archives, GitHub, GitLab, HuggingFace, S3,
//! ~7,700 LOC), which are reached only from `cmd` and `detect/deprecated.go` and
//! are Wave 5. Splitting here is what lets `config` and `detect` be ported
//! without dragging in `go-gitdiff`, `fastwalk`, `mholt/archives`, `go-github`
//! and an async runtime.
//!
//! Zero dependencies.

pub mod archive;
pub mod parallel_git;
mod attribute;
mod file;
mod files;
pub mod git;
pub use attribute::*;
pub use file::{File, DEFAULT_BUFFER_SIZE, MAX_PEEK_SIZE};
pub use files::{Files, ScanTarget, Stdin};
pub use git::{Git, GitError};

use std::collections::BTreeMap;

/// Go `sources.InnerPathSeparator` (`file.go:22`) — separates an archive's path
/// from the path of a file WITHIN it, e.g. `a.zip!inner/b.txt`.
pub const INNER_PATH_SEPARATOR: &str = "!";

/// Go `sources.Fragment` — a fragment of a source with its metadata.
///
/// **Reshape (flagged):** Go's `Attributes map[string]string` is unordered and
/// its iteration order is randomized; this uses a `BTreeMap` so attribute
/// iteration is DETERMINISTIC. Nothing in the ported scope depends on Go's
/// random order, and a stable order makes report output reproducible — but it is
/// a deliberate divergence, not an accident.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fragment {
    /// The raw content of the fragment.
    pub raw: String,

    pub bytes: Vec<u8>,

    /// Whether this fragment is inherited from a finding.
    pub inherited_from_finding: bool,

    /// The line number this fragment starts on.
    pub start_line: i64,

    /// All source-specific metadata.
    pub attributes: BTreeMap<String, String>,
}

impl Fragment {
    /// Go `(*Fragment).SetAttr`. Go lazily allocates the map on first write; a
    /// `BTreeMap` is already valid when empty, so the guard is unnecessary.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }

    /// Go `(*Fragment).Attr` — a missing key yields `""`, never an error.
    pub fn attr(&self, key: &str) -> &str {
        self.attributes.get(key).map_or("", |v| v.as_str())
    }
}

/// Go `sources.SkipFunc` — decides whether to skip a fragment from its
/// attributes. Returns true to SKIP (discard), false to keep. Sources take this
/// as a callback so path/commit filtering stays decoupled from config.
///
/// `Sync` is required because a source may fan its fetches out across threads
/// (S3's `--workers`), which means the whole source — this callback included —
/// has to be shareable. Go gets this for free: its `SkipFunc` is a plain func
/// value called from inside an `errgroup`.
pub type SkipFunc<'a> = &'a (dyn Fn(&BTreeMap<String, String>) -> bool + Sync);

/// Go `sources.FragmentsFunc` — the yield callback `Fragments` drives.
///
/// **Reshape:** Go's signature is `func(fragment Fragment, err error) error` —
/// it passes BOTH a fragment and an error, because a Go source can report a
/// per-fragment failure while continuing. Rust models that as
/// `Result<Fragment, E>`, which makes the "both set" and "neither set" states
/// unrepresentable rather than merely unlikely.
pub type FragmentsFunc<'a, E> = &'a mut dyn FnMut(Result<Fragment, E>) -> Result<(), E>;

/// Go `sources.Source` — a thing that can yield fragments.
///
/// **Reshape:** Go's method takes a `context.Context` for cancellation. Rust has
/// no ambient context type; cancellation is expressed by the implementor (the
/// `codec`/`detect` side already uses explicit cancel flags), so the parameter is
/// dropped here rather than faked with a placeholder. Flagged in PORT-TRACK.md.
pub trait Source {
    /// The error type this source reports.
    type Error;

    /// A `filepath.WalkDir`-like interface for scanning the source's fragments.
    fn fragments(&self, yield_fn: FragmentsFunc<'_, Self::Error>) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod file_tests;
#[cfg(test)]
mod files_tests;
#[cfg(test)]
mod git_tests;
#[cfg(test)]
mod tests;
