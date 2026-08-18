//! Port of Go `sources/files.go` and `sources/stdin.go` (M17) — walking a
//! directory tree and scanning stdin.
//!
//! **`fastwalk` is NOT a dependency here, and that is faithful rather than a
//! shortcut.** Go uses `charlievieth/fastwalk` purely as a fast walker, then
//! spends a comment explaining how it restores `filepath.WalkDir`'s exact path
//! semantics ("fastwalk joins paths by concatenating … which leaves lexical
//! elements such as `./`"). Since the observable contract is WalkDir's, std
//! recursion reproduces it directly.
//!
//! **Concurrency reshape (flagged):** Go walks concurrently and scans files
//! through a `semgroup` worker pool, but serialises the yield callback behind a
//! mutex — so the OBSERVABLE order is already serial. This port walks and scans
//! serially, which is the same observable behaviour at lower throughput. The
//! parallelism is a performance property, not a semantic one; revisit if
//! whole-tree scan time matters.

use crate::{File, Fragment, SkipFunc, ATTR_PATH};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Go `sources.ScanTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    pub path: String,
    /// Set when the target was reached THROUGH a symlink; `path` is then the
    /// resolved real path.
    pub symlink: String,
}

/// Go `sources.Files`.
pub struct Files<'a> {
    pub should_skip: Option<SkipFunc<'a>>,
    pub follow_symlinks: bool,
    /// Skip files larger than this, in bytes. 0 = no limit.
    pub max_file_size: u64,
    pub path: String,
    pub max_archive_depth: usize,
}

impl<'a> Files<'a> {
    pub fn new(path: &str) -> Files<'a> {
        Files {
            should_skip: None,
            follow_symlinks: false,
            max_file_size: 0,
            path: path.to_string(),
            max_archive_depth: 0,
        }
    }

    /// Go `shouldSkipPath` — consult the skip callback with a path attribute.
    ///
    /// The Windows workaround is ported: the path is tried again with forward
    /// slashes, because rules are written with `/` (gitleaks#1641).
    fn should_skip_path(&self, path: &str) -> bool {
        let Some(skip) = self.should_skip else {
            return false;
        };
        let mut attrs = BTreeMap::new();
        attrs.insert(ATTR_PATH.to_string(), path.to_string());
        if skip(&attrs) {
            return true;
        }
        if cfg!(windows) {
            attrs.insert(ATTR_PATH.to_string(), path.replace('\\', "/"));
            return skip(&attrs);
        }
        false
    }

    /// Go `Files.scanTargets` — yield every file worth scanning under `path`.
    ///
    /// Errors on individual entries are LOGGED AND SKIPPED, never fatal: one
    /// unreadable directory must not abort a whole-tree scan.
    pub fn scan_targets(&self) -> Vec<ScanTarget> {
        let root = PathBuf::from(&self.path);
        let mut out = Vec::new();

        let Ok(meta) = std::fs::symlink_metadata(&root) else {
            // Go warns ("permission denied" / "skipping") and returns nil.
            return out;
        };

        if !meta.is_dir() {
            self.consider(&root, &mut out);
            return out;
        }
        self.walk(&root, &mut out);
        out
    }

    fn walk(&self, dir: &Path, out: &mut Vec<ScanTarget>) {
        // A directory the skip func rejects is pruned entirely — Go returns
        // `filepath.SkipDir`, so descendants are never visited.
        if dir != Path::new(&self.path) && self.should_skip_path(&dir.to_string_lossy()) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return; // permission denied etc. — skip, do not abort
        };
        // read_dir order is filesystem-dependent; sort so a scan is reproducible.
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.is_dir() {
                self.walk(&p, out);
            } else {
                self.consider(&p, out);
            }
        }
    }

    /// Decide whether one non-directory entry becomes a scan target.
    fn consider(&self, path: &Path, out: &mut Vec<ScanTarget>) {
        let Ok(meta) = std::fs::symlink_metadata(path) else { return };
        let display = path.to_string_lossy().to_string();

        if meta.file_type().is_symlink() {
            if !self.follow_symlinks {
                return;
            }
            let Ok(real) = std::fs::canonicalize(path) else { return };
            // A symlink to a DIRECTORY is skipped, not descended.
            if std::fs::metadata(&real).map(|m| m.is_dir()).unwrap_or(false) {
                return;
            }
            if self.should_skip_path(&display) {
                return;
            }
            out.push(ScanTarget {
                path: real.to_string_lossy().to_string(),
                symlink: display,
            });
            return;
        }

        // Empty files have nothing to find.
        if meta.len() == 0 {
            return;
        }
        if self.max_file_size > 0 && meta.len() > self.max_file_size {
            return;
        }
        if self.should_skip_path(&display) {
            return;
        }
        out.push(ScanTarget { path: display, symlink: String::new() });
    }

    /// Go `Files.Fragments` — scan every discovered target.
    ///
    /// A file that cannot be OPENED is skipped (Go logs "permission denied" and
    /// returns nil), so one unreadable file does not abort the scan.
    pub fn fragments<E, F>(&self, mut yield_fn: F) -> Result<(), E>
    where
        F: FnMut(Result<Fragment, E>) -> Result<(), E>,
        E: From<String>,
    {
        for target in self.scan_targets() {
            let Ok(handle) = std::fs::File::open(&target.path) else {
                continue;
            };
            let mut file = File::new(handle, &target.path);
            file.symlink = target.symlink.clone();
            file.max_archive_depth = self.max_archive_depth;
            file.fragments(&mut yield_fn)?;
        }
        Ok(())
    }
}

/// Go `sources.Stdin` — scan stdin-like content, stamping caller attributes on
/// every fragment.
pub struct Stdin<R: std::io::Read> {
    pub content: R,
    /// Applied to every fragment BEFORE skip filtering, so a caller-supplied
    /// path participates in the skip decision.
    pub attributes: BTreeMap<String, String>,
    pub should_skip: Option<SkipFunc<'static>>,
    pub max_archive_depth: usize,
}

impl<R: std::io::Read> Stdin<R> {
    pub fn new(content: R) -> Stdin<R> {
        Stdin {
            content,
            attributes: BTreeMap::new(),
            should_skip: None,
            max_archive_depth: 0,
        }
    }

    /// Go `Stdin.Fragments`.
    pub fn fragments<E, F>(self, mut yield_fn: F) -> Result<(), E>
    where
        F: FnMut(Result<Fragment, E>) -> Result<(), E>,
        E: From<String>,
    {
        let attributes = self.attributes;
        let should_skip = self.should_skip;
        let mut file = File::new(self.content, "");
        file.max_archive_depth = self.max_archive_depth;

        file.fragments(&mut |r: Result<Fragment, E>| -> Result<(), E> {
            match r {
                Err(e) => yield_fn(Err(e)),
                Ok(mut fragment) => {
                    // Caller attributes are merged in and WIN over the file
                    // source's own, matching Go's `maps.Copy(dst, src)`.
                    for (k, v) in &attributes {
                        fragment.attributes.insert(k.clone(), v.clone());
                    }
                    if let Some(skip) = should_skip {
                        if skip(&fragment.attributes) {
                            return Ok(());
                        }
                    }
                    yield_fn(Ok(fragment))
                }
            }
        })
    }
}
