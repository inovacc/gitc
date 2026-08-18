//! Apply a PathSpec to a commit's file changes (Rust port of _filter_files).
//!
//! Applies a [`PathSpec`] to a commit's file changes in place (git-filter-repo's
//! `_filter_files`): each path is run through `new_name`; dropped changes are
//! removed, survivors renamed. A `deleteall` is preserved. Rename collisions are
//! resolved where safe (a deletion yields; identical modifies collapse) and
//! otherwise reported as an error. Output is re-sorted by path (deterministic).
//! No git I/O.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use super::bytesutil::decode;
use super::pathspec::PathSpec;
use super::records::{Commit, FileChange, FileChangeType, Ref};

/// A rename produced two changes at the same path that cannot be reconciled.
#[derive(Debug)]
pub struct FilterFilesError(pub String);

impl fmt::Display for FilterFilesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for FilterFilesError {}

/// Apply `spec` to `commit`'s file changes in place. The empty path key is
/// reserved for `deleteall`; a `BTreeMap` keeps the result in byte-lexicographic
/// path order, matching the original's post-filter sort.
pub fn filter_files(commit: &mut Commit, spec: &PathSpec) -> Result<(), FilterFilesError> {
    let mut result: BTreeMap<Vec<u8>, FileChange> = BTreeMap::new();

    for mut change in std::mem::take(&mut commit.file_changes) {
        if change.type_ == FileChangeType::DeleteAll {
            result.insert(Vec::new(), change);
            continue;
        }

        let Some(new_name) = spec.new_name(&change.path) else {
            continue;
        };
        change.path = new_name.clone();
        let key = new_name;

        if let Some(existing) = result.get(&key) {
            if change.type_ == FileChangeType::Delete {
                // A deletion of an already-present path: keep the other.
                continue;
            }
            if change.type_ == FileChangeType::Modify
                && existing.type_ == FileChangeType::Modify
                && change.mode == existing.mode
                && ref_equal(&change.blob, &existing.blob)
            {
                // Identical content at the same path: one copy suffices.
                continue;
            }
            if existing.type_ != FileChangeType::Delete {
                return Err(FilterFilesError(format!(
                    "file renaming caused colliding pathnames: {}",
                    decode(&key)
                )));
            }
            // existing is a deletion that this change supersedes; fall through.
        }

        result.insert(key, change);
    }

    commit.file_changes = result.into_values().collect();
    Ok(())
}

/// Whether two blob references denote the same object.
fn ref_equal(a: &Ref, b: &Ref) -> bool {
    a.mark == b.mark && a.oid == b.oid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modify(path: &[u8], mark: i64) -> FileChange {
        FileChange {
            type_: FileChangeType::Modify,
            mode: b"100644".to_vec(),
            blob: Ref { mark, oid: None },
            path: path.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn drop_rename_deleteall() {
        let mut spec = PathSpec::new();
        spec.add_match(b"keep").unwrap();
        spec.add_rename(b"keep", b"kept").unwrap();

        let mut commit = Commit {
            file_changes: vec![
                FileChange {
                    type_: FileChangeType::DeleteAll,
                    ..Default::default()
                },
                modify(b"drop", 1),
                modify(b"keep", 2),
            ],
            ..Default::default()
        };
        filter_files(&mut commit, &spec).unwrap();

        assert_eq!(commit.file_changes.len(), 2, "deleteall + renamed keep");
        assert_eq!(
            commit.file_changes[0].type_,
            FileChangeType::DeleteAll,
            "deleteall sorts first"
        );
        assert_eq!(commit.file_changes[1].path, b"kept");
    }

    #[test]
    fn rename_collision_with_deletion_resolves() {
        let mut spec = PathSpec::new();
        spec.add_rename(b"old", b"new").unwrap();

        let mut commit = Commit {
            file_changes: vec![
                FileChange {
                    type_: FileChangeType::Delete,
                    path: b"new".to_vec(),
                    ..Default::default()
                },
                modify(b"old", 5),
            ],
            ..Default::default()
        };
        filter_files(&mut commit, &spec).expect("collision with a deletion should resolve");

        assert_eq!(commit.file_changes.len(), 1);
        assert_eq!(
            commit.file_changes[0].type_,
            FileChangeType::Modify,
            "the modify wins"
        );
    }

    #[test]
    fn rename_hard_collision_errors() {
        let mut spec = PathSpec::new();
        spec.add_rename(b"old", b"new").unwrap();

        let mut commit = Commit {
            file_changes: vec![modify(b"new", 7), modify(b"old", 8)],
            ..Default::default()
        };
        assert!(
            filter_files(&mut commit, &spec).is_err(),
            "colliding pathnames must error"
        );
    }

    #[test]
    fn output_is_sorted() {
        let spec = PathSpec::new();
        let mut commit = Commit {
            file_changes: vec![modify(b"zeta", 1), modify(b"alpha", 2)],
            ..Default::default()
        };
        filter_files(&mut commit, &spec).unwrap();
        assert_eq!(commit.file_changes[0].path, b"alpha");
        assert_eq!(commit.file_changes[1].path, b"zeta");
    }
}
