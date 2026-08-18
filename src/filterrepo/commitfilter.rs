//! Empty-commit prune + parent remap (Rust port of git-filter-repo's prune logic).
//!
//! Decides, for each commit whose file changes have already been filtered,
//! whether it is kept or pruned as empty, and rewrites parents so survivors
//! re-point past pruned ancestors. Reproduces the prune-empty subset of
//! git-filter-repo's `_tweak_commit` / `_prunable`; emptiness is judged purely
//! by the absence of `FileChange`s (documented limitations preserved, not fixed).
//!
//! Stateful: it accumulates the pruned→surviving-parent mapping across the whole
//! stream, so one shared instance must drive the commit callback in stream order.

use std::collections::{HashMap, HashSet};

use super::records::{Commit, Ref};

/// How empty commits are handled after file filtering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PruneMode {
    /// Prune a commit emptied by filtering, but keep an originally-empty commit
    /// unless one of its parents was pruned. The upstream default.
    Auto,
    /// Prune any non-merge commit with no file changes (authored-empty too).
    Always,
    /// Keep every commit regardless of emptiness.
    Never,
}

/// Prune-empty decisions + parent remapping across a stream.
///
/// (Go's `NewCommitFilter` also took the parser's `*IDMap`; it was retained only
/// for wiring parity and never mutated — `pruned_to` is keyed on new marks — so
/// this port omits it.)
pub struct CommitFilter {
    mode: PruneMode,
    /// A pruned commit's (new) mark → the reference of its nearest surviving
    /// ancestor (a zero Ref means the whole ancestry was pruned → child is root).
    /// Values are stored fully resolved, so a single lookup hops a pruned chain.
    pruned_to: HashMap<i64, Ref>,
}

impl CommitFilter {
    pub fn new(mode: PruneMode) -> Self {
        CommitFilter {
            mode,
            pruned_to: HashMap::new(),
        }
    }

    /// Decide whether `commit` is kept, after its file changes were filtered.
    /// Rewrites parents (redirecting past pruned commits, de-duplicating), then
    /// applies the prune-empty policy. `had_file_changes` must report whether the
    /// ORIGINAL commit carried any file changes (distinguishes filtered-empty from
    /// authored-empty). On prune it records the survivor, skips the commit, and
    /// returns false.
    pub fn tweak(&mut self, commit: &mut Commit, had_file_changes: bool) -> bool {
        let orig = orig_parents(commit);
        let new_parents = self.resolve_parents(&orig);
        set_parents(commit, &new_parents);

        if self.should_prune(commit, &orig, &new_parents, had_file_changes) {
            let survivor = new_parents.first().cloned().unwrap_or_default();
            self.pruned_to.insert(commit.mark, survivor);
            commit.el.skip();
            return false;
        }
        true
    }

    /// Redirect each parent past any pruned commit and remove duplicates. An
    /// exact-duplicate parent is dropped only when it resulted from a pruning
    /// rewrite; an already-identical duplicate (intentional no-ff merge) is kept.
    fn resolve_parents(&self, orig: &[Ref]) -> Vec<Ref> {
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for r in orig {
            let (rr, drop) = self.resolve(r);
            if drop {
                continue;
            }
            let key = ref_key(&rr);
            let rewritten = self.is_pruned(r);
            if seen.contains(&key) && rewritten {
                continue;
            }
            seen.insert(key);
            out.push(rr);
        }
        out
    }

    /// Map a single parent to its surviving ancestor. The bool is true when the
    /// parent's entire ancestry was pruned and the parent should be dropped.
    fn resolve(&self, r: &Ref) -> (Ref, bool) {
        if r.mark != 0 {
            if let Some(s) = self.pruned_to.get(&r.mark) {
                if s.is_zero() {
                    return (Ref::default(), true);
                }
                return (s.clone(), false);
            }
        }
        (r.clone(), false)
    }

    /// Whether the reference points at a commit that was pruned.
    fn is_pruned(&self, r: &Ref) -> bool {
        r.mark != 0 && self.pruned_to.contains_key(&r.mark)
    }

    /// The prune-empty decision (mirrors `_prunable` for the pipe-free subset).
    fn should_prune(
        &self,
        commit: &Commit,
        orig: &[Ref],
        new_parents: &[Ref],
        had_file_changes: bool,
    ) -> bool {
        if self.mode == PruneMode::Never {
            return false;
        }
        let became_empty = commit.file_changes.is_empty();

        // Genuine merge commits are not pruned here.
        if new_parents.len() >= 2 {
            return false;
        }

        if self.mode == PruneMode::Always {
            return became_empty;
        }

        // Auto.
        if !had_file_changes {
            // Empty in the original repo: prune only if still empty AND a parent
            // was pruned.
            if !became_empty {
                return false;
            }
            return new_parents.len() < orig.len() || (orig.len() == 1 && self.is_pruned(&orig[0]));
        }

        // Originally had file changes; if filtering emptied it, prune.
        became_empty
    }
}

/// The commit's parents (first parent plus merges) on entry, dropping zero refs.
fn orig_parents(commit: &Commit) -> Vec<Ref> {
    let mut out = Vec::new();
    if !commit.from.is_zero() {
        out.push(commit.from.clone());
    }
    for m in &commit.merges {
        if !m.is_zero() {
            out.push(m.clone());
        }
    }
    out
}

/// Write the resolved parent list back, collapsing a degenerated merge into an
/// ordinary commit.
fn set_parents(commit: &mut Commit, parents: &[Ref]) {
    if parents.is_empty() {
        commit.from = Ref::default();
        commit.merges = Vec::new();
        return;
    }
    commit.from = parents[0].clone();
    commit.merges = if parents.len() > 1 {
        parents[1..].to_vec()
    } else {
        Vec::new()
    };
}

/// A stable de-duplication key for a parent reference.
fn ref_key(r: &Ref) -> String {
    if r.mark != 0 {
        format!("m{}", r.mark)
    } else {
        let mut s = String::from("o");
        s.push_str(&String::from_utf8_lossy(r.oid.as_deref().unwrap_or(&[])));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filterrepo::records::{FileChange, FileChangeType};

    fn modify_change(path: &str, mark: i64) -> FileChange {
        FileChange {
            type_: FileChangeType::Modify,
            mode: b"100644".to_vec(),
            blob: Ref { mark, oid: None },
            path: path.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    fn mark_ref(m: i64) -> Ref {
        Ref { mark: m, oid: None }
    }

    fn commit(
        mark: i64,
        branch: &str,
        from: Ref,
        merges: Vec<Ref>,
        fcs: Vec<FileChange>,
    ) -> Commit {
        Commit {
            mark,
            branch: branch.as_bytes().to_vec(),
            from,
            merges,
            file_changes: fcs,
            ..Default::default()
        }
    }

    #[test]
    fn prune_empty_single_commit() {
        struct Case {
            mode: PruneMode,
            had: bool,
            fcs: Vec<FileChange>,
            parent: Ref,
            want_keep: bool,
        }
        let cases = [
            Case {
                mode: PruneMode::Auto,
                had: true,
                fcs: vec![],
                parent: mark_ref(1),
                want_keep: false,
            },
            Case {
                mode: PruneMode::Auto,
                had: false,
                fcs: vec![],
                parent: mark_ref(1),
                want_keep: true,
            },
            Case {
                mode: PruneMode::Auto,
                had: true,
                fcs: vec![modify_change("a", 2)],
                parent: mark_ref(1),
                want_keep: true,
            },
            Case {
                mode: PruneMode::Auto,
                had: false,
                fcs: vec![],
                parent: Ref::default(),
                want_keep: true,
            },
            Case {
                mode: PruneMode::Always,
                had: false,
                fcs: vec![],
                parent: mark_ref(1),
                want_keep: false,
            },
            Case {
                mode: PruneMode::Always,
                had: true,
                fcs: vec![modify_change("a", 2)],
                parent: mark_ref(1),
                want_keep: true,
            },
            Case {
                mode: PruneMode::Never,
                had: true,
                fcs: vec![],
                parent: mark_ref(1),
                want_keep: true,
            },
        ];
        for (i, c) in cases.into_iter().enumerate() {
            let mut cf = CommitFilter::new(c.mode);
            let mut cm = commit(10, "refs/heads/main", c.parent, vec![], c.fcs);
            assert_eq!(cf.tweak(&mut cm, c.had), c.want_keep, "case {i}");
        }
    }

    #[test]
    fn linear_parent_remap() {
        let mut cf = CommitFilter::new(PruneMode::Auto);
        // A (root, content) -> B (empty) -> C (empty) -> D (content)
        let mut a = commit(
            1,
            "refs/heads/main",
            Ref::default(),
            vec![],
            vec![modify_change("a", 100)],
        );
        assert!(cf.tweak(&mut a, true), "A kept");
        let mut b = commit(2, "refs/heads/main", mark_ref(1), vec![], vec![]);
        assert!(!cf.tweak(&mut b, true), "B pruned");
        let mut c = commit(3, "refs/heads/main", mark_ref(2), vec![], vec![]);
        assert!(!cf.tweak(&mut c, true), "C pruned");
        let mut d = commit(
            4,
            "refs/heads/main",
            mark_ref(3),
            vec![],
            vec![modify_change("d", 101)],
        );
        assert!(cf.tweak(&mut d, true), "D kept");
        assert_eq!(d.from.mark, 1, "D re-points to A");
        assert!(d.merges.is_empty());
    }

    #[test]
    fn pruned_root_child_becomes_root() {
        let mut cf = CommitFilter::new(PruneMode::Always);
        let mut a = commit(1, "refs/heads/main", Ref::default(), vec![], vec![]);
        assert!(!cf.tweak(&mut a, false), "empty root pruned under always");
        let mut b = commit(
            2,
            "refs/heads/main",
            mark_ref(1),
            vec![],
            vec![modify_change("b", 100)],
        );
        assert!(cf.tweak(&mut b, true), "B kept");
        assert!(b.from.is_zero(), "B becomes a root");
    }

    #[test]
    fn merge_parent_remap() {
        let mut cf = CommitFilter::new(PruneMode::Auto);
        let mut a = commit(
            1,
            "refs/heads/main",
            Ref::default(),
            vec![],
            vec![modify_change("a", 100)],
        );
        cf.tweak(&mut a, true);
        let mut b = commit(2, "refs/heads/main", mark_ref(1), vec![], vec![]);
        assert!(!cf.tweak(&mut b, true), "B pruned");
        let mut x = commit(
            3,
            "refs/heads/side",
            Ref::default(),
            vec![],
            vec![modify_change("x", 101)],
        );
        cf.tweak(&mut x, true);
        let mut m = commit(
            4,
            "refs/heads/main",
            mark_ref(2),
            vec![mark_ref(3)],
            vec![modify_change("m", 102)],
        );
        assert!(cf.tweak(&mut m, true), "merge M kept");
        assert_eq!(m.from.mark, 1, "M.from re-points to A");
        assert_eq!(m.merges.len(), 1);
        assert_eq!(m.merges[0].mark, 3);
    }

    #[test]
    fn merge_dedup_degenerates() {
        let mut cf = CommitFilter::new(PruneMode::Auto);
        let mut a = commit(
            1,
            "refs/heads/main",
            Ref::default(),
            vec![],
            vec![modify_change("a", 100)],
        );
        cf.tweak(&mut a, true);
        let mut b = commit(2, "refs/heads/topic", mark_ref(1), vec![], vec![]);
        cf.tweak(&mut b, true);
        let mut c = commit(3, "refs/heads/main", mark_ref(1), vec![], vec![]);
        cf.tweak(&mut c, true);
        // Merge of B and C, both resolving to A; empty + rewritten → pruned.
        let mut m = commit(4, "refs/heads/main", mark_ref(2), vec![mark_ref(3)], vec![]);
        assert!(!cf.tweak(&mut m, true), "degenerate empty merge pruned");
        let mut child = commit(
            5,
            "refs/heads/main",
            mark_ref(4),
            vec![],
            vec![modify_change("z", 101)],
        );
        assert!(cf.tweak(&mut child, true), "child kept");
        assert_eq!(child.from.mark, 1, "child re-points to A");
    }

    #[test]
    fn no_ff_duplicate_parent_preserved() {
        let mut cf = CommitFilter::new(PruneMode::Never);
        let mut a = commit(
            1,
            "refs/heads/main",
            Ref::default(),
            vec![],
            vec![modify_change("a", 100)],
        );
        cf.tweak(&mut a, true);
        // A merge that lists A twice without any pruning involved.
        let mut m = commit(2, "refs/heads/main", mark_ref(1), vec![mark_ref(1)], vec![]);
        assert!(cf.tweak(&mut m, true), "never mode keeps");
        assert_eq!(m.from.mark, 1);
        assert_eq!(
            m.merges.len(),
            1,
            "duplicate non-rewritten parent preserved"
        );
        assert_eq!(m.merges[0].mark, 1);
    }
}
