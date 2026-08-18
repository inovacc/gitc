//! The fast-import mark registry (Rust port of git-filter-repo's id mapping).
//!
//! The name domain of fast-import marks (the short integer ids assigned to blobs
//! and commits). The marks emitted by `fast-export` are not necessarily the marks
//! the produced stream uses: new objects consume fresh marks, and pruned objects
//! invalidate a mark so references to them get redirected.

use std::collections::HashMap;

/// Sentinel mark meaning "no object" — an old mark remapped to a skipped/pruned
/// object.
pub const MARK_NONE: i64 = 0;

/// Maintains the mark name domain. Stateful; a parser owns exactly one.
pub struct IdMap {
    next_id: i64,
    /// old mark -> new mark (or `MARK_NONE` if skipped).
    translation: HashMap<i64, i64>,
    /// new mark -> every old mark pointing at it. Written for future reverse
    /// lookups (parser waves); not yet read here.
    #[allow(dead_code)]
    reverse: HashMap<i64, Vec<i64>>,
}

impl IdMap {
    /// An empty map whose first minted mark is 1.
    pub fn new() -> Self {
        IdMap {
            next_id: 1,
            translation: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    /// Mint and return the next fresh mark. Call once per created blob/commit.
    /// (Go `New`; renamed to avoid clashing with the `new` constructor.)
    pub fn new_mark(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Whether any mark has been remapped.
    pub fn has_renames(&self) -> bool {
        !self.translation.is_empty()
    }

    /// Record that `old_id` now refers to `new_id` (`MARK_NONE` = skipped).
    pub fn record_rename(&mut self, old_id: i64, new_id: i64) {
        if old_id == new_id && !self.translation.contains_key(&old_id) {
            return;
        }
        self.translation.insert(old_id, new_id);
        self.reverse.entry(new_id).or_default().push(old_id);
    }

    /// Resolve `old_id` to its current mark. The bool is `false` when the object
    /// was skipped (maps to `MARK_NONE`); otherwise `true` and the value is the
    /// effective mark (`old_id` itself when never remapped).
    pub fn translate(&self, old_id: i64) -> (i64, bool) {
        if let Some(&v) = self.translation.get(&old_id) {
            return (v, v != MARK_NONE);
        }
        (old_id, true)
    }
}

impl Default for IdMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_records_renames_and_identity() {
        let mut m = IdMap::new();
        assert!(!m.has_renames(), "new map should have no renames");

        let (a, b) = (m.new_mark(), m.new_mark());
        assert_eq!((a, b), (1, 2), "New() sequence");

        m.record_rename(5, b);
        assert_eq!(m.translate(5), (2, true), "Translate(5)");
        assert_eq!(m.translate(9), (9, true), "Translate(9) identity");

        m.record_rename(7, MARK_NONE);
        assert_eq!(m.translate(7), (MARK_NONE, false), "Translate(7) skipped");

        assert!(m.has_renames(), "map should report renames");
    }
}
