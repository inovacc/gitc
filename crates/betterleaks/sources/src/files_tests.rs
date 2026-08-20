//! Tests for the directory walker and stdin source. These use a real temp
//! directory rather than a mocked filesystem — the behaviours that matter here
//! (empty files, size caps, pruned directories, symlinks) are filesystem
//! behaviours, and a mock would only assert my own assumptions back at me.

use super::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

struct TempTree(PathBuf);

impl TempTree {
    fn new(tag: &str) -> TempTree {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "betterleaks_files_{tag}_{}",
            std::process::id() as u64 ^ tag.bytes().map(|b| b as u64).sum::<u64>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("mkdir");
        TempTree(p)
    }
    fn file(&self, rel: &str, contents: &str) -> PathBuf {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir -p");
        }
        let mut f = std::fs::File::create(&p).expect("create");
        f.write_all(contents.as_bytes()).expect("write");
        p
    }
    fn path(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn names(targets: &[ScanTarget]) -> Vec<String> {
    let mut v: Vec<String> = targets
        .iter()
        .map(|t| {
            PathBuf::from(&t.path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        })
        .collect();
    v.sort();
    v
}

#[test]
fn walks_a_tree_and_finds_every_file() {
    let t = TempTree::new("walk");
    t.file("a.txt", "one");
    t.file("sub/b.txt", "two");
    t.file("sub/deep/c.txt", "three");

    let f = Files::new(&t.path());
    assert_eq!(names(&f.scan_targets()), vec!["a.txt", "b.txt", "c.txt"]);
}

/// An EMPTY file has nothing to find, and Go skips it before opening.
#[test]
fn empty_files_are_skipped() {
    let t = TempTree::new("empty");
    t.file("empty.txt", "");
    t.file("full.txt", "x");

    let f = Files::new(&t.path());
    assert_eq!(names(&f.scan_targets()), vec!["full.txt"]);
}

/// `max_file_size` of 0 means NO limit — not "skip everything".
#[test]
fn max_file_size_zero_means_unlimited() {
    let t = TempTree::new("nolimit");
    t.file("big.txt", &"x".repeat(10_000));

    let mut f = Files::new(&t.path());
    f.max_file_size = 0;
    assert_eq!(names(&f.scan_targets()), vec!["big.txt"]);
}

#[test]
fn max_file_size_skips_oversized_files() {
    let t = TempTree::new("cap");
    t.file("small.txt", "x");
    t.file("big.txt", &"x".repeat(5_000));

    let mut f = Files::new(&t.path());
    f.max_file_size = 1_000;
    assert_eq!(names(&f.scan_targets()), vec!["small.txt"]);
}

/// A skipped DIRECTORY is pruned — its descendants are never visited. This is
/// Go's `filepath.SkipDir`, and it is the difference between skipping one entry
/// and skipping a subtree.
#[test]
fn skipped_directory_is_pruned_with_its_descendants() {
    let t = TempTree::new("prune");
    t.file("keep.txt", "x");
    t.file("node_modules/pkg/index.js", "x");
    t.file("node_modules/pkg/deep/more.js", "x");

    let skip: SkipFunc = &|attrs: &BTreeMap<String, String>| {
        attrs
            .get(ATTR_PATH)
            .is_some_and(|p| p.replace('\\', "/").contains("/node_modules"))
    };
    let mut f = Files::new(&t.path());
    f.should_skip = Some(skip);

    assert_eq!(
        names(&f.scan_targets()),
        vec!["keep.txt"],
        "the whole node_modules subtree must be pruned"
    );
}

#[test]
fn skipped_file_is_dropped_without_pruning_siblings() {
    let t = TempTree::new("skipfile");
    t.file("keep.txt", "x");
    t.file("skip.lock", "x");

    let skip: SkipFunc = &|attrs: &BTreeMap<String, String>| {
        attrs.get(ATTR_PATH).is_some_and(|p| p.ends_with(".lock"))
    };
    let mut f = Files::new(&t.path());
    f.should_skip = Some(skip);
    assert_eq!(names(&f.scan_targets()), vec!["keep.txt"]);
}

/// A single FILE as the root is scanned directly — Go Lstats the root and calls
/// the walk function on it rather than requiring a directory.
#[test]
fn a_single_file_root_is_scanned() {
    let t = TempTree::new("single");
    let p = t.file("only.txt", "content");

    let f = Files::new(&p.to_string_lossy());
    assert_eq!(names(&f.scan_targets()), vec!["only.txt"]);
}

/// A missing root is not an error — Go warns and yields nothing.
#[test]
fn missing_root_yields_nothing() {
    let f = Files::new("D:/definitely/not/a/real/path/xyz");
    assert!(f.scan_targets().is_empty());
}

/// Walk order is sorted, so a scan is reproducible run to run. Go inherits
/// filesystem order; sorting is a deliberate improvement, pinned here.
#[test]
fn walk_order_is_deterministic() {
    let t = TempTree::new("order");
    for n in ["c.txt", "a.txt", "b.txt"] {
        t.file(n, "x");
    }
    let f = Files::new(&t.path());
    let first = f.scan_targets();
    let second = f.scan_targets();
    assert_eq!(first, second, "two walks must agree");
}

/// End to end: the walker feeds the file scanner and produces fragments with
/// the right path attribute.
#[test]
fn fragments_flow_from_the_walk() {
    let t = TempTree::new("frag");
    t.file("a.txt", "hello\n");
    t.file("sub/b.txt", "world\n");

    let f = Files::new(&t.path());
    let mut out: Vec<Fragment> = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut collect).expect("scan");

    assert_eq!(out.len(), 2);
    let mut raws: Vec<&str> = out.iter().map(|f| f.raw.as_str()).collect();
    raws.sort();
    assert_eq!(raws, vec!["hello\n", "world\n"]);
    for frag in &out {
        assert!(!frag.attr(ATTR_PATH).is_empty(), "every fragment carries a path");
    }
}

// ── Stdin ───────────────────────────────────────────────────────────────────

#[test]
fn stdin_yields_fragments_with_caller_attributes() {
    let mut attrs = BTreeMap::new();
    attrs.insert(ATTR_PATH.to_string(), "piped.txt".to_string());

    let mut s = Stdin::new(std::io::Cursor::new(b"secret content\n".to_vec()));
    s.attributes = attrs;

    let mut out: Vec<Fragment> = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    s.fragments(&mut collect).expect("scan");

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].raw, "secret content\n");
    assert_eq!(
        out[0].attr(ATTR_PATH),
        "piped.txt",
        "caller attributes override the file source's own"
    );
}

/// The skip callback sees the CALLER's attributes — that is why Go merges them
/// before filtering rather than after.
#[test]
fn stdin_skip_sees_caller_attributes() {
    let mut attrs = BTreeMap::new();
    attrs.insert(ATTR_PATH.to_string(), "vendor/x.go".to_string());

    let skip: SkipFunc = &|a: &BTreeMap<String, String>| {
        a.get(ATTR_PATH).is_some_and(|p| p.starts_with("vendor/"))
    };

    let mut s = Stdin::new(std::io::Cursor::new(b"content\n".to_vec()));
    s.attributes = attrs;
    s.should_skip = Some(skip);

    let mut out: Vec<Fragment> = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    s.fragments(&mut collect).expect("scan");
    assert!(out.is_empty(), "the caller's path must drive the skip decision");
}

#[test]
fn stdin_with_no_attributes_still_works() {
    let s = Stdin::new(std::io::Cursor::new(b"plain\n".to_vec()));
    let mut out: Vec<Fragment> = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    s.fragments(&mut collect).expect("scan");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].raw, "plain\n");
}
