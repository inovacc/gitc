//! Tests for the diff parser.
//!
//! The `Raw(OpAdd)` behaviour gets the most attention: it decides what the
//! scanner ever sees. Including deletes would report every secret ever removed;
//! including context would report the same secret on every later commit; missing
//! adds would report nothing at all.

use super::*;

/// AWS-shaped keys, generated at runtime — no literal provider token is committed
/// anywhere in this repository (see the `testkeys` crate). These tests only parse
/// diff text, so any well-formed value serves. The `const` fixtures below carry
/// `__AWSKEY__` / `__OLDKEY__` placeholders because a `const` cannot call a function.
fn aws_key() -> String {
    testkeys::aws(1)
}

fn old_key() -> String {
    testkeys::aws(2)
}

/// Resolves the placeholders in a fixture.
fn fixture(s: &str) -> String {
    s.replace("__AWSKEY__", &aws_key()).replace("__OLDKEY__", &old_key())
}

const LOG: &str = "\
commit 1a2b3c4d5e6f7788990011223344556677889900
Author: Ada Lovelace <ada@example.com>
Date:   Mon Aug 11 09:15:00 2026 +0000

    add config

    with a second paragraph

diff --git a/src/config.rs b/src/config.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/config.rs
@@ -0,0 +1,3 @@
+let key = \"__AWSKEY__\";
+let ok = 1;
+
";

#[test]
fn parses_a_single_commit_and_file() {
    let files = parse(&fixture(LOG));
    assert_eq!(files.len(), 1);
    let f = &files[0];
    assert_eq!(f.new_name, "src/config.rs");
    assert!(f.is_new);
    assert!(!f.is_delete);
    assert!(!f.is_binary);
    assert_eq!(f.text_fragments.len(), 1);
}

#[test]
fn parses_the_commit_header() {
    let h = parse(&fixture(LOG))[0].patch_header.clone().expect("header");
    assert_eq!(h.sha, "1a2b3c4d5e6f7788990011223344556677889900");
    assert_eq!(h.author_name, "Ada Lovelace");
    assert_eq!(h.author_email, "ada@example.com");
    assert_eq!(h.author_date, "Mon Aug 11 09:15:00 2026 +0000");
    assert_eq!(
        h.message, "add config\n\nwith a second paragraph",
        "the four-space indent is stripped and blank lines preserved"
    );
}

/// `@@ -0,0 +1,3 @@` — the NEW position is what a finding's line number is
/// based on.
#[test]
fn hunk_positions_are_parsed() {
    let frag = &parse(&fixture(LOG))[0].text_fragments[0];
    assert_eq!(frag.old_position, 0);
    assert_eq!(frag.old_lines, 0);
    assert_eq!(frag.new_position, 1);
    assert_eq!(frag.new_lines, 3);
}

/// **The load-bearing behaviour.** Only ADDED lines are scanned.
#[test]
fn raw_add_returns_only_added_lines() {
    let frag = &parse(&fixture(LOG))[0].text_fragments[0];
    let raw = frag.raw(Op::Add);
    assert!(raw.contains(&aws_key()));
    assert_eq!(raw, format!("let key = \"{}\";\nlet ok = 1;\n\n", aws_key()));
}

const MIXED: &str = "\
commit aaaa
Author: A B <a@b.c>
Date:   Mon Aug 11 09:15:00 2026 +0000

    change

diff --git a/x.txt b/x.txt
index 111..222 100644
--- a/x.txt
+++ b/x.txt
@@ -10,4 +10,4 @@ fn context_heading() {
 unchanged line
-removed secret __OLDKEY__
+added secret __AWSKEY__
 trailing context
";

/// A REMOVED secret is not a new leak, and a CONTEXT line belongs to some
/// earlier commit. Both must be excluded from what the scanner sees.
#[test]
fn raw_add_excludes_deletes_and_context() {
    let frag = &parse(&fixture(MIXED))[0].text_fragments[0];
    let raw = frag.raw(Op::Add);
    assert_eq!(raw, format!("added secret {}\n", aws_key()));
    assert!(!raw.contains(&old_key()), "a removed secret must not be rescanned");
    assert!(!raw.contains("unchanged"), "context belongs to another commit");

    // The other ops are still available, just not what the scanner uses.
    assert_eq!(frag.raw(Op::Delete), format!("removed secret {}\n", old_key()));
    assert!(frag.raw(Op::Context).contains("unchanged line"));
}

/// A `@@` header may carry a section heading after the second `@@`; it is not
/// content and must not break parsing.
#[test]
fn hunk_heading_is_ignored() {
    let frag = &parse(&fixture(MIXED))[0].text_fragments[0];
    assert_eq!(frag.new_position, 10);
    // context + delete + add + context — the `@@ -10,4 +10,4 @@` counts agree.
    assert_eq!(frag.lines.len(), 4);
}

#[test]
fn detects_deleted_files() {
    let d = "\
commit bbbb
Author: A B <a@b.c>
Date:   Mon Aug 11 09:15:00 2026 +0000

    remove

diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-secret __AWSKEY__
-more
";
    let f = &parse(&fixture(d))[0];
    assert!(f.is_delete, "the git source skips deletes entirely");
    assert_eq!(f.text_fragments[0].raw(Op::Add), "", "nothing was added");
}

#[test]
fn detects_binary_files() {
    let d = "\
diff --git a/img.png b/img.png
index 111..222 100644
Binary files a/img.png and b/img.png differ
";
    let f = &parse(&fixture(d))[0];
    assert!(f.is_binary);
    assert!(f.text_fragments.is_empty());
}

#[test]
fn detects_renames() {
    let d = "\
diff --git a/old.txt b/new.txt
similarity index 95%
rename from old.txt
rename to new.txt
";
    let f = &parse(&fixture(d))[0];
    assert!(f.is_rename);
    assert_eq!(f.old_name, "old.txt");
    assert_eq!(f.new_name, "new.txt");
}

/// Several files in one commit, and several commits in one stream — each file
/// must carry the header of ITS commit, not the first one.
#[test]
fn multiple_commits_and_files() {
    let d = "\
commit c1
Author: One <1@x.y>
Date:   Mon Aug 11 09:15:00 2026 +0000

    first

diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
+aaa
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +1 @@
+bbb
commit c2
Author: Two <2@x.y>
Date:   Tue Aug 12 09:15:00 2026 +0000

    second

diff --git a/c.txt b/c.txt
--- a/c.txt
+++ b/c.txt
@@ -1 +1 @@
+ccc
";
    let files = parse(&fixture(d));
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].new_name, "a.txt");
    assert_eq!(files[1].new_name, "b.txt");
    assert_eq!(files[2].new_name, "c.txt");

    assert_eq!(files[0].patch_header.as_ref().unwrap().sha, "c1");
    assert_eq!(files[1].patch_header.as_ref().unwrap().sha, "c1");
    assert_eq!(
        files[2].patch_header.as_ref().unwrap().sha,
        "c2",
        "the third file belongs to the SECOND commit"
    );
    assert_eq!(files[2].patch_header.as_ref().unwrap().author_name, "Two");
}

/// Multiple hunks in one file each keep their own new-position.
#[test]
fn multiple_hunks_keep_their_positions() {
    let d = "\
diff --git a/x.txt b/x.txt
--- a/x.txt
+++ b/x.txt
@@ -1,2 +1,2 @@
+first
@@ -50,2 +60,2 @@
+second
";
    let f = &parse(&fixture(d))[0];
    assert_eq!(f.text_fragments.len(), 2);
    assert_eq!(f.text_fragments[0].new_position, 1);
    assert_eq!(f.text_fragments[1].new_position, 60);
    assert_eq!(f.text_fragments[1].raw(Op::Add), "second\n");
}

/// `@@ -1 +1 @@` with no counts means one line.
#[test]
fn omitted_hunk_counts_default_to_one() {
    let d = "\
diff --git a/x b/x
--- a/x
+++ b/x
@@ -5 +7 @@
+line
";
    let frag = &parse(&fixture(d))[0].text_fragments[0];
    assert_eq!(frag.old_position, 5);
    assert_eq!(frag.old_lines, 1);
    assert_eq!(frag.new_position, 7);
    assert_eq!(frag.new_lines, 1);
}

/// `\ No newline at end of file` annotates the previous line; it is not content
/// and must not be scanned as an added line.
#[test]
fn no_newline_marker_is_not_content() {
    let d = "\
diff --git a/x b/x
--- a/x
+++ b/x
@@ -1 +1 @@
+no trailing newline
\\ No newline at end of file
";
    let frag = &parse(&fixture(d))[0].text_fragments[0];
    assert_eq!(frag.lines.len(), 1);
    assert_eq!(frag.raw(Op::Add), "no trailing newline\n");
}

/// A line inside a hunk that begins with `+`/`-`/` ` is content even when the
/// rest looks like a header — a file can legitimately contain `+++ b/x`.
#[test]
fn content_that_looks_like_a_header_is_kept() {
    let d = "\
diff --git a/patch.txt b/patch.txt
--- a/patch.txt
+++ b/patch.txt
@@ -1,2 +1,2 @@
++++ b/inner
+-- not a header
";
    let frag = &parse(&fixture(d))[0].text_fragments[0];
    assert_eq!(frag.raw(Op::Add), "+++ b/inner\n-- not a header\n");
}

/// Paths with spaces survive, which is why the split looks for ` b/`.
#[test]
fn paths_with_spaces() {
    let d = "diff --git a/my dir/file name.txt b/my dir/file name.txt\n--- a/my dir/file name.txt\n+++ b/my dir/file name.txt\n@@ -1 +1 @@\n+x\n";
    let f = &parse(&fixture(d))[0];
    assert_eq!(f.new_name, "my dir/file name.txt");
}

#[test]
fn author_without_an_email_does_not_mangle_the_name() {
    let d = "commit z\nAuthor: Just A Name\nDate:   Mon Aug 11 09:15:00 2026 +0000\n\n    msg\n\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n+y\n";
    let h = parse(&fixture(d))[0].patch_header.clone().unwrap();
    assert_eq!(h.author_name, "Just A Name");
    assert_eq!(h.author_email, "");
}

/// Commit decorations (`commit <sha> (HEAD -> main)`) must not end up in the SHA.
#[test]
fn commit_decorations_are_stripped_from_the_sha() {
    let d = "commit abc123 (HEAD -> main, origin/main)\nAuthor: A <a@b>\nDate:   x\n\n    m\n\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n+y\n";
    assert_eq!(parse(&fixture(d))[0].patch_header.as_ref().unwrap().sha, "abc123");
}

#[test]
fn empty_and_garbage_input_do_not_panic() {
    assert!(parse("").is_empty());
    assert!(parse("not a diff at all\njust text\n").is_empty());
    // A truncated stream stops cleanly rather than aborting.
    assert_eq!(parse("diff --git a/x b/x\n--- a/x\n").len(), 1);
}

#[test]
fn commit_attributes_map_to_the_expected_keys() {
    let h = parse(&fixture(LOG))[0].patch_header.clone().unwrap();
    let m = commit_attributes(&h);
    assert_eq!(m["git.sha"], "1a2b3c4d5e6f7788990011223344556677889900");
    assert_eq!(m["git.author_name"], "Ada Lovelace");
    assert_eq!(m["git.author_email"], "ada@example.com");
    assert!(m["git.message"].starts_with("add config"));
}

