//! Tests for the git source.
//!
//! **The Go source has NO active tests for this module** — `sources/git_test.go`
//! is 100% commented out, with a note that the tests were flaky because they
//! moved `.git` directories around. So these are CHARACTERIZATION tests written
//! from the Go implementation's observable behaviour, and the gap is recorded in
//! PORT-TRACK.md. That makes the pure helpers (argument construction, the
//! `--log-opts` tokenizer, the stderr classifier, remote-URL normalisation) the
//! parity contract, since they are the parts whose behaviour can be pinned
//! without a live repository.
//!
//! The last test does spawn a REAL repository and a REAL `git log -p`, because a
//! source that has never actually read a repository is not a working source.

use super::git::*;
use super::*;
use std::collections::BTreeMap;

fn s(p: &str) -> String {
    p.replace('/', &std::path::MAIN_SEPARATOR.to_string())
}

// ── --log-opts tokenizer ────────────────────────────────────────────────────
// A small shell-inspired splitter. Getting this wrong means a user's
// `--log-opts` silently scans the wrong commit range.

#[test]
fn log_opts_splits_on_whitespace() {
    assert_eq!(split_git_log_opts("--all foo...").unwrap(), vec!["--all", "foo..."]);
    assert_eq!(split_git_log_opts("  a   b  ").unwrap(), vec!["a", "b"]);
    assert_eq!(split_git_log_opts("").unwrap(), Vec::<String>::new());
}

#[test]
fn log_opts_groups_quoted_text() {
    assert_eq!(
        split_git_log_opts("--author='Ada Lovelace'").unwrap(),
        vec!["--author=Ada Lovelace"],
        "quotes group and are REMOVED from the output"
    );
    assert_eq!(
        split_git_log_opts("--grep=\"two words\" --all").unwrap(),
        vec!["--grep=two words", "--all"]
    );
}

#[test]
fn log_opts_backslash_escapes_outside_single_quotes() {
    assert_eq!(split_git_log_opts(r"a\ b").unwrap(), vec!["a b"]);
    assert_eq!(split_git_log_opts(r#"a\"b"#).unwrap(), vec!["a\"b"]);
    // Inside SINGLE quotes a backslash is literal, as in a shell.
    assert_eq!(split_git_log_opts(r"'a\b'").unwrap(), vec![r"a\b"]);
}

#[test]
fn log_opts_rejects_unterminated_quote_and_escape() {
    assert!(matches!(split_git_log_opts("'unterminated"), Err(GitError::LogOpts(_))));
    assert!(matches!(split_git_log_opts("\"unterminated"), Err(GitError::LogOpts(_))));
    assert!(matches!(split_git_log_opts(r"trailing\"), Err(GitError::LogOpts(_))));
}

/// A documented quirk of the source: a standalone empty quoted token is DROPPED
/// rather than becoming an empty argument. Kept because the port is faithful,
/// not because it is obviously right.
#[test]
fn log_opts_drops_a_standalone_empty_quoted_token() {
    assert_eq!(split_git_log_opts("a '' b").unwrap(), vec!["a", "b"]);
}

// ── argument construction ───────────────────────────────────────────────────
// These are the exact commands the scanner runs. `-U0` is load-bearing: it means
// ZERO context lines, so a hunk contains only changed lines and a secret cannot
// be re-reported from context on every later commit.

#[test]
fn log_args_without_opts_use_the_full_history_defaults() {
    assert_eq!(
        git_log_args("myrepo", "").unwrap(),
        vec![
            "-C",
            &s("myrepo"),
            "log",
            "-p",
            "-U0",
            "--full-history",
            "--all",
            "--diff-filter=tuxdb",
        ]
    );
}

#[test]
fn log_args_with_opts_replace_the_defaults() {
    let args = git_log_args("myrepo", "--all foo...").unwrap();
    assert_eq!(args, vec!["-C", &s("myrepo"), "log", "-p", "-U0", "--all", "foo..."]);
    assert!(
        !args.iter().any(|a| a == "--full-history"),
        "user --log-opts REPLACE the default range, they do not extend it"
    );
}

#[test]
fn log_args_reject_malformed_opts_before_spawning_git() {
    assert!(matches!(git_log_args("r", "'oops"), Err(GitError::LogOpts(_))));
}

#[test]
fn diff_args_add_staged_only_when_asked() {
    assert_eq!(
        git_diff_args("myrepo", false),
        vec!["-C", &s("myrepo"), "diff", "-U0", "--no-ext-diff", "."]
    );
    assert_eq!(
        git_diff_args("myrepo", true),
        vec!["-C", &s("myrepo"), "diff", "-U0", "--no-ext-diff", "--staged", "."]
    );
}

#[test]
fn source_path_is_cleaned() {
    assert_eq!(git_log_args("./a/../b/", "").unwrap()[1], s("b"));
    assert_eq!(clean_path(""), ".");
    assert_eq!(clean_path("."), ".");
    assert_eq!(clean_path("a//b"), s("a/b"));
    assert_eq!(clean_path("a/./b"), s("a/b"));
    assert_eq!(clean_path("a/b/.."), "a");
    assert_eq!(clean_path("../a"), s("../a"), "a leading .. is kept — it cannot be resolved lexically");
    assert_eq!(clean_path("/../a"), s("/a"), "but a rooted .. has nowhere to go");
}

// ── stderr classification ───────────────────────────────────────────────────
// git writes NON-fatal warnings to stderr and keeps streaming the diff. Treating
// those as errors aborts a whole-history scan partway through and reports a
// clean result — the worst possible failure for a secret scanner.

#[test]
fn benign_git_warnings_do_not_abort_a_scan() {
    for line in [
        "warning: exhaustive rename detection was skipped due to too many files.",
        "warning: inexact rename detection was skipped due to too many files.",
        "you may want to set your diff.renameLimit variable to at least 4000",
        "See \"git help gc\" for manual housekeeping.",
        "Auto packing the repository in background for optimum performance.",
    ] {
        assert!(is_benign_stderr(line), "must be tolerated: {line}");
    }
}

#[test]
fn real_git_errors_are_reported() {
    for line in [
        "fatal: not a git repository (or any of the parent directories): .git",
        "fatal: bad revision 'nope'",
        "error: pathspec did not match any file(s) known to git",
    ] {
        assert!(!is_benign_stderr(line), "must NOT be swallowed: {line}");
    }
}

#[test]
fn stderr_error_joins_only_the_real_errors() {
    let lines = [
        "warning: exhaustive rename detection was skipped due to too many files.",
        "fatal: bad revision 'nope'",
        "error: another problem",
    ];
    let err = stderr_error(&lines).expect("two real errors");
    assert_eq!(err, "git stderr: fatal: bad revision 'nope'; error: another problem");
    assert!(!err.contains("rename detection"), "benign lines are excluded from the error");

    assert!(stderr_error(&[]).is_none());
    assert!(
        stderr_error(&["Auto packing the repository in background for optimum performance."]).is_none(),
        "an all-benign stderr is NOT an error"
    );
}

// ── remote URL normalisation ────────────────────────────────────────────────
// The remote URL ends up in a finding's link. A credential leaking into that
// link would be a leak reported by the leak scanner.

#[test]
fn ssh_remotes_are_rewritten_to_https() {
    assert_eq!(
        normalize_remote_url("git@github.com:owner/repo.git").unwrap(),
        "https://github.com/owner/repo"
    );
    assert_eq!(
        normalize_remote_url("git@gitlab.example.com:group/sub/repo").unwrap(),
        "https://gitlab.example.com/group/sub/repo"
    );
    assert_eq!(
        normalize_remote_url("git@github.com:22/owner/repo.git").unwrap(),
        "https://github.com/owner/repo",
        "an ssh port is dropped, not turned into a URL port"
    );
}

#[test]
fn https_remotes_lose_the_git_suffix() {
    assert_eq!(
        normalize_remote_url("https://github.com/owner/repo.git").unwrap(),
        "https://github.com/owner/repo"
    );
    assert_eq!(
        normalize_remote_url("  https://github.com/owner/repo\n").unwrap(),
        "https://github.com/owner/repo",
        "git's output is trimmed"
    );
}

/// **Load-bearing.** A remote configured with an embedded token must never carry
/// that token into a finding.
#[test]
fn userinfo_is_stripped_from_the_remote() {
    let u = normalize_remote_url("https://user:ghp_SECRETTOKENVALUE@github.com/owner/repo.git")
        .unwrap();
    assert_eq!(u, "https://github.com/owner/repo");
    assert!(!u.contains("ghp_"), "a credential must never reach a finding link");
    assert!(!u.contains("user"));
}

#[test]
fn platform_is_recognised_from_the_host() {
    use scm::Platform;
    assert_eq!(platform_from_host("github.com"), Platform::GitHub);
    assert_eq!(platform_from_host("GitHub.COM"), Platform::GitHub, "case-insensitive");
    assert_eq!(platform_from_host("gitlab.com"), Platform::GitLab);
    assert_eq!(platform_from_host("dev.azure.com"), Platform::AzureDevOps);
    assert_eq!(platform_from_host("visualstudio.com"), Platform::AzureDevOps);
    assert_eq!(platform_from_host("gitea.com"), Platform::Gitea);
    assert_eq!(platform_from_host("code.forgejo.org"), Platform::Gitea);
    assert_eq!(platform_from_host("codeberg.org"), Platform::Gitea);
    assert_eq!(platform_from_host("bitbucket.org"), Platform::Bitbucket);
    assert_eq!(
        platform_from_host("git.internal.corp"), Platform::Unknown,
        "a self-hosted host is Unknown, not a guess"
    );
}

/// `git.date` is normalised to RFC 3339 in UTC, so a finding's timestamp does not
/// depend on the committer's timezone.
#[test]
fn commit_dates_are_normalised_to_utc_rfc3339() {
    assert_eq!(
        parse_git_date("Mon Aug 11 09:15:00 2026 +0000").unwrap(),
        "2026-08-11T09:15:00Z"
    );
    assert_eq!(
        parse_git_date("Tue Aug 12 01:30:00 2026 +0300").unwrap(),
        "2026-08-11T22:30:00Z",
        "a positive offset moves BACK to UTC, here across midnight"
    );
    assert_eq!(
        parse_git_date("Mon Dec 31 20:00:00 2029 -0800").unwrap(),
        "2030-01-01T04:00:00Z",
        "a negative offset can roll the year over"
    );
    assert_eq!(
        parse_git_date("Wed Feb 28 23:00:00 2024 -0200").unwrap(),
        "2024-02-29T01:00:00Z",
        "2024 is a leap year — Feb has 29 days"
    );
    assert_eq!(
        parse_git_date("Sat Feb 28 23:00:00 2026 -0200").unwrap(),
        "2026-03-01T01:00:00Z",
        "2026 is not"
    );
    assert!(parse_git_date("").is_none(), "an absent date yields no attribute");
    assert!(parse_git_date("not a date").is_none());
}

// ── the source itself ───────────────────────────────────────────────────────

/// AWS-shaped key, generated at runtime — no literal token is committed (see the
/// `testkeys` crate). The fixtures below carry `__AWSKEY__` as a placeholder
/// because they are `const` and cannot call a function.
fn aws_key() -> String {
    testkeys::aws(1)
}

/// [`LOG`] with its placeholder resolved.
fn log_fixture() -> String {
    LOG.replace("__AWSKEY__", &aws_key())
}

const LOG: &str = "\
commit 1a2b3c4d5e6f7788990011223344556677889900
Author: Ada Lovelace <ada@example.com>
Date:   Mon Aug 11 09:15:00 2026 +0000

    add config

diff --git a/src/config.rs b/src/config.rs
new file mode 100644
--- /dev/null
+++ b/src/config.rs
@@ -0,0 +1,2 @@
+let key = \"__AWSKEY__\";
+let ok = 1;
";

fn collect(g: &Git) -> Vec<Fragment> {
    let mut out = Vec::new();
    let mut f = |r: Result<Fragment, GitError>| -> Result<(), GitError> {
        out.push(r?);
        Ok(())
    };
    g.fragments(&mut f).expect("fragments");
    out
}

#[test]
fn yields_only_added_lines_with_commit_attributes() {
    let g = Git::from_diff_text(&log_fixture());
    let frags = collect(&g);
    assert_eq!(frags.len(), 1);
    let f = &frags[0];

    assert_eq!(f.raw, format!("let key = \"{}\";\nlet ok = 1;\n", aws_key()));
    assert_eq!(f.start_line, 1, "the hunk's NEW position, verbatim");

    assert_eq!(f.attr(ATTR_GIT_SHA), "1a2b3c4d5e6f7788990011223344556677889900");
    assert_eq!(f.attr(ATTR_GIT_MESSAGE), "add config");
    assert_eq!(f.attr(ATTR_RESOURCE), RESOURCE_GIT_PATCH_CONTENT);
    assert_eq!(f.attr(ATTR_PATH), "src/config.rs");
    assert_eq!(f.attr(ATTR_GIT_AUTHOR_NAME), "Ada Lovelace");
    assert_eq!(f.attr(ATTR_GIT_AUTHOR_EMAIL), "ada@example.com");
    assert_eq!(f.attr(ATTR_GIT_DATE), "2026-08-11T09:15:00Z");
}

#[test]
fn remote_attributes_appear_only_when_a_remote_is_known() {
    let plain = collect(&Git::from_diff_text(&log_fixture()));
    assert_eq!(plain[0].attr(ATTR_GIT_REMOTE_URL), "");
    assert_eq!(plain[0].attr(ATTR_GIT_PLATFORM), "");

    let mut g = Git::from_diff_text(&log_fixture());
    g.remote_url = "https://github.com/owner/repo".to_string();
    g.platform = scm::Platform::GitHub;
    let frags = collect(&g);
    assert_eq!(frags[0].attr(ATTR_GIT_REMOTE_URL), "https://github.com/owner/repo");
    assert_eq!(frags[0].attr(ATTR_GIT_PLATFORM), "github");
}

/// A file DELETED in a commit yields nothing — its content is not being
/// introduced, so it is not a new leak.
#[test]
fn deleted_files_are_skipped() {
    let d = "\
commit bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111
Author: A B <a@b.c>
Date:   Mon Aug 11 09:15:00 2026 +0000

    remove

diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1,1 +0,0 @@
-secret __AWSKEY__
";
    assert!(collect(&Git::from_diff_text(d)).is_empty());
}

/// Binary files are skipped. In Go an ARCHIVE binary is instead re-read as a
/// blob and descended into; that path is deferred with the rest of archive
/// support, so this port skips every binary. It is a MISSED-FINDING gap (a
/// secret inside a committed .zip), not a false-positive one — recorded in
/// PORT-TRACK.md.
#[test]
fn binary_files_are_skipped() {
    let d = "\
diff --git a/img.png b/img.png
index 111..222 100644
Binary files a/img.png and b/img.png differ
";
    assert!(collect(&Git::from_diff_text(d)).is_empty());
}

/// The prefilter runs BEFORE any fragment is built, so a skipped path costs
/// nothing. It sees the commit attributes, including the path.
#[test]
fn should_skip_drops_a_file_before_any_fragment_is_built() {
    let skip = |attrs: &BTreeMap<String, String>| -> bool {
        attrs.get(ATTR_PATH).map(|p| p.ends_with(".rs")) == Some(true)
    };
    let mut g = Git::from_diff_text(&log_fixture());
    g.should_skip = Some(&skip);
    assert!(collect(&g).is_empty(), "src/config.rs matches the skip predicate");

    let keep = |_: &BTreeMap<String, String>| false;
    let mut g2 = Git::from_diff_text(&log_fixture());
    g2.should_skip = Some(&keep);
    assert_eq!(collect(&g2).len(), 1);
}

/// `git diff` (working tree) has no commit header at all. The source must still
/// yield the added lines and still set the path — just without commit
/// attributes, and WITHOUT consulting the prefilter (which is what Go does,
/// because the prefilter call sits inside the header branch).
#[test]
fn a_diff_without_a_commit_header_still_yields_fragments() {
    let d = "\
diff --git a/x.txt b/x.txt
--- a/x.txt
+++ b/x.txt
@@ -1 +1 @@
+added __AWSKEY__
";
    let skip_everything = |_: &BTreeMap<String, String>| true;
    let mut g = Git::from_diff_text(d);
    g.should_skip = Some(&skip_everything);
    let frags = collect(&g);
    assert_eq!(frags.len(), 1, "the prefilter is not consulted without a commit header");
    assert_eq!(frags[0].attr(ATTR_PATH), "x.txt");
    assert_eq!(frags[0].attr(ATTR_GIT_SHA), "");
}

#[test]
fn multiple_hunks_and_files_each_get_their_own_fragment() {
    let d = "\
commit cccc1111cccc1111cccc1111cccc1111cccc1111
Author: A B <a@b.c>
Date:   Mon Aug 11 09:15:00 2026 +0000

    two files

diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
+aaa
@@ -50 +60 @@
+bbb
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +7 @@
+ccc
";
    let frags = collect(&Git::from_diff_text(d));
    assert_eq!(frags.len(), 3);
    assert_eq!(
        frags.iter().map(|f| (f.attr(ATTR_PATH), f.start_line)).collect::<Vec<_>>(),
        vec![("a.txt", 1), ("a.txt", 60), ("b.txt", 7)]
    );
    // Each fragment carries its OWN attribute map — mutating one must not
    // rewrite the path on its sibling.
    assert_eq!(frags[0].attr(ATTR_PATH), "a.txt");
    assert_eq!(frags[2].attr(ATTR_PATH), "b.txt");
}

/// An empty hunk (all deletions) yields a fragment with EMPTY raw rather than
/// being dropped — matching Go, which builds a fragment per text fragment
/// unconditionally.
#[test]
fn a_hunk_with_no_additions_still_yields_an_empty_fragment() {
    let d = "\
diff --git a/x.txt b/x.txt
--- a/x.txt
+++ b/x.txt
@@ -1,2 +1,0 @@
-gone one
-gone two
";
    let frags = collect(&Git::from_diff_text(d));
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].raw, "");
}

// ── a REAL repository ───────────────────────────────────────────────────────

/// **Regression test for an upstream defect.** The isolation environment must
/// let git actually RUN.
///
/// Go sets `GIT_CONFIG_GLOBAL=NUL` on Windows; Git for Windows rejects that with
/// `fatal: unable to access 'NUL': Invalid argument` and exits 128 having
/// emitted nothing — so the Go binary reports "no leaks found" for a repository
/// that contains a live-format AWS key. This asserts the env we pass is one git
/// accepts. Against the pre-fix value it fails with exit 128.
#[test]
fn the_isolation_environment_does_not_break_git() {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["--no-pager", "version"]);
    for (k, v) in git_config_isolation_env() {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("git must be on PATH");
    assert!(
        out.status.success(),
        "git rejected the isolation environment: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );

    // And the values are the ones that were measured to work.
    let env = git_config_isolation_env();
    assert_eq!(env["GIT_CONFIG_GLOBAL"], "/dev/null");
    assert_eq!(env["GIT_CONFIG_SYSTEM"], "/dev/null");
    assert_eq!(env["GIT_TERMINAL_PROMPT"], "0", "a scan must never block on a prompt");
}

/// Build an actual git repository, commit a fake credential, and read it back
/// through `git log -p`. Everything above tests parsing; this tests that the
/// source RUNS — spawns git, survives the isolation environment, and produces a
/// fragment carrying the real commit's SHA.
#[test]
fn reads_a_real_repository_end_to_end() {
    let dir = std::env::temp_dir().join(format!("betterleaks-git-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp repo dir");

    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("git must be on PATH to test the git source");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    git(&["init", "--quiet"]);
    git(&["config", "user.name", "Test User"]);
    git(&["config", "user.email", "test@example.com"]);
    std::fs::write(dir.join("creds.txt"), format!("aws_key = {}\n", aws_key())).unwrap();
    git(&["add", "creds.txt"]);
    git(&["commit", "--quiet", "-m", "add creds"]);

    let src = dir.to_string_lossy().to_string();
    let g = Git::from_log(&src, "").expect("git log -p must succeed on a real repo");
    let frags = collect(&g);

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(frags.len(), 1, "one file, one hunk");
    let f = &frags[0];
    assert_eq!(f.raw, format!("aws_key = {}\n", aws_key()));
    assert_eq!(f.attr(ATTR_PATH), "creds.txt");
    assert_eq!(f.attr(ATTR_GIT_MESSAGE), "add creds");
    assert_eq!(f.attr(ATTR_GIT_AUTHOR_NAME), "Test User");
    assert_eq!(f.attr(ATTR_GIT_AUTHOR_EMAIL), "test@example.com");
    assert_eq!(f.attr(ATTR_GIT_SHA).len(), 40, "a real commit sha");
    assert!(
        f.attr(ATTR_GIT_DATE).ends_with('Z'),
        "the real commit date normalised to UTC, got {:?}",
        f.attr(ATTR_GIT_DATE)
    );
    assert_eq!(f.start_line, 1);
}

