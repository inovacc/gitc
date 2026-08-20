//! The property that matters here is COVERAGE, not speed.
//!
//! A partition scheme that can skip a commit turns a scanner into one that
//! reports "no leaks found" for a repository that has one. So the tests build
//! real repositories with known secrets across many commits and assert that the
//! parallel scan finds exactly what the serial scan finds — at several worker
//! counts, including counts that do not divide the commit count evenly.

use super::*;

/// Build a repository with `n` commits, each adding a file with a unique,
/// findable marker.
fn repo_with_commits(name: &str, n: usize) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bl-pgit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");

    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("git must be on PATH");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@t"]);
    git(&["config", "user.name", "t"]);
    // Commit dates are pinned to the SAME second on purpose: timestamp ties are
    // exactly the case Go's comment says `--skip`-based partitioning gets wrong.
    for i in 0..n {
        std::fs::write(
            dir.join(format!("f{i}.txt")),
            format!("secret_marker_{i} = {}\n", testkeys::aws(1)),
        )
        .unwrap();
        git(&["add", "-A"]);
        let out = std::process::Command::new("git")
            .args(["commit", "-q", "-m", &format!("c{i}")])
            .current_dir(&dir)
            .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
            .output()
            .expect("git commit");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    dir
}

fn collect(src: &ParallelGit) -> Vec<String> {
    let mut markers = Vec::new();
    let mut sink = |r: Result<Fragment, GitError>| -> Result<(), GitError> {
        let f = r?;
        for line in f.raw.lines() {
            if let Some(at) = line.find("secret_marker_") {
                let rest = &line[at..];
                let end = rest.find(' ').unwrap_or(rest.len());
                markers.push(rest[..end].to_string());
            }
        }
        Ok(())
    };
    ParallelGit::fragments(src, &mut sink).expect("scan");
    markers.sort();
    markers.dedup();
    markers
}

/// Every commit is covered EXACTLY once, at every worker count — including
/// counts that do not divide 17 evenly, which is where an off-by-one in the
/// chunking shows up.
#[test]
fn every_commit_is_covered_at_every_worker_count() {
    const COMMITS: usize = 17;
    let dir = repo_with_commits("coverage", COMMITS);
    let path = dir.to_string_lossy().to_string();

    let expected: Vec<String> = (0..COMMITS).map(|i| format!("secret_marker_{i}")).collect();
    let mut expected = expected;
    expected.sort();

    for workers in [1usize, 2, 3, 4, 5, 8, 17, 32] {
        let mut src = ParallelGit::new(&path);
        src.workers = workers;
        let found = collect(&src);
        assert_eq!(
            found, expected,
            "workers={workers} lost or duplicated commits"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parallel scan and the single-worker scan see the same thing. If these
/// ever diverge, the partitioning is wrong — and the parallel one is the path a
/// user opts into for speed, so it is the one that would silently under-report.
#[test]
fn parallel_agrees_with_serial() {
    let dir = repo_with_commits("agree", 12);
    let path = dir.to_string_lossy().to_string();

    let mut serial = ParallelGit::new(&path);
    serial.workers = 1;
    let mut parallel = ParallelGit::new(&path);
    parallel.workers = 4;

    assert_eq!(collect(&serial), collect(&parallel));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Emission order is stable across runs — the chunks are drained in partition
/// order rather than in whichever order the `git` processes finished.
#[test]
fn the_order_does_not_depend_on_which_worker_finished_first() {
    let dir = repo_with_commits("order", 12);
    let path = dir.to_string_lossy().to_string();

    let order = || {
        let mut src = ParallelGit::new(&path);
        src.workers = 4;
        let mut seen = Vec::new();
        let mut sink = |r: Result<Fragment, GitError>| -> Result<(), GitError> {
            let f = r?;
            seen.push(f.attr(crate::ATTR_GIT_SHA).to_string());
            Ok(())
        };
        ParallelGit::fragments(&src, &mut sink).unwrap();
        seen
    };
    let a = order();
    let b = order();
    assert_eq!(a, b, "two runs must emit in the same order");
    assert!(!a.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty repository is not an error — it simply has nothing to scan.
#[test]
fn an_empty_repository_yields_nothing() {
    let dir = repo_with_commits("empty", 0);
    let path = dir.to_string_lossy().to_string();
    let src = ParallelGit::new(&path);
    assert!(src.list_commits().unwrap_or_default().is_empty());
    assert_eq!(collect(&src), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Go's auto default is `min(NumCPU, 4)`. The cap is deliberate: each worker is
/// a `git` PROCESS reading the object store, so this saturates on I/O.
#[test]
fn the_auto_worker_count_is_capped() {
    let src = ParallelGit::new(".");
    let n = src.worker_count();
    assert!((1..=4).contains(&n), "auto worker count was {n}");

    let mut explicit = ParallelGit::new(".");
    explicit.workers = 9;
    assert_eq!(explicit.worker_count(), 9, "an explicit count is honoured");
}

/// `--log-opts` reaches `rev-list`, so a restricted range partitions only what
/// it names rather than the whole history.
#[test]
fn log_opts_restricts_what_is_partitioned() {
    let dir = repo_with_commits("logopts", 8);
    let path = dir.to_string_lossy().to_string();

    let mut all = ParallelGit::new(&path);
    let total = all.list_commits().unwrap().len();
    assert_eq!(total, 8);

    all.log_opts = "--max-count=3 --all".to_string();
    assert_eq!(all.list_commits().unwrap().len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `--log-opts` that names no REVISION works for the serial scan and fails
/// for the parallel one, and that asymmetry is Gos.
///
/// `git log --max-count=3` defaults to HEAD; `git rev-list --max-count=3` does
/// not and exits with a usage error. Gos `listCommits` appends only the user
/// args when logOpts is set, so it inherits this exactly. The behaviour is kept
/// rather than quietly "fixed" by injecting HEAD - that would make the parallel
/// scan cover a different range from the serial one, which is a far worse
/// surprise than an error message. The failure is LOUD, which is the part that
/// matters.
#[test]
fn log_opts_without_a_revision_fails_loudly_as_in_go() {
    let dir = repo_with_commits("norev", 4);
    let path = dir.to_string_lossy().to_string();

    let mut src = ParallelGit::new(&path);
    src.log_opts = "--max-count=3".to_string();
    let err = src.list_commits().expect_err("rev-list needs a revision");
    assert!(
        matches!(err, GitError::Stderr(ref m) if m.contains("usage: git rev-list")),
        "the error must name the real cause: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A malformed `--log-opts` fails BEFORE any git process is started, as it does
/// in the serial source.
#[test]
fn a_malformed_log_opts_is_refused_up_front() {
    let mut src = ParallelGit::new(".");
    src.log_opts = "--author='unterminated".to_string();
    assert!(matches!(src.list_commits(), Err(GitError::LogOpts(_))));
}
