//! Port of Go `sources/parallel_git.go` — scanning a repository's history with
//! several `git log -p` processes at once.
//!
//! ## Why partition by SHA rather than by `--skip`
//!
//! The obvious split is `--skip N --max-count M` per worker. Go's comment says
//! why that is wrong and this port keeps the same approach: on a repository
//! with timestamp ties, `git log`'s ordering is not stable enough to guarantee
//! that N ranges cover every commit exactly once. Commits are enumerated ONCE
//! with `git rev-list`, partitioned, and each worker is handed its own SHAs via
//! `--no-walk --stdin`.
//!
//! That guarantees deterministic, non-overlapping coverage — which for a
//! secret scanner is not a nicety. A partition scheme that can skip a commit is
//! a scanner that reports "no leaks found" for a repository that has one.
//!
//! ## Ordering
//!
//! Findings come back grouped BY WORKER rather than in history order, so the
//! chunks are collected and emitted in partition order. Go does not do this —
//! its workers write to a shared callback as they finish — but Go's own file
//! walk is already non-deterministic, whereas this port keeps reports
//! diffable between runs.

use crate::git::{clean_path, split_git_log_opts};
use crate::{Fragment, FragmentsFunc, Git, GitError, Source};
use std::sync::{Arc, Mutex};

/// Go `ParallelGit`.
pub struct ParallelGit<'a> {
    pub repo_path: String,
    pub log_opts: String,
    /// Go `Workers`; 0 means auto.
    pub workers: usize,
    pub max_archive_depth: usize,
    pub platform: scm::Platform,
    pub remote_url: String,
    pub should_skip: Option<crate::SkipFunc<'a>>,
}

impl<'a> ParallelGit<'a> {
    pub fn new(repo_path: &str) -> ParallelGit<'a> {
        ParallelGit {
            repo_path: repo_path.to_string(),
            log_opts: String::new(),
            workers: 0,
            max_archive_depth: 0,
            platform: scm::Platform::Unknown,
            remote_url: String::new(),
            should_skip: None,
        }
    }

    /// Go `workers()` — `min(NumCPU, 4)` when unset.
    ///
    /// Capped at 4 deliberately: each worker is a `git` PROCESS reading the
    /// object store, so this is I/O bound long before it is CPU bound, and more
    /// processes past that point just contend.
    pub fn worker_count(&self) -> usize {
        if self.workers > 0 {
            return self.workers;
        }
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(4)
    }

    /// Go `listCommits` — every commit SHA, in one `rev-list` so the order is
    /// fixed for the partition.
    pub fn list_commits(&self) -> Result<Vec<String>, GitError> {
        let mut args = vec![
            "-C".to_string(),
            clean_path(&self.repo_path),
            "rev-list".to_string(),
        ];
        if self.log_opts.trim().is_empty() {
            args.push("--all".to_string());
        } else {
            args.extend(split_git_log_opts(&self.log_opts)?);
        }

        let out = Git::output(&args)?;
        let text = out.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        Ok(text.lines().map(|l| l.trim().to_string()).collect())
    }

    /// Go `(*ParallelGit).Fragments`.
    pub fn fragments(&self, yield_fn: FragmentsFunc<'_, GitError>) -> Result<(), GitError> {
        let commits = self.list_commits()?;
        let count = commits.len();
        if count == 0 {
            return Ok(());
        }

        let mut workers = self.worker_count();
        if workers > count {
            workers = count;
        }
        // Go: a single worker is the plain `git log`, with none of the
        // partitioning overhead.
        if workers <= 1 {
            return self.run_single(yield_fn);
        }

        let chunk_size = count.div_ceil(workers);
        logging::info()
            .int("commits", count as i64)
            .int("workers", workers as i64)
            .int("chunk_size", chunk_size as i64)
            .msg("parallel git scan");

        // Each worker collects its own fragments; they are emitted afterwards
        // in partition order so the report does not depend on which `git`
        // process finished first.
        let chunks: Vec<Vec<String>> = commits
            .chunks(chunk_size)
            .map(|c| c.to_vec())
            .collect();
        let collected: Vec<Arc<Mutex<Vec<Fragment>>>> =
            chunks.iter().map(|_| Arc::new(Mutex::new(Vec::new()))).collect();
        let first_error: Arc<Mutex<Option<GitError>>> = Arc::new(Mutex::new(None));

        std::thread::scope(|scope| {
            for (chunk, sink) in chunks.iter().zip(collected.iter()) {
                let sink = sink.clone();
                let first_error = first_error.clone();
                let repo_path = self.repo_path.clone();
                let max_archive_depth = self.max_archive_depth;
                let platform = self.platform;
                let remote_url = self.remote_url.clone();
                scope.spawn(move || {
                    let mut git = match Git::from_log_commits(&repo_path, chunk) {
                        Ok(g) => g,
                        Err(e) => {
                            let mut slot = first_error.lock().unwrap_or_else(|p| p.into_inner());
                            if slot.is_none() {
                                *slot = Some(e);
                            }
                            return;
                        }
                    };
                    git.max_archive_depth = max_archive_depth;
                    git.platform = platform;
                    git.remote_url = remote_url;
                    // should_skip is NOT handed to the worker: it is a
                    // `&dyn Fn` from the detector and is not `Sync`, so it
                    // cannot cross a thread boundary. The filter is applied on
                    // the emit path below instead, which yields the same set -
                    // it costs a fragment that is built and then dropped, and
                    // buys not making every source`s skip callback `Sync`.
                    let mut push = |r: Result<Fragment, GitError>| -> Result<(), GitError> {
                        let f = r?;
                        sink.lock().unwrap_or_else(|p| p.into_inner()).push(f);
                        Ok(())
                    };
                    if let Err(e) = Source::fragments(&git, &mut push) {
                        let mut slot = first_error.lock().unwrap_or_else(|p| p.into_inner());
                        if slot.is_none() {
                            *slot = Some(e);
                        }
                    }
                });
            }
        });

        // A worker failure is reported AFTER the fragments that did arrive are
        // emitted: a partial history is still worth scanning, and the caller
        // decides what a partial scan means for the exit code.
        for sink in &collected {
            let mut fragments = sink.lock().unwrap_or_else(|p| p.into_inner());
            for f in fragments.drain(..) {
                if let Some(skip) = self.should_skip {
                    if skip(&f.attributes) {
                        continue;
                    }
                }
                yield_fn(Ok(f))?;
            }
        }
        if let Some(e) = first_error.lock().unwrap_or_else(|p| p.into_inner()).take() {
            return Err(e);
        }
        Ok(())
    }

    /// Go `runSingleWorker`.
    fn run_single(&self, yield_fn: FragmentsFunc<'_, GitError>) -> Result<(), GitError> {
        let mut git = Git::from_log(&self.repo_path, &self.log_opts)?;
        git.max_archive_depth = self.max_archive_depth;
        git.platform = self.platform;
        git.remote_url = self.remote_url.clone();
        git.should_skip = self.should_skip;
        git.fragments(yield_fn)
    }
}

impl Source for ParallelGit<'_> {
    type Error = GitError;

    fn fragments(&self, yield_fn: FragmentsFunc<'_, Self::Error>) -> Result<(), Self::Error> {
        ParallelGit::fragments(self, yield_fn)
    }
}

#[cfg(test)]
mod tests;
