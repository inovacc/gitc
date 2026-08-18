//! End-to-end history-rewrite orchestrator (Rust port of git-filter-repo's pipeline).
//!
//! End-to-end history rewrite: run the fresh-clone safety check, then stream
//! `git fast-export` through the codec + transform callbacks into `git
//! fast-import`, and finally run cleanup. On dry-run the import stream is
//! discarded and the repo is left untouched.
//!
//! Git is driven by subprocessing a resolved REAL git (`Options.git_bin` or
//! [`super::gitutils::default_git_binary`]) — NOT the lensr_git shim, which a bare
//! `git` would re-enter. The parser reads the export child's stdout and writes the
//! import child's stdin on ONE thread; the import child's stdout is `null`, so the
//! single-threaded pump cannot deadlock. Child stderr is drained on side threads.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::io::{self, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::thread::JoinHandle;

use super::blobfilter::replace_blob_text;
use super::commitfilter::{CommitFilter, PruneMode};
use super::gitutils::{self, default_git_binary};
use super::parser::{Callbacks, FastExportParser};
use super::pathfilter::filter_files;
use super::pathspec::PathSpec;
use super::records::{Blob, Commit};
use super::replacetext::ReplaceRules;
use super::sanity::{sanity_check, SanityCheckError};

/// The fixed flags git-filter-repo passes to fast-export so the stream carries
/// enough information to be losslessly re-imported.
const FAST_EXPORT_FLAGS: &[&str] = &[
    "fast-export",
    "--show-original-ids",
    "--reference-excluded-parents",
    "--signed-tags=strip",
    "--tag-of-filtered-object=rewrite",
    "--fake-missing-tagger",
    "--use-done-feature",
];

/// Configuration for a single history-rewriting run.
#[derive(Default)]
pub struct Options<'a> {
    /// The repository to rewrite (commands run with `git -C repo_dir`).
    pub repo_dir: String,
    /// The git executable to invoke; empty → [`default_git_binary`].
    pub git_bin: String,
    /// Refs / rev-list args to limit the rewrite; empty → `--all`.
    pub refs: Vec<String>,
    /// When set, filters/renames file paths in every commit.
    pub paths: Option<&'a PathSpec>,
    /// When non-empty, applies textual substitutions to blob contents.
    pub replace_text: Option<&'a ReplaceRules>,
    /// How commits that become empty are handled.
    pub prune: PruneMode,
    /// Bypass the fresh-clone sanity check.
    pub force: bool,
    /// Run the export + transforms but discard the import stream (repo unchanged).
    pub dry_run: bool,
}

impl Default for PruneMode {
    fn default() -> Self {
        PruneMode::Auto
    }
}

/// An error from a rewrite run.
#[derive(Debug)]
pub enum PipelineError {
    Layout(String),
    Sanity(SanityCheckError),
    Spawn(String),
    Callback(String),
    Export(String),
    Import(String),
    Stream(String),
    Cleanup(String),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::Layout(m) => write!(f, "filterrepo: resolving repository layout: {m}"),
            PipelineError::Sanity(e) => write!(f, "{e}"),
            PipelineError::Spawn(m) => write!(f, "{m}"),
            PipelineError::Callback(m) => f.write_str(m),
            PipelineError::Export(m) => f.write_str(m),
            PipelineError::Import(m) => f.write_str(m),
            PipelineError::Stream(m) => f.write_str(m),
            PipelineError::Cleanup(m) => f.write_str(m),
        }
    }
}

impl Error for PipelineError {}

/// Rewrite the repository described by `opts`.
pub fn run(opts: &Options) -> Result<(), PipelineError> {
    let git_bin = if opts.git_bin.is_empty() {
        default_git_binary()
    } else {
        opts.git_bin.clone()
    };

    let layout = gitutils::repo_layout(&git_bin, &opts.repo_dir)
        .map_err(|e| PipelineError::Layout(e.to_string()))?;
    sanity_check(&git_bin, &opts.repo_dir, opts.force).map_err(PipelineError::Sanity)?;

    let refs: Vec<String> = if opts.refs.is_empty() {
        vec!["--all".to_string()]
    } else {
        opts.refs.clone()
    };

    // --- start fast-export ---
    let mut export_args = vec!["-C".to_string(), opts.repo_dir.clone()];
    export_args.extend(FAST_EXPORT_FLAGS.iter().map(|s| s.to_string()));
    export_args.extend(refs);

    let mut export = Command::new(&git_bin)
        .args(&export_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PipelineError::Spawn(format!("filterrepo: starting fast-export: {e}")))?;
    let export_out = export.stdout.take().expect("export stdout");
    let export_err_h = drain(export.stderr.take().expect("export stderr"));

    // --- start fast-import (unless dry-run) ---
    let mut import: Option<Child> = None;
    let mut import_err_h: Option<JoinHandle<Vec<u8>>> = None;
    let sink: Box<dyn Write> = if opts.dry_run {
        Box::new(io::sink())
    } else {
        let import_args = [
            "-C",
            &opts.repo_dir,
            "-c",
            "core.ignorecase=false",
            "fast-import",
            "--force",
            "--quiet",
        ];
        match Command::new(&git_bin)
            .args(import_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                let stdin = child.stdin.take().expect("import stdin");
                import_err_h = Some(drain(child.stderr.take().expect("import stderr")));
                import = Some(child);
                Box::new(stdin)
            }
            Err(e) => {
                // Abort the already-started export without deadlocking: kill it,
                // drain its stdout so Wait can return, then wait.
                let _ = export.kill();
                let mut eo = export_out;
                let _ = io::copy(&mut eo, &mut io::sink());
                let _ = export.wait();
                return Err(PipelineError::Spawn(format!(
                    "filterrepo: starting fast-import: {e}"
                )));
            }
        }
    };

    // --- pump: parse export stdout, transform, write import stdin ---
    let mut parser = FastExportParser::new();
    let cb_err: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let run_err = {
        let cf = CommitFilter::new(opts.prune);
        let cb = build_callbacks(cf, opts.paths, opts.replace_text, cb_err.clone());
        // `sink` (the import stdin) is dropped when run returns, signaling EOF.
        parser.run(BufReader::new(export_out), sink, cb).err()
    };

    // --- wait for both children + collect stderr ---
    let export_ok = export.wait().map(|s| s.success()).unwrap_or(false);
    let export_stderr = join_stderr(Some(export_err_h));

    let (import_ran, import_ok, import_stderr) = match import {
        Some(mut child) => {
            let ok = child.wait().map(|s| s.success()).unwrap_or(false);
            (true, ok, join_stderr(import_err_h))
        }
        None => (false, true, String::new()),
    };

    let cb_err_val = cb_err.borrow().clone();
    if let Some(e) = aggregate(
        cb_err_val,
        run_err,
        export_ok,
        &export_stderr,
        import_ran,
        import_ok,
        &import_stderr,
    ) {
        return Err(e);
    }

    if opts.dry_run {
        return Ok(());
    }

    super::cleanup::cleanup(&git_bin, &opts.repo_dir, layout.bare)
        .map_err(|e| PipelineError::Cleanup(e.to_string()))?;
    Ok(())
}

/// Wire the ported transforms onto a shared [`CommitFilter`]. The `cb_err` cell
/// holds the first error raised inside a callback (callbacks cannot return one).
fn build_callbacks<'a>(
    mut cf: CommitFilter,
    paths: Option<&'a PathSpec>,
    rules: Option<&'a ReplaceRules>,
    cb_err: Rc<RefCell<Option<String>>>,
) -> Callbacks<'a> {
    let mut cb = Callbacks::default();

    if let Some(rules) = rules {
        if !rules.empty() {
            cb.blob = Some(Box::new(move |b: &mut Blob| replace_blob_text(b, rules)));
        }
    }

    cb.commit = Some(Box::new(move |c: &mut Commit| {
        if cb_err.borrow().is_some() {
            c.el.skip();
            return;
        }
        // Capture original emptiness BEFORE filtering (PruneAuto must not prune a
        // commit the author intentionally made empty).
        let had_file_changes = !c.file_changes.is_empty();
        if let Some(paths) = paths {
            if let Err(e) = filter_files(c, paths) {
                *cb_err.borrow_mut() = Some(format!("filterrepo: filtering files: {e}"));
                c.el.skip();
                return;
            }
        }
        cf.tweak(c, had_file_changes);
    }));

    cb
}

/// Combine every failure surface into a single error, favouring the
/// earliest/most-specific cause and attaching captured stderr.
fn aggregate(
    cb_err: Option<String>,
    run_err: Option<super::parser::ParseError>,
    export_ok: bool,
    export_stderr: &str,
    import_ran: bool,
    import_ok: bool,
    import_stderr: &str,
) -> Option<PipelineError> {
    if let Some(e) = cb_err {
        return Some(PipelineError::Callback(e));
    }
    if !export_ok {
        return Some(PipelineError::Export(format!(
            "filterrepo: fast-export failed{}",
            stderr_suffix(export_stderr)
        )));
    }
    if import_ran && !import_ok {
        return Some(PipelineError::Import(format!(
            "filterrepo: fast-import failed{}",
            stderr_suffix(import_stderr)
        )));
    }
    if let Some(re) = run_err {
        if !import_stderr.trim().is_empty() {
            return Some(PipelineError::Stream(format!(
                "filterrepo: stream error: {re}{}",
                stderr_suffix(import_stderr)
            )));
        }
        return Some(PipelineError::Stream(format!(
            "filterrepo: stream error: {re}"
        )));
    }
    None
}

fn stderr_suffix(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        String::new()
    } else {
        format!(": {s}")
    }
}

/// Drain a child stream on a side thread so a full stderr pipe never deadlocks.
fn drain<R: Read + Send + 'static>(mut r: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

fn join_stderr(h: Option<JoinHandle<Vec<u8>>>) -> String {
    match h {
        Some(handle) => String::from_utf8_lossy(&handle.join().unwrap_or_default()).into_owned(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fr-pipe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // A dry-run on a fresh, empty repo exercises the whole plumbing (spawn export,
    // parse, aggregate) without an import child or any commits. Skips if git is
    // unusable.
    #[test]
    fn dry_run_on_fresh_repo_is_ok() {
        let git = default_git_binary();
        let dir = temp_dir("dry");
        let d = dir.to_string_lossy().into_owned();
        if gitutils::git_output(&git, &d, &["-c", "init.defaultBranch=main", "init", "-q"]).is_err()
        {
            eprintln!("skip pipeline dry-run: no usable git ({git})");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let opts = Options {
            repo_dir: d,
            git_bin: git,
            force: true,
            dry_run: true,
            ..Default::default()
        };
        run(&opts).expect("dry-run on a fresh empty repo should succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // End-to-end parity tests (real fast-export → filter → fast-import → verify).
    // Ignored by default: they need a plain (non-shim) git so commits don't hit a
    // gate scan. Run with:
    //   set LENSR_GIT_REAL_GIT=C:\weaver-sync\public_repos\git\git.exe
    //   cargo test --features scrub -- --ignored e2e
    fn rg(git: &str, dir: &str, args: &[&str]) -> String {
        gitutils::git_output(git, dir, args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))
    }

    #[test]
    #[ignore = "needs a plain git; run with LENSR_GIT_REAL_GIT set"]
    fn e2e_removes_path_from_all_history() {
        let git = default_git_binary();
        let dir = temp_dir("rm");
        let d = dir.to_string_lossy().into_owned();
        rg(&git, &d, &["init", "-q", "-b", "main"]);
        rg(&git, &d, &["config", "user.name", "Test"]);
        rg(&git, &d, &["config", "user.email", "test@example.com"]);
        rg(&git, &d, &["config", "commit.gpgsign", "false"]);

        std::fs::write(dir.join("secret.txt"), b"top secret\n").unwrap();
        std::fs::write(dir.join("keep.txt"), b"keep me\n").unwrap();
        rg(&git, &d, &["add", "-A"]);
        rg(&git, &d, &["commit", "-q", "-m", "add secret and keep"]);
        std::fs::write(dir.join("keep.txt"), b"keep me v2\n").unwrap();
        rg(&git, &d, &["add", "-A"]);
        rg(&git, &d, &["commit", "-q", "-m", "update keep"]);
        rg(&git, &d, &["gc", "--quiet"]);

        let mut spec = PathSpec::new();
        spec.add_match(b"secret.txt").unwrap();
        spec.invert = true; // remove the matching path

        let opts = Options {
            repo_dir: d.clone(),
            git_bin: git.clone(),
            paths: Some(&spec),
            force: true,
            ..Default::default()
        };
        run(&opts).expect("Run");

        assert!(
            rg(&git, &d, &["log", "--all", "--oneline", "--", "secret.txt"]).is_empty(),
            "secret.txt still in history"
        );
        assert!(
            !rg(&git, &d, &["ls-tree", "-r", "--name-only", "HEAD"])
                .lines()
                .any(|l| l == "secret.txt"),
            "secret.txt in HEAD tree"
        );
        rg(&git, &d, &["fsck", "--full"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "needs a plain git; run with LENSR_GIT_REAL_GIT set"]
    fn e2e_replace_text_redacts_secret() {
        let git = default_git_binary();
        let dir = temp_dir("redact");
        let d = dir.to_string_lossy().into_owned();
        rg(&git, &d, &["init", "-q", "-b", "main"]);
        rg(&git, &d, &["config", "user.name", "Test"]);
        rg(&git, &d, &["config", "user.email", "test@example.com"]);
        rg(&git, &d, &["config", "commit.gpgsign", "false"]);

        let secret = "hunter2password";
        std::fs::write(dir.join("config.txt"), format!("api_key = {secret}\n")).unwrap();
        rg(&git, &d, &["add", "-A"]);
        rg(&git, &d, &["commit", "-q", "-m", "add config with secret"]);
        rg(&git, &d, &["gc", "--quiet"]);

        let rules = ReplaceRules {
            literals: vec![super::super::replacetext::LiteralReplace {
                from: secret.as_bytes().to_vec(),
                to: b"REDACTED".to_vec(),
            }],
            regexes: vec![],
        };
        let opts = Options {
            repo_dir: d.clone(),
            git_bin: git.clone(),
            replace_text: Some(&rules),
            force: true,
            ..Default::default()
        };
        run(&opts).expect("Run");

        let head = rg(&git, &d, &["show", "HEAD:config.txt"]);
        assert!(head.contains("REDACTED"), "replacement missing: {head}");
        assert!(!head.contains(secret), "secret still in HEAD config.txt");
        rg(&git, &d, &["fsck", "--full"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
