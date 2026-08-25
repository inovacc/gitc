//! `gitc scrub` — local git-history remediation.
//!
//! Purge paths, redact text, or scrub detected secrets out of a repository's
//! entire history by rewriting it through the vendored git-filter-repo port
//! ([`crate::filterrepo`]): `git fast-export` → in-stream filter → `git
//! fast-import` → cleanup. Rewriting history is destructive and irreversible for
//! collaborators, so every rewrite is fenced by:
//!
//! * **preconditions** (exit 5) — a real git, a clean working tree (unless
//!   `--force`), and filter-repo's own fresh-clone sanity check;
//! * **a backup** — an all-objects `git bundle` + a ref snapshot under
//!   `<git-dir>/gitc-scrub/`, from which `gitc scrub rollback` restores;
//! * **`--plan`** — a read-only preview of what would change, and **`--dry-run`**
//!   — run the export+filter but discard the import (repo untouched);
//! * **verification** (exit 4) — after `scrub secret`, history is re-scanned and
//!   the run FAILS if any scrubbed secret is still reachable.
//!
//! This is a LIBRARY entry point: it returns the process exit code and never calls
//! `process::exit`. It drives a resolved REAL git (`GITC_REAL_GIT` /
//! `LENSR_GIT_REAL_GIT` / the first non-self `git` on PATH) so it never re-enters
//! the gitc binary.

use std::path::{Path, PathBuf};

use crate::filterrepo::commitfilter::PruneMode;
use crate::filterrepo::gitutils::{default_git_binary, git_output};
use crate::filterrepo::identity::IdentityRewrite;
use crate::filterrepo::pathspec::PathSpec;
use crate::filterrepo::pipeline::{self, Options, PipelineError};
use crate::filterrepo::replacetext::{parse_replace_text, LiteralReplace, ReplaceRules};
use detect::Detector;
use sources::{Fragment, ATTR_GIT_SHA, ATTR_PATH};

pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_RUNTIME: i32 = 3;
pub const EXIT_VERIFY_FAILED: i32 = 4;
pub const EXIT_PRECONDITION: i32 = 5;

/// Default replacement text for a redacted secret / literal.
const DEFAULT_REDACTION: &str = "***REMOVED***";

/// Per-blob cap when scanning history for secrets (mirrors the scan surface).
const MAX_BLOB_BYTES: usize = 5 * 1024 * 1024;

/// Parsed `gitc scrub …` options.
struct Opts {
    dry_run: bool,
    plan: bool,
    force: bool,
    no_backup: bool,
    refs: Vec<String>,         // explicit rev args (--ref/--refs)
    branches: Vec<String>,     // --branch <b>
    tags: bool,                // --tags
    all_refs: bool,            // --all-refs (→ --all)
    exclude_refs: Vec<String>, // --exclude-ref <r> (→ ^r)
    prune_backups: bool,       // cleanup: also delete local scrub backups
    strip_sigs: bool,          // acknowledge that the rewrite invalidates signatures
    redaction: String,         // replacement text for `secret`/bare `replace`
    replace_file: String,
    output: String, // serialize a plan to this JSON file (§8)
    identity_match_email: String,
    identity_match_name: String,
    identity_name: String,
    identity_email: String,
    identity_author_only: bool,
    identity_committer_only: bool,
    positional: Vec<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            dry_run: false,
            plan: false,
            force: false,
            no_backup: false,
            refs: Vec::new(),
            branches: Vec::new(),
            tags: false,
            all_refs: false,
            exclude_refs: Vec::new(),
            prune_backups: false,
            strip_sigs: false,
            redaction: DEFAULT_REDACTION.to_string(),
            replace_file: String::new(),
            output: String::new(),
            identity_match_email: String::new(),
            identity_match_name: String::new(),
            identity_name: String::new(),
            identity_email: String::new(),
            identity_author_only: false,
            identity_committer_only: false,
            positional: Vec::new(),
        }
    }
}

/// `gitc scrub <subcommand> [args]`. `args` is everything AFTER `scrub`.
pub fn run(args: &[String]) -> i32 {
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("{}", usage());
        return EXIT_USAGE;
    };
    match sub.as_str() {
        "plan" => cmd_plan(rest),
        "path" => cmd_path(rest),
        "blob" => cmd_blob(rest),
        "replace" => cmd_replace(rest),
        "identity" => cmd_identity(rest),
        "secret" => cmd_secret(rest),
        "rollback" => cmd_rollback(rest),
        "cleanup" => cmd_cleanup(rest),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            EXIT_CLEAN
        }
        other => usage_err(&format!("unknown scrub subcommand '{other}'")),
    }
}

fn usage() -> &'static str {
    "gitc scrub — local git-history remediation (destructive; rewrites history)\n\
     \n\
     USAGE:\n\
       gitc scrub plan [<fingerprint>] [--output plan.json]  inspect what a rewrite would do\n\
       gitc scrub path <glob>...            remove matching paths from ALL history\n\
       gitc scrub blob <oid>...             remove path(s) carrying the given blob object(s)\n\
       gitc scrub replace <from>=<to>...    redact literal text in blobs\n\
       gitc scrub replace --replace-file <f>  redact per a git-filter-repo rules file\n\
       gitc scrub identity --match-email <old> --name <new> --email <new>\n\
                                      rewrite matching author/committer metadata\n\
       gitc scrub secret [<fingerprint>]    redact every detected secret, or one finding by id\n\
       gitc scrub rollback                  restore refs from the most recent backup\n\
       gitc scrub cleanup                   expire reflogs + gc so old object bytes are removed\n\
     \n\
     SCOPE (default: all refs — a secret left on any ref stays reachable):\n\
       --all-refs        rewrite every ref\n\
       --branch <b>      rewrite refs/heads/<b> (repeatable)\n\
       --branches        rewrite all branches\n\
       --tags            include tags\n\
       --ref <ref>       rewrite an explicit rev (repeatable)\n\
       --exclude-ref <r> exclude <r> from the rewrite\n\
     \n\
     FLAGS:\n\
       --plan            preview what would change; make NO changes\n\
       --dry-run         run export+filter but discard the result (repo unchanged)\n\
       --force           bypass clean-tree + fresh-clone preconditions\n\
       --no-backup       skip the pre-rewrite bundle/ref backup (not recommended)\n\
       --to <text>       replacement text for secret/bare-replace (default ***REMOVED***)\n\
       --replace-file <f>  git-filter-repo replace-text rules file\n\
       --match-email <e>  exact email to match for identity rewrites\n\
       --match-name <n>   exact name to match for identity rewrites\n\
       --name <n>         replacement author/committer name\n\
       --email <e>        replacement author/committer email\n\
       --author-only      rewrite authors but leave committers unchanged\n\
       --committer-only   rewrite committers but leave authors unchanged\n\
       --prune-backups   cleanup: also delete local scrub backups\n\
       --strip-invalid-signatures  acknowledge that the rewrite invalidates signatures (§12)\n\
     \n\
     Exit codes: 0 ok · 2 usage · 3 runtime · 4 verification failed · 5 precondition failed."
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("gitc scrub: {msg}\n\n{}", usage());
    EXIT_USAGE
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--plan" => o.plan = true,
            "--dry-run" => o.dry_run = true,
            "--force" => o.force = true,
            "--no-backup" => o.no_backup = true,
            "--refs" | "--ref" => o.refs.push(take(args, &mut i, a)?),
            "--branch" => o.branches.push(take(args, &mut i, a)?),
            "--branches" => o.refs.push("--branches".to_string()),
            "--tags" => o.tags = true,
            "--all-refs" => o.all_refs = true,
            "--exclude-ref" => o.exclude_refs.push(take(args, &mut i, a)?),
            "--prune-backups" => o.prune_backups = true,
            "--strip-invalid-signatures" => o.strip_sigs = true,
            "--to" | "--redaction" => o.redaction = take(args, &mut i, a)?,
            "--replace-file" => o.replace_file = take(args, &mut i, a)?,
            "--output" => o.output = take(args, &mut i, a)?,
            "--match-email" => o.identity_match_email = take(args, &mut i, a)?,
            "--match-name" => o.identity_match_name = take(args, &mut i, a)?,
            "--name" => o.identity_name = take(args, &mut i, a)?,
            "--email" => o.identity_email = take(args, &mut i, a)?,
            "--author-only" => o.identity_author_only = true,
            "--committer-only" => o.identity_committer_only = true,
            "-h" | "--help" => return Err("help".to_string()),
            s if s.starts_with("--") => return Err(format!("unknown flag '{s}'")),
            _ => o.positional.push(a.clone()),
        }
        i += 1;
    }
    Ok(o)
}

fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

// ── subcommands ──────────────────────────────────────────────────────────────

/// `gitc scrub plan [<fingerprint>] [--output plan.json]` (§8) — a read-only,
/// inspectable, serializable plan of a secret-remediation rewrite: which findings
/// are targeted, how many blobs/commits/refs it touches, the signatures it would
/// invalidate, whether commit ids change, the replacement strategy, and the
/// rollback location. Contains fingerprints/rules/counts only — never raw secrets.
fn cmd_plan(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub plan: {e}");
            return EXIT_PRECONDITION;
        }
    };
    let gitdir = git_output(&git, &repo, &["rev-parse", "--absolute-git-dir"])
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|_| PathBuf::from(&repo).join(".git"));

    let all = match collect_history_secrets() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gitc scrub plan: scan history: {e}");
            return EXIT_RUNTIME;
        }
    };
    let targeted: Vec<SecretHit> = if let Some(fp) = o.positional.first() {
        all.into_iter()
            .filter(|s| fp_matches(&s.fingerprint, fp))
            .collect()
    } else {
        all
    };
    if targeted.is_empty() {
        println!("gitc scrub plan: no matching findings — nothing to remediate");
        return EXIT_CLEAN;
    }

    // Affected blobs/commits: blobs whose content still carries a targeted value.
    let values: std::collections::BTreeSet<&str> =
        targeted.iter().map(|s| s.secret.as_str()).collect();
    let (blobs, commits) = plan_stats(&gitdir, &values);
    let refs = ref_names(&git, &repo);
    let (signed_commits, signed_tags) =
        crate::gitwalk::count_signed(&gitdir, &crate::gitwalk::all_ref_tips(&gitdir));
    let rollback = backup_dir(&git, &repo)
        .map(|d| d.display().to_string())
        .unwrap_or_default();

    // Human-readable plan.
    println!("gitc scrub plan (read-only — no changes):");
    println!("  targeted findings: {}", targeted.len());
    for s in &targeted {
        println!("    {} [{}]", s.fingerprint, s.rule);
    }
    println!("  distinct secret values: {}", values.len());
    println!("  affected blobs:        {blobs}");
    println!("  affected commits:      {}", commits.len());
    println!(
        "  affected refs:         {} ({})",
        refs.len(),
        refs.join(", ")
    );
    println!("  commit ids change:     yes (all descendants rewritten)");
    println!("  signatures invalidated: {signed_commits} commit(s), {signed_tags} tag(s)");
    println!(
        "  replacement strategy:  literal redaction -> {}",
        o.redaction
    );
    println!("  rollback location:     {rollback}");

    if !o.output.is_empty() {
        let json = plan_json(
            &targeted,
            values.len(),
            blobs,
            commits.len(),
            &refs,
            signed_commits,
            signed_tags,
            &o.redaction,
            &rollback,
        );
        if let Err(e) = std::fs::write(&o.output, json) {
            eprintln!("gitc scrub plan: write {}: {e}", o.output);
            return EXIT_RUNTIME;
        }
        println!("  plan written to {}", o.output);
    }
    EXIT_CLEAN
}

/// Count blobs (and their commits) in reachable history that still carry any of the
/// targeted secret values — the rewrite's blast radius.
fn plan_stats(
    gitdir: &Path,
    values: &std::collections::BTreeSet<&str>,
) -> (usize, std::collections::BTreeSet<String>) {
    let tips = crate::gitwalk::all_ref_tips(gitdir);
    let (intros, _t) = crate::gitwalk::reachable_blob_intros(gitdir, &tips, &[]);
    let mut blobs = 0usize;
    let mut commits = std::collections::BTreeSet::new();
    for b in &intros {
        let content = match crate::gitobj::read_blob(gitdir, &b.oid_hex, MAX_BLOB_BYTES) {
            Ok(Some(c)) => c,
            _ => continue,
        };
        if content.iter().take(8192).any(|&x| x == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&content);
        if values.iter().any(|v| text.contains(*v)) {
            blobs += 1;
            commits.insert(b.commit.clone());
        }
    }
    (blobs, commits)
}

/// All ref names in the repo (for the plan's affected-refs list).
fn ref_names(git: &str, repo: &str) -> Vec<String> {
    git_output(git, repo, &["for-each-ref", "--format=%(refname)"])
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Serialize a plan to JSON by hand (no serde dep). Secrets are never included —
/// only fingerprints, rules, counts, and metadata (§8/§44).
#[allow(clippy::too_many_arguments)]
fn plan_json(
    targeted: &[SecretHit],
    distinct_values: usize,
    blobs: usize,
    commits: usize,
    refs: &[String],
    signed_commits: usize,
    signed_tags: usize,
    redaction: &str,
    rollback: &str,
) -> String {
    let findings: Vec<String> = targeted
        .iter()
        .map(|s| {
            format!(
                "{{\"fingerprint\":\"{}\",\"rule\":\"{}\"}}",
                json_escape(&s.fingerprint),
                json_escape(&s.rule)
            )
        })
        .collect();
    let refs_json: Vec<String> = refs
        .iter()
        .map(|r| format!("\"{}\"", json_escape(r)))
        .collect();
    format!(
        "{{\n  \"version\": 1,\n  \"findings\": [{}],\n  \"distinct_secret_values\": {},\n  \"affected_blobs\": {},\n  \"affected_commits\": {},\n  \"affected_refs\": [{}],\n  \"commit_ids_change\": true,\n  \"signatures_invalidated\": {{\"commits\": {}, \"tags\": {}}},\n  \"replacement_strategy\": \"literal-redaction\",\n  \"replacement_marker\": \"{}\",\n  \"rollback_location\": \"{}\"\n}}\n",
        findings.join(","),
        distinct_values,
        blobs,
        commits,
        refs_json.join(","),
        signed_commits,
        signed_tags,
        json_escape(redaction),
        json_escape(rollback),
    )
}

/// Minimal JSON string escaping (quotes, backslashes, control chars).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn cmd_path(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    if o.positional.is_empty() {
        return usage_err("`gitc scrub path` needs one or more <glob> paths to remove");
    }
    let mut spec = PathSpec::new();
    for p in &o.positional {
        if let Err(e) = spec.add_match(p.as_bytes()) {
            return usage_err(&format!("bad path '{p}': {e}"));
        }
    }
    spec.invert = true; // invert = REMOVE the matching paths
    if o.plan {
        return plan_path(&o);
    }
    let what = format!("removed {} path pattern(s)", o.positional.len());
    do_rewrite(&o, Some(&spec), None, None, &what)
}

/// `gitc scrub blob <oid>...` (§6) — remove the path(s) carrying the given blob
/// object(s) from all history. Resolves each oid to its path(s) via
/// `git rev-list --all --objects` (so nothing sensitive is typed), then removes
/// those paths. Useful for large/sensitive binary objects.
fn cmd_blob(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    if o.positional.is_empty() {
        return usage_err("`gitc scrub blob` needs one or more blob <oid>s");
    }
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub: {e}");
            return EXIT_PRECONDITION;
        }
    };
    let listing = git_output(&git, &repo, &["rev-list", "--all", "--objects"]).unwrap_or_default();
    let mut spec = PathSpec::new();
    let mut paths = std::collections::BTreeSet::new();
    for oid in &o.positional {
        for line in listing.lines() {
            if let Some((obj, path)) = line.split_once(' ') {
                // full or abbreviated oid match, non-empty path
                if (obj == oid || obj.starts_with(oid.as_str())) && !path.trim().is_empty() {
                    paths.insert(path.to_string());
                }
            }
        }
    }
    if paths.is_empty() {
        eprintln!("gitc scrub blob: no path in history carries the given blob oid(s)");
        return EXIT_USAGE;
    }
    for p in &paths {
        if let Err(e) = spec.add_match(p.as_bytes()) {
            return usage_err(&format!("bad path '{p}': {e}"));
        }
    }
    spec.invert = true;
    if o.plan {
        println!("gitc scrub blob — PLAN (no changes will be made):");
        for p in &paths {
            println!("  would remove path carrying the blob: {p}");
        }
        warn_signatures(o.strip_sigs);
        return EXIT_CLEAN;
    }
    let what = format!(
        "removed {} path(s) carrying the target blob(s)",
        paths.len()
    );
    do_rewrite(&o, Some(&spec), None, None, &what)
}

fn cmd_replace(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    let rules = match build_replace_rules(&o) {
        Ok(r) => r,
        Err(e) => return usage_err(&e),
    };
    if rules.empty() {
        return usage_err("`gitc scrub replace` needs <from>=<to>... or --replace-file <file>");
    }
    if o.plan {
        println!("gitc scrub replace — PLAN (no changes will be made)");
        println!(
            "  {} literal + {} regex replacement rule(s) would be applied across history",
            rules.literals.len(),
            rules.regexes.len()
        );
        warn_signatures(o.strip_sigs);
        return EXIT_CLEAN;
    }
    do_rewrite(&o, None, Some(&rules), None, "redacted text")
}

/// Rewrite exact author/committer metadata without touching blobs or paths.
fn cmd_identity(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    if o.identity_match_email.is_empty() && o.identity_match_name.is_empty() {
        return usage_err("`gitc scrub identity` needs --match-email and/or --match-name");
    }
    if o.identity_name.is_empty() || o.identity_email.is_empty() {
        return usage_err("`gitc scrub identity` needs both --name and --email replacements");
    }
    if o.identity_author_only && o.identity_committer_only {
        return usage_err("`--author-only` and `--committer-only` cannot be combined");
    }
    let mut rewrite = IdentityRewrite::new(
        (!o.identity_match_email.is_empty()).then(|| o.identity_match_email.as_bytes().to_vec()),
        (!o.identity_match_name.is_empty()).then(|| o.identity_match_name.as_bytes().to_vec()),
        o.identity_name.as_bytes().to_vec(),
        o.identity_email.as_bytes().to_vec(),
    );
    rewrite.rewrite_author = !o.identity_committer_only;
    rewrite.rewrite_committer = !o.identity_author_only;
    if o.plan {
        println!("gitc scrub identity — PLAN (no changes will be made)");
        println!("  matching identity metadata will be replaced across the selected history");
        warn_signatures(o.strip_sigs);
        return EXIT_CLEAN;
    }
    let what = "rewrote matching author/committer identity metadata";
    do_rewrite(&o, None, None, Some(&rewrite), what)
}

fn cmd_secret(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    let all = match collect_history_secrets() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gitc scrub secret: scan history: {e}");
            return EXIT_RUNTIME;
        }
    };
    // §14: an optional <fingerprint> targets ONE finding by identity — no raw secret
    // on the command line. Its value is recovered internally from the finding.
    let secrets: Vec<SecretHit> = if let Some(fp) = o.positional.first() {
        let matched: Vec<SecretHit> = all
            .into_iter()
            .filter(|s| fp_matches(&s.fingerprint, fp))
            .collect();
        if matched.is_empty() {
            eprintln!("gitc scrub secret: no finding matches '{fp}' in reachable history");
            return EXIT_USAGE;
        }
        matched
    } else {
        all
    };
    if secrets.is_empty() {
        println!("gitc scrub secret: no secrets found in history — nothing to scrub");
        return EXIT_CLEAN;
    }
    if o.plan {
        println!(
            "gitc scrub secret — PLAN: would redact {} distinct secret(s) across history:",
            secrets.len()
        );
        for s in &secrets {
            println!("  [{}] {}", s.rule, mask(&s.secret));
        }
        warn_signatures(o.strip_sigs);
        return EXIT_CLEAN;
    }
    let rules = secrets_to_rules(&secrets, &o.redaction);
    let what = format!("redacted {} secret(s)", secrets.len());
    let code = do_rewrite(&o, None, Some(&rules), None, &what);
    if code != EXIT_CLEAN || o.dry_run {
        return code;
    }
    // Verification (exit 4): only done if the secrets are gone from EVERY ref (§16/§17).
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub secret: verify: {e}");
            return EXIT_RUNTIME;
        }
    };
    match verify_scrubbed(&git, &repo, &secrets) {
        Ok(v) if v.clean => {
            println!(
                "gitc scrub secret: verified — no scrubbed secret remains reachable from any ref"
            );
            EXIT_CLEAN
        }
        Ok(v) => {
            eprintln!(
                "gitc scrub secret: VERIFICATION FAILED — a scrubbed secret is still reachable."
            );
            if !v.residual_refs.is_empty() {
                eprintln!("  refs that still expose it:");
                for r in &v.residual_refs {
                    eprintln!("    {r}");
                }
                eprintln!("  re-run with --all-refs (or scrub those refs), then verify again.");
            }
            eprintln!("  restore with `gitc scrub rollback` if needed.");
            EXIT_VERIFY_FAILED
        }
        Err(e) => {
            eprintln!("gitc scrub secret: verification error: {e}");
            EXIT_RUNTIME
        }
    }
}

fn cmd_rollback(_args: &[String]) -> i32 {
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub rollback: {e}");
            return EXIT_PRECONDITION;
        }
    };
    let dir = match backup_dir(&git, &repo) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("gitc scrub rollback: {e}");
            return EXIT_RUNTIME;
        }
    };
    let Some(n) = latest_backup_index(&dir) else {
        eprintln!(
            "gitc scrub rollback: no backup found under {}",
            dir.display()
        );
        return EXIT_PRECONDITION;
    };
    let bundle = dir.join(format!("backup-{n}.bundle"));
    // Restore every ref (and its objects) from the bundle, then resync the tree.
    if let Err(e) = git_output(
        &git,
        &repo,
        &[
            "fetch",
            "--force",
            &bundle.to_string_lossy(),
            "+refs/*:refs/*",
        ],
    ) {
        eprintln!(
            "gitc scrub rollback: restore from {}: {e}",
            bundle.display()
        );
        return EXIT_RUNTIME;
    }
    let _ = git_output(&git, &repo, &["reset", "--hard", "HEAD"]);
    println!(
        "gitc scrub rollback: restored refs from backup-{n} ({})",
        bundle.display()
    );
    EXIT_CLEAN
}

/// `gitc scrub cleanup` (§18/§19) — expire reflogs + gc so the old, now-unreachable
/// object BYTES are physically removed, and report the before/after unreachable
/// count. Distinguishes "history no longer references the secret" from "old bytes
/// physically gone". Backups (bundles) are retained unless `--prune-backups`.
fn cmd_cleanup(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub cleanup: {e}");
            return EXIT_PRECONDITION;
        }
    };
    let before = count_unreachable(&git, &repo);
    println!("gitc scrub cleanup: {before} unreachable object(s) present");
    if o.plan || o.dry_run {
        println!(
            "  (no changes) would run: reflog expire --expire=now --expire-unreachable=now --all; gc --prune=now"
        );
        return EXIT_CLEAN;
    }
    if let Err(e) = git_output(
        &git,
        &repo,
        &[
            "reflog",
            "expire",
            "--expire=now",
            "--expire-unreachable=now",
            "--all",
        ],
    ) {
        eprintln!("gitc scrub cleanup: reflog expire: {e}");
        return EXIT_RUNTIME;
    }
    if let Err(e) = git_output(&git, &repo, &["gc", "--prune=now", "--quiet"]) {
        eprintln!("gitc scrub cleanup: gc: {e}");
        return EXIT_RUNTIME;
    }
    let after = count_unreachable(&git, &repo);
    println!("gitc scrub cleanup: {after} unreachable object(s) remain after reflog-expire + gc");
    println!(
        "  history no longer references the removed content; old object BYTES are now physically gc'd."
    );
    if o.prune_backups {
        if let Ok(dir) = backup_dir(&git, &repo) {
            let _ = std::fs::remove_dir_all(&dir);
            println!("  removed local scrub backups under {}", dir.display());
        }
    } else {
        println!("  local scrub backups retained (pass --prune-backups to remove them).");
    }
    EXIT_CLEAN
}

/// Count objects git reports as unreachable (excluding reflog-held), for the
/// cleanup before/after summary.
fn count_unreachable(git: &str, repo: &str) -> usize {
    git_output(git, repo, &["fsck", "--unreachable", "--no-reflogs"])
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("unreachable "))
        .count()
}

// ── rewrite orchestration ────────────────────────────────────────────────────

/// Run a rewrite behind the safety fence: preconditions → backup → pipeline.
fn do_rewrite(
    o: &Opts,
    paths: Option<&PathSpec>,
    rules: Option<&ReplaceRules>,
    identity: Option<&IdentityRewrite>,
    what: &str,
) -> i32 {
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub: {e}");
            return EXIT_PRECONDITION;
        }
    };
    if let Err(e) = preconditions(&git, &repo, o.force) {
        eprintln!("gitc scrub: {e}");
        return EXIT_PRECONDITION;
    }
    warn_signatures(o.strip_sigs);
    if !o.dry_run && !o.no_backup {
        match make_backup(&git, &repo) {
            Ok(b) => eprintln!("gitc scrub: backup written to {}", b.display()),
            Err(e) => {
                eprintln!(
                    "gitc scrub: backup failed ({e}) — aborting; pass --no-backup to override"
                );
                return EXIT_RUNTIME;
            }
        }
    }
    let opts = Options {
        repo_dir: repo.clone(),
        git_bin: git.clone(),
        refs: resolve_refs(o),
        paths,
        replace_text: rules,
        identity,
        prune: PruneMode::Auto,
        force: o.force,
        dry_run: o.dry_run,
    };
    match pipeline::run(&opts) {
        Ok(()) => {
            if o.dry_run {
                println!("gitc scrub: dry-run complete — repo UNCHANGED ({what})");
            } else {
                println!("gitc scrub: rewrote history ({what}); run `git push --force-with-lease` to publish");
            }
            EXIT_CLEAN
        }
        // filter-repo's fresh-clone check is a rewrite precondition (exit 5).
        Err(PipelineError::Sanity(e)) => {
            eprintln!("gitc scrub: {e}\n(pass --force to override the fresh-clone safety check)");
            EXIT_PRECONDITION
        }
        Err(e) => {
            eprintln!("gitc scrub: {e}");
            EXIT_RUNTIME
        }
    }
}

/// Warn that a rewrite invalidates cryptographic signatures (§12): count signed
/// commits + signed annotated tags in the repo and surface them prominently.
/// Self-resolving so plans and the rewrite path can both call it cheaply.
fn warn_signatures(acknowledged: bool) {
    let git = resolve_git();
    let Ok(repo) = repo_root(&git) else {
        return;
    };
    let gitdir = git_output(&git, &repo, &["rev-parse", "--absolute-git-dir"])
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|_| PathBuf::from(&repo).join(".git"));
    let tips = crate::gitwalk::all_ref_tips(&gitdir);
    let (commits, tags) = crate::gitwalk::count_signed(&gitdir, &tips);
    if commits == 0 && tags == 0 {
        return;
    }
    eprintln!(
        "gitc scrub: WARNING (§12) — rewriting invalidates signatures: {commits} signed commit(s), {tags} signed tag(s)."
    );
    if !acknowledged {
        eprintln!(
            "  fast-export strips tag signatures; commit signatures become invalid on the rewritten bytes."
        );
        eprintln!("  pass --strip-invalid-signatures to acknowledge.");
    }
}

/// Resolve the rewrite scope (§10) to fast-export rev args. `--all-refs` wins with
/// `--all`; otherwise explicit `--ref`s + `--tags`/`--branch`/`--exclude-ref`. An
/// empty result means the pipeline's own default (`--all`) — the conservative
/// remediation default is "all refs", because a secret left on any unrewritten ref
/// stays reachable; narrow explicitly to keep some refs, and residual refs are
/// reported after verification.
fn resolve_refs(o: &Opts) -> Vec<String> {
    if o.all_refs {
        return vec!["--all".to_string()];
    }
    let mut refs = o.refs.clone();
    if o.tags {
        refs.push("--tags".to_string());
    }
    for b in &o.branches {
        refs.push(format!("refs/heads/{b}"));
    }
    for e in &o.exclude_refs {
        refs.push(format!("^{e}"));
    }
    refs
}

/// Real git only — never this binary. `GITC_REAL_GIT`/`LENSR_GIT_REAL_GIT` override
/// the PATH search, which itself skips the running executable.
fn resolve_git() -> String {
    for var in ["GITC_REAL_GIT", "LENSR_GIT_REAL_GIT"] {
        if let Ok(p) = std::env::var(var) {
            let p = p.trim();
            if !p.is_empty() {
                return p.to_string();
            }
        }
    }
    default_git_binary()
}

/// The repository top-level (working dir the pipeline runs `git -C` against).
fn repo_root(git: &str) -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let cwd = cwd.to_string_lossy().into_owned();
    let top = git_output(git, &cwd, &["rev-parse", "--show-toplevel"])
        .map_err(|_| "not inside a git working tree".to_string())?;
    let top = top.trim();
    if top.is_empty() {
        return Err("not inside a git working tree".to_string());
    }
    Ok(top.to_string())
}

/// Precondition gate (exit 5): a clean working tree unless `--force`.
fn preconditions(git: &str, repo: &str, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let status = git_output(git, repo, &["status", "--porcelain"]).unwrap_or_default();
    if !status.trim().is_empty() {
        return Err(
            "working tree has uncommitted changes — commit/stash first, or pass --force"
                .to_string(),
        );
    }
    Ok(())
}

/// `<git-dir>/gitc-scrub` — where backups live.
fn backup_dir(git: &str, repo: &str) -> Result<PathBuf, String> {
    let gd = git_output(git, repo, &["rev-parse", "--absolute-git-dir"])
        .map_err(|e| format!("resolve git dir: {e}"))?;
    Ok(PathBuf::from(gd.trim()).join("gitc-scrub"))
}

/// Bundle every object + snapshot every ref BEFORE a rewrite, so `rollback` can
/// restore the exact pre-rewrite state even after filter-repo's gc.
fn make_backup(git: &str, repo: &str) -> Result<PathBuf, String> {
    let dir = backup_dir(git, repo)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create backup dir: {e}"))?;
    let n = latest_backup_index(&dir).map(|n| n + 1).unwrap_or(0);
    let bundle = dir.join(format!("backup-{n}.bundle"));
    git_output(
        git,
        repo,
        &["bundle", "create", &bundle.to_string_lossy(), "--all"],
    )
    .map_err(|e| format!("create bundle: {e}"))?;
    let refs = git_output(
        git,
        repo,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
    )
    .unwrap_or_default();
    std::fs::write(dir.join(format!("backup-{n}.refs")), refs)
        .map_err(|e| format!("write ref snapshot: {e}"))?;
    Ok(bundle)
}

/// The highest existing `backup-<n>.bundle` index under `dir`, if any.
fn latest_backup_index(dir: &Path) -> Option<u64> {
    let mut best: Option<u64> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("backup-") {
            if let Some(num) = rest.strip_suffix(".bundle") {
                if let Ok(n) = num.parse::<u64>() {
                    best = Some(best.map_or(n, |b| b.max(n)));
                }
            }
        }
    }
    best
}

// ── replace-rule construction ────────────────────────────────────────────────

/// Build the literal/regex replace rules for `gitc scrub replace`: a
/// `--replace-file` (git-filter-repo format) plus any `<from>=<to>` positionals
/// (`<to>` omitted → the `--to` redaction).
fn build_replace_rules(o: &Opts) -> Result<ReplaceRules, String> {
    let mut rules = if o.replace_file.is_empty() {
        ReplaceRules::default()
    } else {
        parse_replace_text(&o.replace_file).map_err(|e| format!("replace file: {e}"))?
    };
    for pos in &o.positional {
        let (from, to) = match pos.split_once('=') {
            Some((f, t)) => (f, t),
            None => (pos.as_str(), o.redaction.as_str()),
        };
        if from.is_empty() {
            return Err(format!("empty <from> in replace rule '{pos}'"));
        }
        rules.literals.push(LiteralReplace {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
        });
    }
    Ok(rules)
}

/// One literal redaction rule per distinct secret VALUE (findings may share a value).
fn secrets_to_rules(secrets: &[SecretHit], redaction: &str) -> ReplaceRules {
    let mut seen = std::collections::BTreeSet::new();
    let mut rules = ReplaceRules::default();
    for s in secrets {
        if seen.insert(s.secret.clone()) {
            rules.literals.push(LiteralReplace {
                from: s.secret.clone().into_bytes(),
                to: redaction.as_bytes().to_vec(),
            });
        }
    }
    rules
}

// ── secret discovery + verification (uses the detect engine) ─────────────────

/// A distinct finding in history — its raw value (the redaction key), rule, and
/// canonical fingerprint (`[commit:]file:rule:line`) for identity-based targeting.
struct SecretHit {
    secret: String,
    rule: String,
    fingerprint: String,
}

/// Does `fingerprint` match a user query — the full canonical id, its `v1:`-stripped
/// form, or a prefix thereof (abbreviated ids)? Mirrors `scan --trace-finding`.
fn fp_matches(fingerprint: &str, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return false;
    }
    let bare = fingerprint.strip_prefix("v1:").unwrap_or(fingerprint);
    let q_bare = q.strip_prefix("v1:").unwrap_or(q);
    fingerprint == q || bare == q_bare || fingerprint.starts_with(q) || bare.starts_with(q_bare)
}

/// Scan every blob reachable from ALL refs and return the DISTINCT raw secrets, so
/// each can be redacted across all of history (a secret on any branch/tag counts).
fn collect_history_secrets() -> Result<Vec<SecretHit>, String> {
    let gitdir = discover_gitdir()?;
    let tips = crate::gitwalk::all_ref_tips(&gitdir);
    collect_secrets(&gitdir, &tips)
}

/// Distinct findings reachable from `tips`, deduped by canonical fingerprint. Feeds
/// the blob's path + commit into a Fragment so each finding fingerprints correctly.
fn collect_secrets(gitdir: &Path, tips: &[String]) -> Result<Vec<SecretHit>, String> {
    let (intros, _truncated) = crate::gitwalk::reachable_blob_intros(gitdir, tips, &[]);
    let d = Detector::with_default_rules();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for b in &intros {
        let content = match crate::gitobj::read_blob(gitdir, &b.oid_hex, MAX_BLOB_BYTES) {
            Ok(Some(c)) => c,
            _ => continue,
        };
        if content.iter().take(8192).any(|&x| x == 0) {
            continue; // binary
        }
        let raw = String::from_utf8_lossy(&content).into_owned();
        let mut frag = Fragment {
            raw,
            ..Default::default()
        };
        frag.set_attr(ATTR_PATH, &b.path);
        if !b.commit.is_empty() {
            frag.set_attr(ATTR_GIT_SHA, &b.commit);
        }
        for f in d.detect(&frag) {
            if f.secret.is_empty() {
                continue;
            }
            if seen.insert(f.fingerprint.clone()) {
                out.push(SecretHit {
                    secret: f.secret,
                    rule: f.rule_id,
                    fingerprint: f.fingerprint,
                });
            }
        }
    }
    Ok(out)
}

/// Post-rewrite verification (§16/§17): whether every scrubbed secret is gone from
/// ALL reachable history, plus the names of any refs that still expose one.
struct VerifyResult {
    clean: bool,
    residual_refs: Vec<String>,
}

fn verify_scrubbed(git: &str, repo: &str, scrubbed: &[SecretHit]) -> Result<VerifyResult, String> {
    let gitdir = discover_gitdir()?;
    let target: std::collections::BTreeSet<&str> =
        scrubbed.iter().map(|s| s.secret.as_str()).collect();
    // Cheap union check first: is anything left anywhere?
    let remaining = collect_secrets(&gitdir, &crate::gitwalk::all_ref_tips(&gitdir))?;
    if !remaining.iter().any(|s| target.contains(s.secret.as_str())) {
        return Ok(VerifyResult {
            clean: true,
            residual_refs: Vec::new(),
        });
    }
    // Something survives — name the refs that still expose a scrubbed secret.
    let mut residual = Vec::new();
    let listing = git_output(
        git,
        repo,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
    )
    .unwrap_or_default();
    for line in listing.lines() {
        let Some((oid, name)) = line.trim().split_once(' ') else {
            continue;
        };
        let found = collect_secrets(&gitdir, &[oid.to_string()])
            .map(|s| s.iter().any(|h| target.contains(h.secret.as_str())))
            .unwrap_or(false);
        if found {
            residual.push(name.to_string());
        }
    }
    Ok(VerifyResult {
        clean: false,
        residual_refs: residual,
    })
}

/// Find the `.git` directory by walking up from cwd (for the detect-side scan).
fn discover_gitdir() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    loop {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Ok(candidate);
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return Err("not inside a git repository".to_string()),
        }
    }
}

/// A short, safe display of a secret (never the full value).
fn mask(secret: &str) -> String {
    let n = secret.chars().count();
    let head: String = secret.chars().take(4).collect();
    format!("{head}… ({n} chars)")
}

// ── read-only plan ───────────────────────────────────────────────────────────

/// Read-only preview for `scrub path`: how many commits touch each path.
fn plan_path(o: &Opts) -> i32 {
    let git = resolve_git();
    let repo = match repo_root(&git) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc scrub: {e}");
            return EXIT_PRECONDITION;
        }
    };
    println!("gitc scrub path — PLAN (no changes will be made):");
    for p in &o.positional {
        let log =
            git_output(&git, &repo, &["log", "--all", "--oneline", "--", p]).unwrap_or_default();
        let commits = log.lines().filter(|l| !l.trim().is_empty()).count();
        println!("  {p}: {commits} commit(s) touch this path — would be removed from all history");
    }
    warn_signatures(o.strip_sigs);
    EXIT_CLEAN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn parse_flags_and_positionals() {
        let o = parse(&s(&[
            "--dry-run",
            "--plan",
            "--force",
            "--refs",
            "main",
            "--refs",
            "dev",
            "--to",
            "X",
            "secret.txt",
        ]))
        .unwrap();
        assert!(o.dry_run && o.plan && o.force);
        assert_eq!(o.refs, vec!["main".to_string(), "dev".to_string()]);
        assert_eq!(o.redaction, "X");
        assert_eq!(o.positional, vec!["secret.txt".to_string()]);
        assert!(parse(&s(&["--nope"])).is_err());
        assert!(parse(&s(&["--refs"])).is_err()); // needs a value
    }

    #[test]
    fn build_replace_rules_from_pairs_and_bare() {
        let o = Opts {
            redaction: "REDACTED".to_string(),
            positional: s(&["password=hunter2", "sk_live_abc"]),
            ..Default::default()
        };
        let rules = build_replace_rules(&o).unwrap();
        assert_eq!(rules.literals.len(), 2);
        assert_eq!(rules.literals[0].from, b"password");
        assert_eq!(rules.literals[0].to, b"hunter2");
        // a bare token redacts to the --to text
        assert_eq!(rules.literals[1].from, b"sk_live_abc");
        assert_eq!(rules.literals[1].to, b"REDACTED");
        // an empty from is rejected
        let bad = Opts {
            positional: s(&["=x"]),
            ..Default::default()
        };
        assert!(build_replace_rules(&bad).is_err());
    }

    #[test]
    fn resolve_refs_scope_control() {
        // --all-refs wins.
        let o = Opts {
            all_refs: true,
            tags: true,
            ..Default::default()
        };
        assert_eq!(resolve_refs(&o), vec!["--all".to_string()]);
        // branches + tags + exclude compose into rev args.
        let o = Opts {
            branches: s(&["main", "release"]),
            tags: true,
            exclude_refs: s(&["refs/tags/archive"]),
            refs: s(&["deadbeef"]),
            ..Default::default()
        };
        let refs = resolve_refs(&o);
        assert!(refs.contains(&"deadbeef".to_string()));
        assert!(refs.contains(&"--tags".to_string()));
        assert!(refs.contains(&"refs/heads/main".to_string()));
        assert!(refs.contains(&"refs/heads/release".to_string()));
        assert!(refs.contains(&"^refs/tags/archive".to_string()));
        // no scope → empty → pipeline default (--all).
        assert!(resolve_refs(&Opts::default()).is_empty());
    }

    #[test]
    fn parse_scope_and_cleanup_flags() {
        let o = parse(&s(&[
            "--branch",
            "main",
            "--tags",
            "--exclude-ref",
            "refs/tags/x",
            "--prune-backups",
        ]))
        .unwrap();
        assert_eq!(o.branches, vec!["main".to_string()]);
        assert!(o.tags && o.prune_backups);
        assert_eq!(o.exclude_refs, vec!["refs/tags/x".to_string()]);
    }

    #[test]
    fn secrets_to_rules_one_literal_each() {
        let secrets = vec![
            SecretHit {
                secret: "abc123".to_string(),
                rule: "r1".to_string(),
                fingerprint: "c:f:r1:1".to_string(),
            },
            SecretHit {
                secret: "def456".to_string(),
                rule: "r2".to_string(),
                fingerprint: "c:f:r2:2".to_string(),
            },
            // a repeated VALUE (different finding) collapses to one literal rule.
            SecretHit {
                secret: "abc123".to_string(),
                rule: "r1".to_string(),
                fingerprint: "c:g:r1:9".to_string(),
            },
        ];
        let rules = secrets_to_rules(&secrets, "***");
        assert_eq!(rules.literals.len(), 2, "dedup by secret value");
        assert!(rules
            .literals
            .iter()
            .any(|l| l.from == b"abc123" && l.to == b"***"));
    }

    #[test]
    fn json_escape_and_plan_json_shape() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("line\nbreak"), "line\\nbreak");
        let targeted = vec![SecretHit {
            secret: "SECRET".to_string(),
            rule: "aws".to_string(),
            fingerprint: "c:f:aws:5".to_string(),
        }];
        let json = plan_json(
            &targeted,
            1,
            3,
            2,
            &["refs/heads/main".to_string()],
            4,
            1,
            "***",
            "/tmp/bk",
        );
        // Plan carries fingerprint/rule/counts — but NEVER the raw secret value.
        assert!(json.contains("\"fingerprint\":\"c:f:aws:5\""));
        assert!(json.contains("\"affected_blobs\": 3"));
        assert!(json.contains("\"commits\": 4"));
        assert!(json.contains("refs/heads/main"));
        assert!(
            !json.contains("SECRET"),
            "raw secret must never appear in a plan"
        );
    }

    #[test]
    fn fp_matches_identity_forms() {
        assert!(fp_matches("abc123:src/x.rs:aws:5", "abc123:src/x.rs:aws:5")); // full
        assert!(fp_matches("abc123:src/x.rs:aws:5", "abc123")); // prefix
        assert!(fp_matches("v1:abc123:src/x.rs:aws:5", "abc123")); // v1-stripped vs prefix
        assert!(fp_matches("abc123:src/x.rs:aws:5", "v1:abc123")); // query v1-prefixed
        assert!(!fp_matches("abc123:src/x.rs:aws:5", "zzz"));
        assert!(!fp_matches("abc123:src/x.rs:aws:5", ""));
    }

    #[test]
    fn parse_identity_rewrite_flags() {
        let args = [
            "--match-email",
            "old@example.test",
            "--name",
            "Maintainer",
            "--email",
            "new@example.test",
            "--author-only",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        let parsed = parse(&args).expect("identity flags parse");
        assert_eq!(parsed.identity_match_email, "old@example.test");
        assert_eq!(parsed.identity_name, "Maintainer");
        assert_eq!(parsed.identity_email, "new@example.test");
        assert!(parsed.identity_author_only);
    }

    #[test]
    fn latest_backup_index_picks_max() {
        let dir = std::env::temp_dir().join(format!("gitc_scrub_bk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(latest_backup_index(&dir), None);
        for n in [0u64, 1, 2, 10] {
            std::fs::write(dir.join(format!("backup-{n}.bundle")), b"x").unwrap();
        }
        std::fs::write(dir.join("backup-notanum.bundle"), b"x").unwrap();
        std::fs::write(dir.join("backup-3.refs"), b"x").unwrap(); // not a .bundle
        assert_eq!(latest_backup_index(&dir), Some(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mask_never_reveals_full_secret() {
        let m = mask("supersecretvalue");
        assert!(m.starts_with("supe"));
        assert!(!m.contains("supersecretvalue"));
        assert!(m.contains("16 chars"));
    }

    #[test]
    fn unknown_subcommand_is_usage_error() {
        assert_eq!(run(&s(&["frobnicate"])), EXIT_USAGE);
        assert_eq!(run(&[]), EXIT_USAGE);
    }

    // Full command-level rewrite: build a repo with a secret, `scrub secret`, and
    // assert it is redacted, verification passed (exit 0), and a backup exists.
    // Ignored by default — needs a plain git; run with:
    //   set LENSR_GIT_REAL_GIT=…\git.exe
    //   cargo test --features scrub -- --ignored e2e_scrub_secret
    #[test]
    #[ignore = "needs a plain git; run with LENSR_GIT_REAL_GIT set"]
    fn e2e_scrub_secret_redacts_and_verifies() {
        let git = resolve_git();
        let dir = std::env::temp_dir().join(format!("gitc_scrub_e2e_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();
        let g = |args: &[&str]| {
            git_output(&git, &d, args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))
        };
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.name", "T"]);
        g(&["config", "user.email", "t@example.com"]);
        g(&["config", "commit.gpgsign", "false"]);
        // Assemble the AWS-shaped secret at runtime (never a contiguous literal here).
        let secret = format!("AKIA{}", "Z3XQ7RTPKMWV4C2D");
        std::fs::write(dir.join("cfg.txt"), format!("aws_key = \"{secret}\"\n")).unwrap();
        g(&["add", "-A"]);
        g(&["commit", "-q", "-m", "add secret"]);

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let code = run(&s(&["secret", "--force"]));
        std::env::set_current_dir(&prev).unwrap();

        assert_eq!(
            code, EXIT_CLEAN,
            "scrub secret should rewrite + verify clean"
        );
        let head = git_output(&git, &d, &["show", "HEAD:cfg.txt"]).unwrap();
        assert!(!head.contains(&secret), "secret still present: {head}");
        assert!(
            head.contains(DEFAULT_REDACTION),
            "redaction marker missing: {head}"
        );
        let bk = backup_dir(&git, &d).unwrap();
        assert!(
            latest_backup_index(&bk).is_some(),
            "a backup bundle should exist"
        );
        g(&["fsck", "--full"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
