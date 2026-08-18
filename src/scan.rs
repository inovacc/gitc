//! Secret scanner over a repo's git objects — the gitleaks/betterleaks-rs (detect) engine.
//!
//! `commit_scan` reproduces the Go gate's `scanStaged`: it reads the staged blob
//! set from `.git/index` (on-disk parse, `gitindex`), reads each loose blob
//! (`gitobj`), and runs the ported `detect` engine (the `betterleaks-rs` gitleaks
//! port) over the content. A finding is returned as Scan::Findings; the caller decides warn-vs-block. Secrets are credential-masked before they ever reach a message.
//!
//! Scope/limits (logged, never silent): only loose (unpacked) blobs are read —
//! packed blobs are skipped; binary and very large blobs are skipped; `push_scan`
//! (outgoing-diff scan) is a follow-up. Any index/IO error fails OPEN with a
//! warning (the scan is warn-by-default), matching the gate's fail-open floor.

use std::path::{Path, PathBuf};

use crate::gitargs::Invocation;

/// Per-blob and total scan budgets (mirrors the Go gate's bounded scan).
const MAX_BLOB_BYTES: usize = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of a secret scan.
pub enum Scan {
    /// No secrets found — proceed.
    Clean,
    /// Secrets found. `hits` are already credential-masked, human-readable.
    Findings { hits: Vec<String> },
}

/// Scan the staged content about to be committed (the `.git/index` blob set).
pub fn commit_scan(inv: &Invocation) -> Scan {
    match scan_staged(inv) {
        Ok(hits) if !hits.is_empty() => Scan::Findings { hits },
        Ok(_) => Scan::Clean,
        Err(e) => {
            // Fail-open with a loud breadcrumb — never silently pass.
            eprintln!("gitc: secret scan skipped ({e})");
            Scan::Clean
        }
    }
}

/// Scan the outgoing content about to be pushed — the blobs in commits reachable
/// from the local branch tip but not from its remote-tracking tip (seam 4,
/// `gitwalk`). Fail-open: any resolution/IO error yields Clean with a breadcrumb.
pub fn push_scan(inv: &Invocation) -> Scan {
    match scan_push(inv) {
        Ok(hits) if !hits.is_empty() => Scan::Findings { hits },
        Ok(_) => Scan::Clean,
        Err(e) => {
            eprintln!("gitc: push secret scan skipped ({e})");
            Scan::Clean
        }
    }
}

/// The real outgoing-blob scan: resolve the push range, enumerate new blobs, detect.
fn scan_push(inv: &Invocation) -> Result<Vec<String>, String> {
    let gitdir = discover_gitdir(inv)?;
    let branch = crate::gitwalk::current_branch(&gitdir)
        .ok_or("detached HEAD — push scan needs a branch")?;
    let local = crate::gitwalk::resolve_ref(&gitdir, &format!("refs/heads/{branch}"))
        .ok_or("local branch tip unresolved")?;
    let remote = push_remote_name(inv);
    // The tracking tip bounds the walk to genuinely-new commits; if it is absent
    // (never fetched / first push) the walk falls back to the capped local history.
    let tracking = crate::gitwalk::resolve_ref(&gitdir, &format!("refs/remotes/{remote}/{branch}"));
    let (blobs, truncated) = crate::gitwalk::pushed_blobs(&gitdir, &local, tracking.as_deref());
    if truncated {
        eprintln!("gitc: push secret scan truncated (history/blob cap) — partial scan");
    }

    let detector = detect::Detector::with_default_rules();
    let mut hits = Vec::new();
    let mut total = 0usize;
    for b in blobs {
        let content = match crate::gitobj::read_blob(&gitdir, &b.oid_hex, MAX_BLOB_BYTES) {
            Ok(Some(c)) => c,
            Ok(None) => continue, // non-blob / oversized — skipped
            Err(e) => {
                eprintln!("gitc: skipped {} ({e})", b.path);
                continue;
            }
        };
        if is_binary(&content) {
            continue;
        }
        total += content.len();
        if total > MAX_TOTAL_BYTES {
            eprintln!("gitc: push secret scan truncated (exceeded {MAX_TOTAL_BYTES} bytes)");
            break;
        }
        for f in detector.detect_bytes(&content) {
            let mut crc = flate2::Crc::new();
            crc.update(f.secret.as_bytes());
            let hash = crc.sum();
            hits.push(format!(
                "{}:{} [{}] {} [{:08x}]",
                b.path,
                f.start_line,
                f.rule_id,
                detect::masked(&f),
                hash
            ));
        }
    }
    Ok(hits)
}

/// Value-taking push options whose following token is a value, not the remote name.
const PUSH_VALUE_OPTS: &[&str] = &[
    "-o",
    "--push-option",
    "--repo",
    "--upload-pack",
    "--receive-pack",
    "--exec",
];

/// The remote NAME a push targets — the first bare non-option token after the verb,
/// unless it is URL-shaped (a URL push has no local tracking ref → default `origin`,
/// which fail-safely yields the capped local-history fallback). Defaults to `origin`.
fn push_remote_name(inv: &Invocation) -> String {
    let mut skip_next = false;
    for tok in &inv.rest {
        if skip_next {
            skip_next = false;
            continue;
        }
        if tok.starts_with('-') {
            if PUSH_VALUE_OPTS.contains(&tok.as_str()) {
                skip_next = true;
            }
            continue;
        }
        // A URL-shaped remote maps to no tracking ref → fall back to origin.
        if tok.contains("://") || (tok.contains('@') && tok.contains(':')) {
            return "origin".to_string();
        }
        return tok.clone();
    }
    "origin".to_string()
}

/// The real staged-blob scan. Returns masked, human-readable hit lines.
fn scan_staged(inv: &Invocation) -> Result<Vec<String>, String> {
    let gitdir = discover_gitdir(inv)?;
    let index = std::fs::read(gitdir.join("index")).map_err(|e| format!("read index: {e}"))?;
    let entries = crate::gitindex::parse(&index)?;

    let detector = detect::Detector::with_default_rules();
    let mut hits = Vec::new();
    let mut total = 0usize;

    for entry in entries {
        // read_blob caps inflation at MAX_BLOB_BYTES (zlib-bomb guard); an oversized
        // or bomb object returns None and is skipped without full inflation.
        let content = match crate::gitobj::read_blob(&gitdir, &entry.oid_hex, MAX_BLOB_BYTES) {
            Ok(Some(c)) => c,
            Ok(None) => continue, // packed / non-blob / oversized — skipped
            Err(e) => {
                eprintln!("gitc: skipped {} ({e})", entry.path);
                continue;
            }
        };
        if is_binary(&content) {
            continue;
        }
        total += content.len();
        if total > MAX_TOTAL_BYTES {
            eprintln!("gitc: secret scan truncated (exceeded {MAX_TOTAL_BYTES} bytes)");
            break;
        }
        for f in detector.detect_bytes(&content) {
            let mut crc = flate2::Crc::new();
            crc.update(f.secret.as_bytes());
            let hash = crc.sum();
            hits.push(format!(
                "{}:{} [{}] {} [{:08x}]",
                entry.path,
                f.start_line,
                f.rule_id,
                detect::masked(&f),
                hash
            ));
        }
    }
    Ok(hits)
}

/// Find the `.git` directory, honoring `-C` dirs then walking up from there.
/// A `.git` FILE (worktree/submodule pointer) is a follow-up — reported as such.
fn discover_gitdir(inv: &Invocation) -> Result<PathBuf, String> {
    let mut start = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    for c in &inv.c_dirs {
        let p = Path::new(c);
        start = if p.is_absolute() {
            p.to_path_buf()
        } else {
            start.join(p)
        };
    }

    let mut dir = start.as_path();
    loop {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Ok(candidate);
        }
        if candidate.is_file() {
            return Err(".git is a file (worktree/submodule) — scan not yet supported".into());
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => return Err("not inside a git repository".into()),
        }
    }
}

/// Heuristic binary check: a NUL byte in the first 8 KB (git's own heuristic).
fn is_binary(content: &[u8]) -> bool {
    content.iter().take(8192).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv_rest(parts: &[&str]) -> Invocation {
        Invocation {
            rest: parts.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn push_remote_name_defaults_and_reads_named() {
        assert_eq!(push_remote_name(&inv_rest(&[])), "origin"); // bare push
        assert_eq!(push_remote_name(&inv_rest(&["--tags"])), "origin");
        assert_eq!(
            push_remote_name(&inv_rest(&["upstream", "main"])),
            "upstream"
        );
        assert_eq!(
            push_remote_name(&inv_rest(&["--force", "origin", "main"])),
            "origin"
        );
        // -o VALUE must not be mistaken for the remote.
        assert_eq!(
            push_remote_name(&inv_rest(&["-o", "ci.skip", "origin"])),
            "origin"
        );
        // A URL push has no tracking ref → fall back to origin.
        assert_eq!(
            push_remote_name(&inv_rest(&["https://github.com/o/r", "main"])),
            "origin"
        );
        assert_eq!(
            push_remote_name(&inv_rest(&["git@github.com:o/r", "main"])),
            "origin"
        );
    }

    #[test]
    fn is_binary_detects_nul() {
        assert!(is_binary(b"abc\0def"));
        assert!(!is_binary(b"plain text content"));
    }
}
