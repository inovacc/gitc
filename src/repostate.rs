//! Per-repository gitc ledger at `.git/gitc/state.json`.
//!
//! Records what gitc observed **about this clone**: which gates ran and how they
//! ruled, secret leaks found, and vulnerabilities detected. It answers "what does
//! gitc know about this repo right now" without a query against the machine-wide
//! forensic audit DB.
//!
//! ## This file is ADVISORY. It is never authoritative.
//!
//! `.git/` is writable by every process that can write the working tree. Anything
//! stored here can be edited, truncated, or deleted by exactly the actor a gate
//! exists to stop. So:
//!
//! - **No gate decision may read this file.** There is deliberately no
//!   `is_clean()`, no `last_verdict_allows()`, no cache the gate consults. The API
//!   below only *writes*, plus a [`load`] for humans and `gitc` reporting commands.
//!   The moment a gate trusts a repo-writable file, the gate is decorative —
//!   an attacker deletes the "leak found" row and pushes.
//! - The authoritative trail stays the machine-scoped, hash-chained audit DB
//!   ([`crate::store`]), which lives outside the repo under the user profile.
//!
//! Think of it as the repo's notebook, not its lock.
//!
//! ## No secret value is ever written here
//!
//! A leak row stores a **fingerprint** — a truncated SHA-256 over rule, path, line
//! and the matched text — never the match itself. [`LeakRecord`] has no field that
//! could hold one: [`LeakRecord::new`] consumes the secret to hash it and drops it.
//! That is a type-level guarantee rather than a review convention, because this
//! file is far more likely to be copied around than the audit DB — it rides along
//! in any `.git` directory someone zips, syncs, or shares.
//!
//! ## Growth
//!
//! Every section is capped and keeps the newest entries. A per-invocation ledger
//! with no retention policy is an unbounded file on a developer's disk.

#![cfg(feature = "app")]

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Schema version of `state.json`.
pub const SCHEMA_VERSION: i64 = 1;

/// Directory created inside the git dir.
pub const DIR_NAME: &str = "gitc";
/// The ledger filename inside [`DIR_NAME`].
pub const FILE_NAME: &str = "state.json";

/// Most recent gate verdicts retained.
pub const MAX_GATES: usize = 200;
/// Most recent leak fingerprints retained.
pub const MAX_LEAKS: usize = 500;
/// Most recent vulnerability records retained.
pub const MAX_VULNS: usize = 200;

/// The whole ledger.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RepoState {
    /// Schema version ([`SCHEMA_VERSION`]).
    pub version: i64,
    /// RFC 3339 UTC timestamp of the last write.
    pub updated_at: String,
    /// Gate verdicts, oldest first, newest last.
    pub gates: Vec<GateRecord>,
    /// Secret-leak fingerprints. **Never secret values** — see the module docs.
    pub leaks: Vec<LeakRecord>,
    /// Vulnerabilities detected against this repo's dependencies.
    pub vulns: Vec<VulnRecord>,
}

/// One gate verdict — internal (the built-in enforcement gate) or external (a
/// command named by the machine policy).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GateRecord {
    /// Gate label, e.g. `"gate"` or the policy's `stages.pre[].name`.
    pub name: String,
    /// `"internal"` or `"external"`.
    pub kind: String,
    /// `"allow"`, `"block"`, or `"error"` (the gate itself failed to run).
    pub verdict: String,
    /// Exit code the gate produced (0 when it allowed).
    pub code: i32,
    /// The git subcommand it ruled on, e.g. `"push"`.
    pub subcommand: String,
    /// RFC 3339 UTC.
    pub at: String,
}

/// A secret-leak sighting, identified only by fingerprint.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LeakRecord {
    /// Detection rule id, e.g. `"aws-access-token"`.
    pub rule_id: String,
    /// Repo-relative path the match was found in.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// Truncated SHA-256 over rule/path/line/match. Stable across runs, and not
    /// reversible to the secret.
    pub fingerprint: String,
    /// RFC 3339 UTC.
    pub at: String,
}

impl LeakRecord {
    /// Builds a record, hashing `secret` into the fingerprint and dropping it.
    ///
    /// `secret` is taken by reference and never stored; there is no field for it.
    pub fn new(rule_id: &str, path: &str, line: u32, secret: &str) -> LeakRecord {
        LeakRecord {
            rule_id: rule_id.to_string(),
            path: path.to_string(),
            line,
            fingerprint: fingerprint(rule_id, path, line, secret),
            at: now_rfc3339(),
        }
    }
}

/// A vulnerability detected against this repo.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnRecord {
    /// Advisory id, e.g. `"RUSTSEC-2026-0194"`.
    pub id: String,
    /// Affected package name.
    pub package: String,
    /// Affected version.
    pub version: String,
    /// Advisory severity as reported by the source, e.g. `"high"`.
    pub severity: String,
    /// Where the finding came from, e.g. `"cargo-audit"`.
    pub source: String,
    /// RFC 3339 UTC.
    pub at: String,
}

/// Truncated SHA-256 identifying a leak without revealing it.
///
/// The secret participates so two different secrets on the same line are distinct
/// rows; 128 bits of the digest is ample for dedup and far too little to invert.
fn fingerprint(rule_id: &str, path: &str, line: u32, secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // Length-prefix each field so ("ab","c") and ("a","bc") cannot collide.
    for part in [rule_id, path, &line.to_string(), secret] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    let d = h.finalize();
    d[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Current UTC time, RFC 3339. Empty if formatting fails (never a fake time).
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Resolves this repository's git directory.
///
/// Honors `GIT_DIR`, then walks up from `start` looking for `.git`. Handles `.git`
/// being a **file** rather than a directory — that is the normal shape inside a
/// linked worktree or a submodule, where it holds `gitdir: <path>`; treating it as
/// a directory there would silently write the ledger nowhere.
pub fn git_dir_from(start: &Path) -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("GIT_DIR") {
        let p = PathBuf::from(d);
        if p.exists() {
            return Some(p);
        }
    }

    for dir in start.ancestors() {
        let dot = dir.join(".git");
        if dot.is_dir() {
            return Some(dot);
        }
        if dot.is_file() {
            // `gitdir: <path>` — absolute, or relative to the file's own directory.
            let txt = std::fs::read_to_string(&dot).ok()?;
            let rest = txt.split_once("gitdir:").map(|(_, r)| r.trim())?;
            let p = PathBuf::from(rest);
            let p = if p.is_absolute() { p } else { dir.join(p) };
            return std::fs::canonicalize(&p).ok().or(Some(p));
        }
        // A bare repo: the directory itself is the git dir.
        if dir.join("HEAD").is_file() && dir.join("objects").is_dir() {
            return Some(dir.to_path_buf());
        }
    }

    None
}

/// [`git_dir_from`] anchored at the current directory.
pub fn git_dir() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    git_dir_from(&cwd)
}

/// Path to the ledger inside `git_dir`.
pub fn path_in(git_dir: &Path) -> PathBuf {
    git_dir.join(DIR_NAME).join(FILE_NAME)
}

/// Reads the ledger. A missing file is an empty ledger, not an error. A CORRUPT
/// file is an error — silently replacing unreadable state with a blank slate would
/// destroy the record it exists to keep.
pub fn load(path: &Path) -> io::Result<RepoState> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(RepoState {
                version: SCHEMA_VERSION,
                ..RepoState::default()
            })
        }
        Err(e) => return Err(e),
    };

    serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Writes the ledger atomically: a sibling temp file, then a rename.
///
/// Several gitc processes can touch one repo at once; a half-written `state.json`
/// would be read back as corruption by all of them.
pub fn save(path: &Path, st: &RepoState) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut out = st.clone();
    out.version = SCHEMA_VERSION;
    out.updated_at = now_rfc3339();
    truncate(&mut out);

    let data = serde_json::to_vec_pretty(&out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, &data)?;
    // Windows rename fails onto an existing path; remove first. The window this
    // opens is acceptable here — a lost advisory ledger is a lost note, not a lost
    // control (see the module docs).
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Drops the oldest entries past each section cap.
fn truncate(st: &mut RepoState) {
    if st.gates.len() > MAX_GATES {
        st.gates.drain(..st.gates.len() - MAX_GATES);
    }
    if st.leaks.len() > MAX_LEAKS {
        st.leaks.drain(..st.leaks.len() - MAX_LEAKS);
    }
    if st.vulns.len() > MAX_VULNS {
        st.vulns.drain(..st.vulns.len() - MAX_VULNS);
    }
}

/// Read-modify-write against the current repo's ledger.
///
/// **Best-effort by design.** Not being in a repo, or not being able to write
/// `.git/`, is not an error worth failing a git command over — this is a notebook.
/// Returns whether the write happened, for tests and for `gitc doctor`.
pub fn update<F: FnOnce(&mut RepoState)>(f: F) -> bool {
    let Some(gd) = git_dir() else { return false };
    update_in(&gd, f)
}

/// [`update`] against an explicit git dir (the testable core).
pub fn update_in<F: FnOnce(&mut RepoState)>(git_dir: &Path, f: F) -> bool {
    let path = path_in(git_dir);
    let mut st = match load(&path) {
        Ok(s) => s,
        // A corrupt ledger is reported once and then rebuilt — the alternative is a
        // repo that can never record anything again.
        Err(e) => {
            eprintln!("gitc: repo ledger unreadable ({e}); starting a new one");
            RepoState {
                version: SCHEMA_VERSION,
                ..RepoState::default()
            }
        }
    };

    f(&mut st);

    match save(&path, &st) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("gitc: repo ledger write skipped: {e}");
            false
        }
    }
}

/// Appends one gate verdict.
pub fn record_gate(name: &str, kind: &str, verdict: &str, code: i32, subcommand: &str) -> bool {
    let rec = GateRecord {
        name: name.to_string(),
        kind: kind.to_string(),
        verdict: verdict.to_string(),
        code,
        subcommand: subcommand.to_string(),
        at: now_rfc3339(),
    };
    update(|st| st.gates.push(rec))
}

/// Appends leak fingerprints, skipping any whose fingerprint is already recorded.
pub fn record_leaks(new: &[LeakRecord]) -> bool {
    if new.is_empty() {
        return false;
    }
    update(|st| {
        for r in new {
            if !st.leaks.iter().any(|e| e.fingerprint == r.fingerprint) {
                st.leaks.push(r.clone());
            }
        }
    })
}

/// Appends vulnerability records, skipping duplicates by `(id, package, version)`.
pub fn record_vulns(new: &[VulnRecord]) -> bool {
    if new.is_empty() {
        return false;
    }
    update(|st| {
        for r in new {
            let dup = st
                .vulns
                .iter()
                .any(|e| e.id == r.id && e.package == r.package && e.version == r.version);
            if !dup {
                st.vulns.push(r.clone());
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Tmp {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "gitc-repostate-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn roundtrip_through_the_git_dir() {
        let t = Tmp::new();
        assert!(update_in(&t.0, |st| {
            st.gates.push(GateRecord {
                name: "gate".into(),
                kind: "internal".into(),
                verdict: "block".into(),
                code: 1,
                subcommand: "push".into(),
                at: "2026-08-20T00:00:00Z".into(),
            })
        }));

        let got = load(&path_in(&t.0)).unwrap();
        assert_eq!(got.version, SCHEMA_VERSION);
        assert_eq!(got.gates.len(), 1);
        assert_eq!(got.gates[0].verdict, "block");
        assert!(!got.updated_at.is_empty(), "save must stamp updated_at");
    }

    /// The guarantee the whole design rests on.
    #[test]
    fn the_secret_never_reaches_the_file() {
        let t = Tmp::new();
        // Built at runtime by `testkeys` — no literal provider-shaped token is
        // committed anywhere in this repository.
        let secret = testkeys::aws(1);
        let secret = secret.as_str();
        let rec = LeakRecord::new("aws-access-token", "src/cfg.rs", 12, secret);

        assert!(update_in(&t.0, |st| st.leaks.push(rec)));

        let raw = std::fs::read_to_string(path_in(&t.0)).unwrap();
        assert!(
            !raw.contains(secret),
            "the secret value must never appear in the ledger"
        );
        assert!(raw.contains("aws-access-token"), "rule id should be present");

        let got = load(&path_in(&t.0)).unwrap();
        assert_eq!(got.leaks[0].fingerprint.len(), 32, "128-bit hex fingerprint");
    }

    #[test]
    fn fingerprints_are_stable_and_field_separated() {
        let a = fingerprint("r", "p", 1, "s");
        assert_eq!(a, fingerprint("r", "p", 1, "s"), "must be deterministic");
        assert_ne!(a, fingerprint("r", "p", 1, "s2"), "secret participates");
        // Length prefixing: ("ab","c") must not collide with ("a","bc").
        assert_ne!(fingerprint("ab", "c", 1, "s"), fingerprint("a", "bc", 1, "s"));
    }

    #[test]
    fn missing_file_loads_as_empty_not_error() {
        let t = Tmp::new();
        let st = load(&path_in(&t.0)).unwrap();
        assert_eq!(st.version, SCHEMA_VERSION);
        assert!(st.gates.is_empty() && st.leaks.is_empty() && st.vulns.is_empty());
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_silent_reset() {
        let t = Tmp::new();
        let p = path_in(&t.0);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"{not json").unwrap();

        assert!(
            load(&p).is_err(),
            "corruption must surface, not read back as an empty ledger"
        );
    }

    #[test]
    fn sections_are_capped_to_the_newest_entries() {
        let mut st = RepoState::default();
        for i in 0..(MAX_GATES + 25) {
            st.gates.push(GateRecord {
                name: format!("g{i}"),
                ..GateRecord::default()
            });
        }
        truncate(&mut st);

        assert_eq!(st.gates.len(), MAX_GATES);
        assert_eq!(
            st.gates[0].name,
            format!("g{}", 25),
            "the OLDEST entries are the ones dropped"
        );
    }

    #[test]
    fn resolves_a_dot_git_directory() {
        let t = Tmp::new();
        let work = t.0.join("work");
        let gd = work.join(".git");
        std::fs::create_dir_all(gd.join("objects")).unwrap();
        let nested = work.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(git_dir_from(&nested), Some(gd));
    }

    /// A linked worktree or submodule has `.git` as a FILE pointing elsewhere.
    #[test]
    fn resolves_a_dot_git_file_pointing_elsewhere() {
        let t = Tmp::new();
        let real = t.0.join("real-git-dir");
        std::fs::create_dir_all(&real).unwrap();
        let work = t.0.join("wt");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join(".git"), format!("gitdir: {}\n", real.display())).unwrap();

        let got = git_dir_from(&work).expect("should resolve the gitdir pointer");
        assert!(
            got.ends_with("real-git-dir"),
            "expected the pointed-to dir, got {got:?}"
        );
    }

    #[test]
    fn leak_dedup_is_by_fingerprint() {
        let t = Tmp::new();
        let r = LeakRecord::new("rule", "p.rs", 3, "s3cr3t");
        assert!(update_in(&t.0, |st| st.leaks.push(r.clone())));
        assert!(update_in(&t.0, |st| {
            if !st.leaks.iter().any(|e| e.fingerprint == r.fingerprint) {
                st.leaks.push(r.clone());
            }
        }));

        assert_eq!(load(&path_in(&t.0)).unwrap().leaks.len(), 1);
    }
}

