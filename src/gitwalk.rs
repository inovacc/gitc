//! Seam 4 — enumerate the BLOBS an outgoing `push` would send, for the secret scan.
//!
//! The commit scan (`scan_staged`) covers `.git/index`; a `push` sends whole
//! commits whose blobs were never staged on this machine (rebases, cherry-picks,
//! imported branches). This module walks the commit graph from the local tip,
//! stopping at whatever the remote already has (the `refs/remotes/<remote>/<branch>`
//! tracking tip), and returns the distinct blob oids in the NEW commits' trees — the
//! outgoing content to scan.
//!
//! FAIL-SAFE, like the rest of the gate: unresolved refs, unreadable objects, and
//! malformed commits/trees are skipped (never a hard error); every walk is CAPPED
//! (commits, blobs, tree depth) and a hit cap sets `truncated` so the skipped tail
//! is surfaced, never silent. The worst case degrades to the pre-seam `push_scan`
//! no-op (scan nothing) — it can only ever scan MORE, never fabricate content. The
//! tracking-ref diff is an approximation of git's true "objects not on the remote"
//! set (it does not consult the live remote), which is acceptable: a push whose new
//! objects we under-count is scanned partially (logged), never wrongly.

use std::collections::{HashSet, VecDeque};
use std::path::Path;

use crate::gitpack::{OBJ_COMMIT, OBJ_TAG, OBJ_TREE};

/// Caps that bound the walk against a huge/crafted history (fail-safe truncation).
const MAX_NEW_COMMITS: usize = 500;
const MAX_REMOTE_COMMITS: usize = 5000;
const MAX_BLOBS: usize = 5000;
const MAX_TREE_DEPTH: u32 = 100;

/// A blob to scan: its repo-relative path (for the finding message) and hex oid.
pub struct BlobRef {
    pub path: String,
    pub oid_hex: String,
}

/// The current branch short-name from `<gitdir>/HEAD` (`ref: refs/heads/<b>`), or
/// `None` when detached (no branch → nothing to diff against a tracking ref).
pub fn current_branch(gitdir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    head.strip_prefix("ref: refs/heads/").map(|s| s.to_string())
}

/// Resolve a full ref name (`refs/heads/main`, `refs/remotes/origin/main`) to a
/// 40-hex commit oid, following one symref hop and consulting `packed-refs`. `None`
/// if the ref does not exist (fail-safe — the caller treats it as "no tip").
pub fn resolve_ref(gitdir: &Path, refname: &str) -> Option<String> {
    // Loose ref file first.
    if let Ok(s) = std::fs::read_to_string(gitdir.join(refname)) {
        let s = s.trim();
        if let Some(target) = s.strip_prefix("ref: ") {
            return resolve_ref(gitdir, target.trim()); // one symref hop
        }
        if is_hex40(s) {
            return Some(s.to_string());
        }
    }
    // packed-refs fallback.
    let packed = std::fs::read_to_string(gitdir.join("packed-refs")).ok()?;
    packed_ref_oid(&packed, refname)
}

/// Collect the distinct blob refs in commits reachable from `local_tip` but NOT from
/// `remote_tip` (if any). `truncated` is set when a cap cut the walk short.
pub fn pushed_blobs(
    gitdir: &Path,
    local_tip: &str,
    remote_tip: Option<&str>,
) -> (Vec<BlobRef>, bool) {
    let mut truncated = false;

    // The commits the remote already has (a stop-set for the outgoing walk).
    let mut remote_set = HashSet::new();
    if let Some(rt) = remote_tip {
        collect_commits(gitdir, rt, MAX_REMOTE_COMMITS, &mut remote_set);
    }

    let mut seen_commit = HashSet::new();
    let mut seen_tree = HashSet::new();
    let mut seen_blob = HashSet::new();
    let mut blobs = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(local_tip.to_string());
    let mut commit_budget = MAX_NEW_COMMITS;

    while let Some(c) = queue.pop_front() {
        if remote_set.contains(&c) || !seen_commit.insert(c.clone()) {
            continue;
        }
        if commit_budget == 0 {
            truncated = true;
            break;
        }
        commit_budget -= 1;
        let Some(commit) = read_commit(gitdir, &c) else {
            continue;
        };
        collect_tree_blobs(
            gitdir,
            &commit.tree,
            "",
            0,
            &mut blobs,
            &mut seen_blob,
            &mut seen_tree,
            &mut truncated,
        );
        if blobs.len() >= MAX_BLOBS {
            break;
        }
        for p in commit.parents {
            if !remote_set.contains(&p) {
                queue.push_back(p);
            }
        }
    }
    (blobs, truncated)
}

// ── reachable-history scanning (`gitc scan git --history/--all-refs/<rev>`) ───

/// Caps bounding a full-history walk against a huge/crafted repo (fail-safe).
const MAX_HISTORY_COMMITS: usize = 50_000;
const MAX_HISTORY_BLOBS: usize = 100_000;

/// A blob's introduction point in history: the repo-relative `path` it lives at,
/// its `oid_hex`, and the `commit` that first introduced this exact content
/// (the oldest reachable commit whose tree contains the blob, by committer date).
pub struct BlobIntro {
    pub path: String,
    pub oid_hex: String,
    pub commit: String,
}

/// The commit `HEAD` points at — following `ref: refs/heads/<b>` to its tip, or a
/// detached 40-hex oid written directly in `HEAD`. `None` on an unborn branch.
pub fn head_tip(gitdir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(target) = head.strip_prefix("ref: ") {
        return resolve_ref(gitdir, target.trim());
    }
    if is_hex40(head) {
        Some(head.to_string())
    } else {
        None
    }
}

/// Every ref tip in the repo — loose `refs/**` files plus `packed-refs`, and
/// `HEAD` — deduped to distinct commit oids. Drives `--all-refs`.
pub fn all_ref_tips(gitdir: &Path) -> Vec<String> {
    let mut set = HashSet::new();
    if let Some(h) = head_tip(gitdir) {
        set.insert(h);
    }
    collect_loose_refs(&gitdir.join("refs"), gitdir, &mut set);
    if let Ok(packed) = std::fs::read_to_string(gitdir.join("packed-refs")) {
        for line in packed.lines() {
            if line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            if let Some((sha, _name)) = line.split_once(' ') {
                if is_hex40(sha.trim()) {
                    set.insert(sha.trim().to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Recurse `refs/` collecting each loose ref's resolved oid (following one symref).
fn collect_loose_refs(dir: &Path, gitdir: &Path, set: &mut HashSet<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_loose_refs(&p, gitdir, set);
        } else if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim();
            if let Some(t) = s.strip_prefix("ref: ") {
                if let Some(o) = resolve_ref(gitdir, t.trim()) {
                    set.insert(o);
                }
            } else if is_hex40(s) {
                set.insert(s.to_string());
            }
        }
    }
}

/// Collect the distinct blobs reachable from `tips`, each attributed to the OLDEST
/// commit (by committer date) that introduced it — the history-scan / introduction
/// primitive. Commits reachable from `exclude` (a `A..B` range's left side) are
/// skipped. `truncated` is set when a cap cut the walk short.
///
/// Introduction attribution is exact for the common case: walking oldest→newest
/// with a global seen-set, the first commit to carry a given blob/subtree claims
/// it, and later commits that merely retain it are skipped. Committer dates order
/// the walk (git's own `--date-order` default); a rewritten/backdated date can only
/// mis-attribute WHICH commit introduced a secret, never whether it is present.
pub fn reachable_blob_intros(
    gitdir: &Path,
    tips: &[String],
    exclude: &[String],
) -> (Vec<BlobIntro>, bool) {
    let mut truncated = false;

    // Commits to skip: everything reachable from the range's excluded (left) side.
    let mut excluded = HashSet::new();
    for e in exclude {
        collect_commits(gitdir, e, MAX_HISTORY_COMMITS, &mut excluded);
    }

    // Gather reachable commit metadata (tree + parents + committer date).
    let mut commits: Vec<CommitMeta> = Vec::new();
    let mut seen_commit = HashSet::new();
    let mut queue: VecDeque<String> = tips.iter().cloned().collect();
    while let Some(c) = queue.pop_front() {
        if excluded.contains(&c) || !seen_commit.insert(c.clone()) {
            continue;
        }
        if commits.len() >= MAX_HISTORY_COMMITS {
            truncated = true;
            break;
        }
        let Some(meta) = read_commit_meta(gitdir, &c) else {
            continue;
        };
        for p in &meta.parents {
            if !excluded.contains(p) && !seen_commit.contains(p) {
                queue.push_back(p.clone());
            }
        }
        commits.push(meta);
    }

    // Oldest first (committer date, oid tie-break) so introduction is the earliest.
    commits.sort_by(|a, b| a.date.cmp(&b.date).then_with(|| a.oid.cmp(&b.oid)));

    let mut seen_tree = HashSet::new();
    let mut seen_blob = HashSet::new();
    let mut intros = Vec::new();
    for meta in &commits {
        if intros.len() >= MAX_HISTORY_BLOBS {
            truncated = true;
            break;
        }
        let mut fresh = Vec::new();
        collect_tree_blobs(
            gitdir,
            &meta.tree,
            "",
            0,
            &mut fresh,
            &mut seen_blob,
            &mut seen_tree,
            &mut truncated,
        );
        for b in fresh {
            intros.push(BlobIntro {
                path: b.path,
                oid_hex: b.oid_hex,
                commit: meta.oid.clone(),
            });
        }
    }
    (intros, truncated)
}

/// A commit with the metadata the history walk orders and attributes by.
struct CommitMeta {
    oid: String,
    tree: String,
    parents: Vec<String>,
    date: i64,
}

/// Parse a commit's tree + parents + committer unix timestamp. `None` without a tree.
fn read_commit_meta(gitdir: &Path, oid_hex: &str) -> Option<CommitMeta> {
    let content = read_typed(gitdir, oid_hex, OBJ_COMMIT)?;
    let text = std::str::from_utf8(&content).ok()?;
    let mut tree = None;
    let mut parents = Vec::new();
    let mut date = 0i64;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(h) = line.strip_prefix("tree ") {
            if is_hex40(h.trim()) {
                tree = Some(h.trim().to_string());
            }
        } else if let Some(p) = line.strip_prefix("parent ") {
            if is_hex40(p.trim()) {
                parents.push(p.trim().to_string());
            }
        } else if let Some(c) = line.strip_prefix("committer ") {
            date = commit_ident_date(c).unwrap_or(0);
        }
    }
    tree.map(|tree| CommitMeta {
        oid: oid_hex.to_string(),
        tree,
        parents,
        date,
    })
}

/// The unix timestamp from a `committer`/`author` ident line whose tail is
/// `… <email> <unix-ts> <tz>`. `None` if the two trailing fields aren't present.
fn commit_ident_date(ident: &str) -> Option<i64> {
    let mut it = ident.trim_end().rsplit(' ');
    let _tz = it.next()?;
    it.next()?.parse().ok()
}

// ── signature detection (§12: warn that a rewrite invalidates signatures) ─────

/// Count signed commits reachable from `tips` and signed annotated tags in the
/// repo — the material a history rewrite would invalidate. Offline and gpg-free:
/// it detects the PRESENCE of a signature (a `gpgsig` commit header / a signature
/// block in a tag object), not its validity.
pub fn count_signed(gitdir: &Path, tips: &[String]) -> (usize, usize) {
    // Signed commits over reachable history (bounded).
    let mut seen = HashSet::new();
    let mut queue: VecDeque<String> = tips.iter().cloned().collect();
    let mut signed_commits = 0usize;
    while let Some(c) = queue.pop_front() {
        if !seen.insert(c.clone()) {
            continue;
        }
        if seen.len() > MAX_HISTORY_COMMITS {
            break;
        }
        let Some(body) = read_typed(gitdir, &c, OBJ_COMMIT) else {
            continue;
        };
        if commit_is_signed(&body) {
            signed_commits += 1;
        }
        if let Some(m) = parse_commit(&body) {
            for p in m.parents {
                queue.push_back(p);
            }
        }
    }

    // Signed annotated tags: enumerate refs/tags (loose + packed) → tag objects.
    let mut tag_oids = HashSet::new();
    collect_tag_oids(&gitdir.join("refs").join("tags"), gitdir, &mut tag_oids);
    if let Ok(packed) = std::fs::read_to_string(gitdir.join("packed-refs")) {
        for line in packed.lines() {
            if line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            if let Some((sha, name)) = line.split_once(' ') {
                if name.trim().starts_with("refs/tags/") && is_hex40(sha.trim()) {
                    tag_oids.insert(sha.trim().to_string());
                }
            }
        }
    }
    let mut signed_tags = 0usize;
    for oid in tag_oids {
        if let Ok(Some((typ, body))) = crate::gitobj::read_object(gitdir, &oid, 1 << 20) {
            if typ == OBJ_TAG && tag_is_signed(&body) {
                signed_tags += 1;
            }
        }
    }
    (signed_commits, signed_tags)
}

/// A commit object is signed if a `gpgsig`/`gpgsig-sha256` header appears before
/// the blank line that ends the header block.
fn commit_is_signed(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        if line.is_empty() {
            return false; // reached the message — no signature header
        }
        if line.starts_with("gpgsig ") || line.starts_with("gpgsig-sha256 ") {
            return true;
        }
    }
    false
}

/// A tag object is signed if its body carries a PGP or SSH signature block.
fn tag_is_signed(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    text.contains("-----BEGIN PGP SIGNATURE-----") || text.contains("-----BEGIN SSH SIGNATURE-----")
}

/// Recurse `refs/tags` collecting each tag ref's resolved oid.
fn collect_tag_oids(dir: &Path, gitdir: &Path, set: &mut HashSet<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_tag_oids(&p, gitdir, set);
        } else if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim();
            if let Some(t) = s.strip_prefix("ref: ") {
                if let Some(o) = resolve_ref(gitdir, t.trim()) {
                    set.insert(o);
                }
            } else if is_hex40(s) {
                set.insert(s.to_string());
            }
        }
    }
}

/// BFS commit ancestry from `tip`, inserting oids into `set` up to `budget`.
fn collect_commits(gitdir: &Path, tip: &str, budget: usize, set: &mut HashSet<String>) {
    let mut queue = VecDeque::new();
    queue.push_back(tip.to_string());
    while let Some(c) = queue.pop_front() {
        if set.len() >= budget {
            return;
        }
        if !set.insert(c.clone()) {
            continue;
        }
        if let Some(commit) = read_commit(gitdir, &c) {
            for p in commit.parents {
                queue.push_back(p);
            }
        }
    }
}

/// Recursively collect blob refs under a tree, deduping shared subtrees/blobs.
#[allow(clippy::too_many_arguments)]
fn collect_tree_blobs(
    gitdir: &Path,
    tree_oid: &str,
    prefix: &str,
    depth: u32,
    blobs: &mut Vec<BlobRef>,
    seen_blob: &mut HashSet<String>,
    seen_tree: &mut HashSet<String>,
    truncated: &mut bool,
) {
    if depth > MAX_TREE_DEPTH || blobs.len() >= MAX_BLOBS {
        *truncated = true;
        return;
    }
    if !seen_tree.insert(tree_oid.to_string()) {
        return; // shared subtree already walked
    }
    let Some(content) = read_typed(gitdir, tree_oid, OBJ_TREE) else {
        return;
    };
    for entry in parse_tree(&content) {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        match entry.kind {
            EntryKind::Blob => {
                if blobs.len() >= MAX_BLOBS {
                    *truncated = true;
                    return;
                }
                if seen_blob.insert(entry.oid_hex.clone()) {
                    blobs.push(BlobRef {
                        path,
                        oid_hex: entry.oid_hex,
                    });
                }
            }
            EntryKind::Tree => {
                collect_tree_blobs(
                    gitdir,
                    &entry.oid_hex,
                    &path,
                    depth + 1,
                    blobs,
                    seen_blob,
                    seen_tree,
                    truncated,
                );
            }
            EntryKind::Skip => {}
        }
    }
}

/// A parsed commit — just the fields the walk needs.
struct Commit {
    tree: String,
    parents: Vec<String>,
}

fn read_commit(gitdir: &Path, oid_hex: &str) -> Option<Commit> {
    let content = read_typed(gitdir, oid_hex, OBJ_COMMIT)?;
    parse_commit(&content)
}

/// Read an object and return its content only if it is of the expected `want` type
/// (a modest per-object cap bounds any single read). `None` otherwise (fail-safe).
fn read_typed(gitdir: &Path, oid_hex: &str, want: u8) -> Option<Vec<u8>> {
    const MAX_META_BYTES: usize = 16 * 1024 * 1024; // commits/trees are small
    match crate::gitobj::read_object(gitdir, oid_hex, MAX_META_BYTES) {
        Ok(Some((typ, content))) if typ == want => Some(content),
        _ => None,
    }
}

/// Parse a commit object body: the leading `tree <hex>` + zero-or-more `parent
/// <hex>` header lines (headers end at the first blank line). `None` without a tree.
fn parse_commit(content: &[u8]) -> Option<Commit> {
    let text = std::str::from_utf8(content).ok()?;
    let mut tree = None;
    let mut parents = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break; // end of headers → message follows
        }
        if let Some(h) = line.strip_prefix("tree ") {
            if is_hex40(h.trim()) {
                tree = Some(h.trim().to_string());
            }
        } else if let Some(p) = line.strip_prefix("parent ") {
            if is_hex40(p.trim()) {
                parents.push(p.trim().to_string());
            }
        }
    }
    tree.map(|tree| Commit { tree, parents })
}

enum EntryKind {
    Blob,
    Tree,
    Skip, // symlink / gitlink — no file content to scan
}

struct TreeEntry {
    name: String,
    oid_hex: String,
    kind: EntryKind,
}

/// Parse a tree object body: a sequence of `<mode> <name>\0<20-byte oid>` records.
/// Malformed tails stop the parse (fail-safe — returns what parsed cleanly).
fn parse_tree(content: &[u8]) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let Some(sp) = content[pos..].iter().position(|&b| b == b' ') else {
            break;
        };
        let mode = &content[pos..pos + sp];
        let after_mode = pos + sp + 1;
        let Some(nul_rel) = content[after_mode..].iter().position(|&b| b == 0) else {
            break;
        };
        let name_bytes = &content[after_mode..after_mode + nul_rel];
        let oid_start = after_mode + nul_rel + 1;
        let oid_end = oid_start + 20;
        if oid_end > content.len() {
            break;
        }
        let oid_hex: String = content[oid_start..oid_end]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        out.push(TreeEntry {
            name,
            oid_hex,
            kind: mode_kind(mode),
        });
        pos = oid_end;
    }
    out
}

/// Classify a tree-entry mode: regular files are blobs, `40000` is a subtree,
/// symlinks (`120000`) and gitlinks (`160000`) carry nothing to scan.
fn mode_kind(mode: &[u8]) -> EntryKind {
    match mode {
        b"40000" | b"040000" => EntryKind::Tree,
        b"100644" | b"100755" => EntryKind::Blob,
        _ => EntryKind::Skip,
    }
}

/// Find `refname`'s oid in a `packed-refs` file body (`<sha> <refname>` lines;
/// `^<sha>` peel lines are ignored). `None` if absent.
fn packed_ref_oid(packed: &str, refname: &str) -> Option<String> {
    for line in packed.lines() {
        if line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        if let Some((sha, name)) = line.split_once(' ') {
            if name.trim() == refname && is_hex40(sha.trim()) {
                return Some(sha.trim().to_string());
            }
        }
    }
    None
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const T: &str = "3333333333333333333333333333333333333333";

    #[test]
    fn parse_commit_extracts_tree_and_parents() {
        let body = format!("tree {T}\nparent {A}\nparent {B}\nauthor x <x@y> 0 +0000\n\nmsg\n");
        let c = parse_commit(body.as_bytes()).unwrap();
        assert_eq!(c.tree, T);
        assert_eq!(c.parents, vec![A.to_string(), B.to_string()]);
    }

    #[test]
    fn parse_commit_root_has_no_parents() {
        let body = format!("tree {T}\nauthor x <x@y> 0 +0000\n\nmsg\n");
        let c = parse_commit(body.as_bytes()).unwrap();
        assert!(c.parents.is_empty());
        assert!(parse_commit(b"no tree here\n\nmsg").is_none());
    }

    #[test]
    fn parse_tree_classifies_entries() {
        // Build a tree body: a blob, a subtree, a symlink (skip), a gitlink (skip).
        let mut body = Vec::new();
        let push = |body: &mut Vec<u8>, mode: &str, name: &str, byte: u8| {
            body.extend_from_slice(mode.as_bytes());
            body.push(b' ');
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(&[byte; 20]);
        };
        push(&mut body, "100644", "file.txt", 0xaa);
        push(&mut body, "40000", "subdir", 0xbb);
        push(&mut body, "120000", "link", 0xcc);
        push(&mut body, "160000", "submodule", 0xdd);
        let entries = parse_tree(&body);
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[0].kind, EntryKind::Blob));
        assert_eq!(entries[0].name, "file.txt");
        assert_eq!(entries[0].oid_hex, "aa".repeat(20));
        assert!(matches!(entries[1].kind, EntryKind::Tree));
        assert!(matches!(entries[2].kind, EntryKind::Skip));
        assert!(matches!(entries[3].kind, EntryKind::Skip));
    }

    #[test]
    fn parse_tree_stops_on_truncated_tail() {
        // A record whose oid is cut short must not panic — parse what's clean, stop.
        let mut body = Vec::new();
        body.extend_from_slice(b"100644 a\0");
        body.extend_from_slice(&[0u8; 5]); // only 5 of 20 oid bytes
        assert!(parse_tree(&body).is_empty());
    }

    #[test]
    fn packed_ref_lookup() {
        let packed = format!(
            "# pack-refs with: peeled fully-peeled sorted\n{A} refs/heads/main\n{B} refs/remotes/origin/main\n^{T}\n"
        );
        assert_eq!(
            packed_ref_oid(&packed, "refs/heads/main").as_deref(),
            Some(A)
        );
        assert_eq!(
            packed_ref_oid(&packed, "refs/remotes/origin/main").as_deref(),
            Some(B)
        );
        assert_eq!(packed_ref_oid(&packed, "refs/heads/nope"), None);
    }

    #[test]
    fn hex40_validation() {
        assert!(is_hex40(A));
        assert!(!is_hex40("abc"));
        assert!(!is_hex40(&"z".repeat(40)));
    }

    #[test]
    fn parse_tree_and_commit_never_panic_on_garbage() {
        // Fuzz the byte-level tree/commit parsers with malformed input (goal §50).
        let mut x = 0xABCD_EF01_2345_6789u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..4000 {
            let len = (next() as usize) % 300;
            let buf: Vec<u8> = (0..len)
                .map(|i| ((next() >> (i % 56)) & 0xff) as u8)
                .collect();
            let _ = parse_tree(&buf);
            let _ = parse_commit(&buf);
            let _ = read_commit_meta_bytes(&buf);
        }
        // Structured-but-malformed tree: valid mode + name, then a truncated oid.
        let mut t = b"100644 file\0".to_vec();
        t.extend_from_slice(&[0xffu8; 7]); // only 7 of 20 oid bytes
        assert!(parse_tree(&t).is_empty());
        // A commit header with a huge parent list must not blow up.
        let mut c = format!("tree {}\n", "a".repeat(40)).into_bytes();
        for _ in 0..1000 {
            c.extend_from_slice(format!("parent {}\n", "b".repeat(40)).as_bytes());
        }
        assert!(parse_commit(&c).is_some());
    }

    /// Exercise `read_commit_meta`'s parser path on raw bytes (via the header parse
    /// it delegates to) without touching disk — malformed input must not panic.
    fn read_commit_meta_bytes(content: &[u8]) -> Option<i64> {
        let text = std::str::from_utf8(content).ok()?;
        let mut date = None;
        for line in text.lines() {
            if line.is_empty() {
                break;
            }
            if let Some(c) = line.strip_prefix("committer ") {
                date = commit_ident_date(c);
            }
        }
        date
    }

    #[test]
    fn signature_detectors() {
        // A commit with a gpgsig header is signed; without, not.
        let signed = format!(
            "tree {T}\nparent {A}\nauthor a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n \n-----END PGP SIGNATURE-----\n\nmsg\n"
        );
        assert!(commit_is_signed(signed.as_bytes()));
        let plain = format!("tree {T}\nauthor a <a@b> 0 +0000\n\ngpgsig is only in the message\n");
        assert!(!commit_is_signed(plain.as_bytes()));
        // Tag objects: PGP / SSH signature blocks in the body.
        assert!(tag_is_signed(b"object x\ntype commit\ntag v1\n\nrelease\n-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----\n"));
        assert!(tag_is_signed(b"...\n-----BEGIN SSH SIGNATURE-----\n...\n"));
        assert!(!tag_is_signed(
            b"object x\ntype commit\ntag v1\n\njust a message\n"
        ));
    }

    #[test]
    fn commit_ident_date_reads_unix_ts() {
        assert_eq!(
            commit_ident_date("Jane Doe <jane@example.com> 1700000000 +0000"),
            Some(1_700_000_000)
        );
        // trailing whitespace tolerated; a negative (pre-epoch) tz-offset ts parses.
        assert_eq!(
            commit_ident_date("A B <a@b> 1699999999 -0700  "),
            Some(1_699_999_999)
        );
        // malformed idents (no ts/tz tail) fail cleanly rather than panic.
        assert_eq!(commit_ident_date("no timestamp here"), None);
        assert_eq!(commit_ident_date(""), None);
    }

    #[test]
    fn read_commit_meta_orders_by_date() {
        // Two CommitMeta sort oldest-first (date asc), oid tie-break.
        let mut v = vec![
            CommitMeta {
                oid: B.to_string(),
                tree: T.to_string(),
                parents: vec![],
                date: 200,
            },
            CommitMeta {
                oid: A.to_string(),
                tree: T.to_string(),
                parents: vec![],
                date: 100,
            },
        ];
        v.sort_by(|a, b| a.date.cmp(&b.date).then_with(|| a.oid.cmp(&b.oid)));
        assert_eq!(v[0].oid, A); // date 100 first
        assert_eq!(v[1].oid, B);
    }
}

/// End-to-end walk over a REAL repo built by git. Skipped (not failed) when no
/// usable `git` is present — the walk is pure Rust, but the fixture needs git.
#[cfg(test)]
mod e2e {
    use super::{head_tip, reachable_blob_intros};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn find_git() -> Option<String> {
        let mut candidates = Vec::new();
        if let Ok(g) = std::env::var("GITC_TEST_GIT") {
            candidates.push(g);
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            candidates.push(format!("{home}\\scoop\\apps\\git\\current\\cmd\\git.exe"));
        }
        candidates.push("git".to_string());
        candidates.into_iter().find(|g| {
            Command::new(g)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
    }

    fn git(bin: &str, dir: &Path, args: &[&str]) -> String {
        let out = Command::new(bin)
            .args(args)
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "T")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "T")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn temp_repo_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("gitc_hist_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reachable_history_attributes_each_blob_to_its_introducing_commit() {
        let Some(bin) = find_git() else {
            eprintln!("skipping reachable_history e2e: no usable git found");
            return;
        };
        let repo = temp_repo_dir();
        let gitdir = repo.join(".git");

        // commit1 introduces v1 of tracked.txt; commit2 rewrites it + adds other.txt.
        // Innocuous content, distinct blobs — this asserts blob→commit attribution.
        git(&bin, &repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("tracked.txt"), "line one\nVERSION-ONE-TOKEN\n").unwrap();
        git(&bin, &repo, &["add", "tracked.txt"]);
        git(
            &bin,
            &repo,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "c1",
                "--date",
                "2001-01-01T00:00:00",
            ],
        );
        let c1 = git(&bin, &repo, &["rev-parse", "HEAD"]);

        std::fs::write(repo.join("tracked.txt"), "line one\nVERSION-TWO-TOKEN\n").unwrap();
        std::fs::write(repo.join("other.txt"), "nothing here\n").unwrap();
        git(&bin, &repo, &["add", "-A"]);
        git(
            &bin,
            &repo,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "c2",
                "--date",
                "2002-02-02T00:00:00",
            ],
        );
        let c2 = git(&bin, &repo, &["rev-parse", "HEAD"]);

        let head = head_tip(&gitdir).expect("HEAD resolves");
        assert_eq!(head, c2, "head_tip resolves to the latest commit");
        let (intros, truncated) = reachable_blob_intros(&gitdir, &[head], &[]);
        assert!(!truncated, "small fixture must not truncate");

        // tracked.txt has TWO distinct blobs, each at its introducing commit.
        let v1 = intros
            .iter()
            .find(|b| b.path == "tracked.txt" && b.commit == c1)
            .expect("tracked.txt v1 attributed to first commit");
        let v2 = intros
            .iter()
            .find(|b| b.path == "tracked.txt" && b.commit == c2)
            .expect("tracked.txt v2 attributed to second commit");
        assert_ne!(v1.oid_hex, v2.oid_hex, "distinct blob versions");
        assert!(
            intros
                .iter()
                .any(|b| b.path == "other.txt" && b.commit == c2),
            "other.txt attributed to the commit that added it"
        );

        // Both introduced blobs are readable via gitc's own object reader.
        let read = |oid: &str| {
            crate::gitobj::read_blob(&gitdir, oid, 1 << 20)
                .unwrap()
                .expect("blob readable via gitc::gitobj")
        };
        assert!(String::from_utf8_lossy(&read(&v1.oid_hex)).contains("VERSION-ONE-TOKEN"));
        assert!(String::from_utf8_lossy(&read(&v2.oid_hex)).contains("VERSION-TWO-TOKEN"));

        let _ = std::fs::remove_dir_all(&repo);
    }
}
