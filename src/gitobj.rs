//! Read git objects by object id — LOOSE first, then PACKED (seam 5, `gitpack`).
//!
//! A loose object lives at `<gitdir>/objects/<oid[0:2]>/<oid[2:]>`, zlib-deflated,
//! with a `"<type> <size>\0"` header before the payload. Freshly `git add`ed blobs
//! are loose (the common pre-commit case). Anything git has packed is read via
//! `gitpack` — so the scan is no longer blind to packed content. Every failure path
//! returns `Ok(None)` (skip), keeping the scan fail-safe.

use std::io::Read;
use std::path::Path;

use flate2::read::ZlibDecoder;

use crate::gitpack::{self, OBJ_BLOB};

/// Read the raw `(type, content)` for `oid_hex` — LOOSE store first, then packs.
/// Returns `Ok(None)` if the object is absent, over `max_bytes` (decompression-bomb
/// guard), or unresolvable. Inflation is capped AT THE READER (`Read::take`) so a
/// zlib bomb stops early instead of exhausting memory (an OOM abort the caller's
/// `Result`-based fail-open could not catch).
pub fn read_object(
    gitdir: &Path,
    oid_hex: &str,
    max_bytes: usize,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    if let Some(obj) = read_loose(gitdir, oid_hex, max_bytes)? {
        return Ok(Some(obj));
    }
    gitpack::read_object(gitdir, oid_hex, max_bytes)
}

/// Read the BLOB content for `oid_hex` (loose or packed), or `Ok(None)` if it is not
/// a blob / absent / over-cap. The secret scan's entry point.
pub fn read_blob(
    gitdir: &Path,
    oid_hex: &str,
    max_bytes: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    match read_object(gitdir, oid_hex, max_bytes)? {
        Some((OBJ_BLOB, content)) => Ok(Some(content)),
        _ => Ok(None),
    }
}

/// Read a loose object's raw `(type, content)`, or `Ok(None)` if there is no loose
/// object at that oid (→ the caller tries packs) or it is over-cap.
fn read_loose(
    gitdir: &Path,
    oid_hex: &str,
    max_bytes: usize,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    if oid_hex.len() < 3 {
        return Ok(None);
    }
    let (dir, rest) = oid_hex.split_at(2);
    let path = gitdir.join("objects").join(dir).join(rest);
    let raw = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None), // maybe packed
        Err(e) => return Err(e),
    };

    // Inflate at most max_bytes + 1: reading one extra byte lets us distinguish
    // "exactly at the cap" (keep) from "over the cap" (skip) without a size oracle.
    let mut decoded = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    ZlibDecoder::new(&raw[..])
        .take(limit)
        .read_to_end(&mut decoded)?;
    if decoded.len() > max_bytes {
        return Ok(None); // oversized / decompression bomb — skip (never fully inflated)
    }

    // Header: "<type> <size>\0". Map the type word to its code; only blobs carry
    // file content worth scanning, but trees/commits are read by the push walk.
    let Some(nul) = decoded.iter().position(|&b| b == 0) else {
        return Ok(None);
    };
    let Some(typ) = loose_type(&decoded[..nul]) else {
        return Ok(None);
    };
    Ok(Some((typ, decoded[nul + 1..].to_vec())))
}

/// Map a loose-object header (`"blob 123"`, `"tree …"`, …) to its type code.
fn loose_type(header: &[u8]) -> Option<u8> {
    if header.starts_with(b"blob ") {
        Some(gitpack::OBJ_BLOB)
    } else if header.starts_with(b"tree ") {
        Some(gitpack::OBJ_TREE)
    } else if header.starts_with(b"commit ") {
        Some(gitpack::OBJ_COMMIT)
    } else if header.starts_with(b"tag ") {
        Some(gitpack::OBJ_TAG)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn loose_type_maps_headers() {
        assert_eq!(loose_type(b"blob 123"), Some(gitpack::OBJ_BLOB));
        assert_eq!(loose_type(b"tree 40"), Some(gitpack::OBJ_TREE));
        assert_eq!(loose_type(b"commit 200"), Some(gitpack::OBJ_COMMIT));
        assert_eq!(loose_type(b"tag 9"), Some(gitpack::OBJ_TAG));
        assert_eq!(loose_type(b"bogus 1"), None);
    }

    /// A 64 MiB all-zero "blob" object deflates to a few KB but would inflate to
    /// 64 MiB — the classic bomb shape. With a small cap it must be skipped, and
    /// the decode must stop early (we assert it returns without OOM).
    #[test]
    fn oversized_blob_is_skipped_not_inflated() {
        let mut payload = b"blob 67108864\0".to_vec();
        payload.extend(std::iter::repeat(b'0').take(64 * 1024 * 1024));
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&payload).unwrap();
        let compressed = enc.finish().unwrap();
        assert!(compressed.len() < 1024 * 1024, "bomb should compress small");

        // Inflate the compressed bytes directly through the same capped path.
        let mut decoded = Vec::new();
        let cap = 5 * 1024 * 1024u64;
        ZlibDecoder::new(&compressed[..])
            .take(cap + 1)
            .read_to_end(&mut decoded)
            .unwrap();
        assert!(decoded.len() as u64 <= cap + 1, "cap must bound inflation");
        assert!(decoded.len() as u64 > cap, "and it exceeds the cap → skip");
    }
}
