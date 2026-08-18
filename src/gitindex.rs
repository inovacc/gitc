//! Parse git's on-disk index (`.git/index`) to enumerate the staged blobs.
//!
//! We read the STABLE on-disk format (documented in git's `Documentation/gitformat-
//! index.txt`) rather than git's in-memory structs, so this does not depend on
//! git's internal ABI. Supports index versions 2, 3, and 4 (v4 path prefix-
//! compression). We surface only stage-0 regular-file blobs — the content a
//! secret scan cares about (symlinks/gitlinks/conflict stages are skipped).
//!
//! This mirrors the Go gate's `scanStaged`: the scan target is the staged blob set
//! recorded in the index.

/// A staged blob: its repo-relative path and its 20-byte object id (hex).
pub struct Entry {
    pub path: String,
    pub oid_hex: String,
}

/// Parse `.git/index` bytes into the stage-0 regular-file blob entries.
/// Returns an error string on a malformed/unsupported index.
pub fn parse(data: &[u8]) -> Result<Vec<Entry>, String> {
    if data.len() < 12 || &data[0..4] != b"DIRC" {
        return Err("not a git index (missing DIRC signature)".into());
    }
    let version = be32(&data[4..8]);
    if !(2..=4).contains(&version) {
        return Err(format!("unsupported index version {version}"));
    }
    let count = be32(&data[8..12]) as usize;

    // Do NOT pre-size from the untrusted header: `count` is a raw 4-byte field
    // (up to ~4.29e9), and `Vec::with_capacity(count)` would eagerly reserve
    // count * size_of::<Entry>() (~200 GB), aborting the process from ~12 crafted
    // bytes — an abort the caller's Result-based fail-open cannot catch. The
    // smallest possible entry is 62 bytes, so no valid index can hold more than
    // data.len()/62 entries; clamp the reservation to that ceiling.
    let cap_ceiling = data.len() / 62;
    let mut entries = Vec::with_capacity(count.min(cap_ceiling));
    let mut off = 12usize;
    let mut prev_path: Vec<u8> = Vec::new();

    for _ in 0..count {
        let entry_start = off;
        // Fixed fields: 10×u32 (40) + 20-byte oid + 2-byte flags = 62 bytes.
        if off + 62 > data.len() {
            return Err("truncated index entry".into());
        }
        let mode = be32(&data[off + 24..off + 28]);
        let oid = &data[off + 40..off + 60];
        let flags = be16(&data[off + 60..off + 62]);
        off += 62;

        let extended = flags & 0x4000 != 0;
        if extended {
            if version < 3 {
                return Err("extended flag in a v2 index".into());
            }
            if off + 2 > data.len() {
                return Err("truncated extended flags".into());
            }
            off += 2;
        }
        let stage = (flags >> 12) & 0x3;

        // Path.
        let path_bytes: Vec<u8> = if version >= 4 {
            // v4: varint strip-count from prev path + NUL-terminated suffix.
            let (strip, consumed) = read_varint(&data[off..]).ok_or("bad v4 varint")?;
            off += consumed;
            let end = memchr_nul(&data[off..]).ok_or("unterminated v4 path")?;
            let suffix = &data[off..off + end];
            off += end + 1; // consume the NUL
            let keep = prev_path
                .len()
                .checked_sub(strip)
                .ok_or("v4 strip underflow")?;
            let mut p = prev_path[..keep].to_vec();
            p.extend_from_slice(suffix);
            p
        } else {
            // v2/v3: NUL-terminated path, then pad with NULs to an 8-byte multiple.
            let end = memchr_nul(&data[off..]).ok_or("unterminated path")?;
            let p = data[off..off + end].to_vec();
            off += end + 1;
            let entry_len = off - entry_start;
            let pad = (8 - (entry_len % 8)) % 8;
            off += pad;
            p
        };
        prev_path = path_bytes.clone();

        // Keep only stage-0 regular files (mode 0o100644 / 0o100755).
        let object_type = (mode >> 12) & 0xF; // 0b1000 = regular file
        if stage == 0 && object_type == 0b1000 {
            entries.push(Entry {
                path: String::from_utf8_lossy(&path_bytes).into_owned(),
                oid_hex: hex(oid),
            });
        }
    }
    Ok(entries)
}

/// git's index-v4 / pack offset varint decode. Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut val: usize = 0;
    let mut i = 0;
    loop {
        let c = *data.get(i)?;
        if i == 0 {
            val = (c & 0x7f) as usize;
        } else {
            // Checked arithmetic: a long run of continuation bytes would overflow
            // `usize`. Unchecked, that PANICS in a debug/overflow-checked build —
            // and a panic (unlike a returned `None`) escapes the caller's
            // Result-based fail-open. Return `None` on overflow so a malformed v4
            // index stays on the fail-open path in every build profile.
            val = match val.checked_add(1).and_then(|v| v.checked_shl(7)) {
                Some(shifted) => shifted | (c & 0x7f) as usize,
                None => return None,
            };
        }
        i += 1;
        if c & 0x80 == 0 {
            return Some((val, i));
        }
    }
}

fn memchr_nul(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == 0)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_index() {
        assert!(parse(b"not an index").is_err());
    }

    #[test]
    fn huge_count_does_not_oom() {
        // DIRC, version 2, count = 0xFFFFFFFF, no entry bytes. Must Err quickly on
        // the truncated first entry — NOT pre-allocate ~200 GB and abort.
        let data = b"DIRC\x00\x00\x00\x02\xFF\xFF\xFF\xFF";
        assert!(
            parse(data).is_err(),
            "crafted huge-count index must error, not OOM"
        );
    }

    #[test]
    fn varint_decodes() {
        // Single-byte value.
        assert_eq!(read_varint(&[0x05]), Some((5, 1)));
        // Two-byte continuation.
        assert_eq!(read_varint(&[0x80, 0x00]), Some(((0 + 1) << 7, 2)));
    }

    #[test]
    fn varint_overflow_returns_none() {
        // A long run of continuation bytes (0x80 = high bit set, no terminator)
        // overflows usize; must return None, not panic (which would escape
        // fail-open in an overflow-checked build).
        assert_eq!(read_varint(&[0x80; 16]), None);
    }
}
