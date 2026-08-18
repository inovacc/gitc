//! Seam 5 — read git objects from PACKFILES (`.git/objects/pack/*.{idx,pack}`).
//!
//! The loose-object reader (`gitobj`) only sees unpacked objects; anything git has
//! packed (via `gc`/`repack`, or fetched as a pack) is invisible to it. This module
//! closes that blind spot: it finds an object by oid via the pack `.idx` (v2 fanout
//! + binary search), then reads the pack entry — inflating a plain object, or
//! resolving an `OFS_DELTA`/`REF_DELTA` chain against its base — and returns the raw
//! `(type, content)`.
//!
//! FAIL-SAFE by construction: every uncertain path (unsupported idx version, a
//! malformed entry, an over-cap/over-deep object, an unresolvable base) returns
//! `Ok(None)` — the caller then SKIPS the object, exactly as before this seam
//! existed. So a bug here can only ever scan FEWER bytes (never fabricate content
//! that could cause a false secret-block), and the worst case degrades to the
//! pre-seam "packed objects skipped" behavior. The varint decoders and delta
//! application are the same algorithms proven in the scratch verifier.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use flate2::read::ZlibDecoder;

/// git object type codes (packfile + our unified loose reader).
pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

/// Bound the delta chain we will resolve — a guard against a pathological or
/// crafted cycle. Real git delta chains are shallow (default depth 50).
const MAX_DELTA_DEPTH: u32 = 64;

/// Read the raw object `oid_hex` from any pack under `gitdir`, inflating at most
/// `max_bytes`. Returns `Ok(None)` if the object is in no pack, or on ANY parse /
/// cap / depth failure (fail-safe skip). The tuple is `(type_code, content)`.
pub fn read_object(
    gitdir: &Path,
    oid_hex: &str,
    max_bytes: usize,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    read_object_depth(gitdir, oid_hex, max_bytes, 0)
}

fn read_object_depth(
    gitdir: &Path,
    oid_hex: &str,
    max_bytes: usize,
    depth: u32,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    if depth > MAX_DELTA_DEPTH {
        return Ok(None);
    }
    let Some(oid) = hex_to_oid(oid_hex) else {
        return Ok(None);
    };
    let pack_dir = gitdir.join("objects").join("pack");
    let entries = match std::fs::read_dir(&pack_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        let idx = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let Some(offset) = idx_lookup(&idx, &oid) else {
            continue;
        };
        let pack_path = path.with_extension("pack");
        return read_at(&pack_path, offset, gitdir, max_bytes, depth);
    }
    Ok(None)
}

/// Read the pack entry at `offset` in `pack_path`, resolving deltas. `Ok(None)` on
/// any failure (fail-safe skip).
fn read_at(
    pack_path: &Path,
    offset: u64,
    gitdir: &Path,
    max_bytes: usize,
    depth: u32,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    if depth > MAX_DELTA_DEPTH {
        return Ok(None);
    }
    let mut file = match std::fs::File::open(pack_path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Ok(None);
    }
    let mut r = std::io::BufReader::new(file);
    let Some((typ, _size)) = read_obj_header_stream(&mut r) else {
        return Ok(None);
    };
    match typ {
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => match inflate_capped(&mut r, max_bytes)? {
            Some(data) => Ok(Some((typ, data))),
            None => Ok(None),
        },
        OBJ_OFS_DELTA => {
            let Some(rel) = read_ofs_stream(&mut r) else {
                return Ok(None);
            };
            let Some(base_off) = offset.checked_sub(rel) else {
                return Ok(None);
            };
            let Some(delta) = inflate_capped(&mut r, max_bytes)? else {
                return Ok(None);
            };
            let Some((base_typ, base)) =
                read_at(pack_path, base_off, gitdir, max_bytes, depth + 1)?
            else {
                return Ok(None);
            };
            Ok(apply_delta(&base, &delta, max_bytes).map(|out| (base_typ, out)))
        }
        OBJ_REF_DELTA => {
            let mut base_oid = [0u8; 20];
            if r.read_exact(&mut base_oid).is_err() {
                return Ok(None);
            }
            let Some(delta) = inflate_capped(&mut r, max_bytes)? else {
                return Ok(None);
            };
            // The base may live in this pack, another pack, or loose — resolve by oid
            // through the unified reader (packs here; loose is handled by the caller's
            // read_object, but a ref-delta base is virtually always packed).
            let Some((base_typ, base)) =
                read_object_depth(gitdir, &oid_to_hex(&base_oid), max_bytes, depth + 1)?
            else {
                return Ok(None);
            };
            Ok(apply_delta(&base, &delta, max_bytes).map(|out| (base_typ, out)))
        }
        _ => Ok(None),
    }
}

/// Inflate the deflate stream at the reader's current position, capping at
/// `max_bytes` (zlib-bomb guard, same as `gitobj`). `None` if it exceeds the cap.
fn inflate_capped(r: &mut impl Read, max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    ZlibDecoder::new(r).take(limit).read_to_end(&mut out)?;
    if out.len() > max_bytes {
        return Ok(None);
    }
    Ok(Some(out))
}

// ---- idx v2 lookup (fanout + binary search) — proven in the scratch verifier -----

/// Find `oid` in an idx v2, returning its pack offset. `None` on a non-v2 idx, a
/// miss, or a truncated table.
fn idx_lookup(idx: &[u8], oid: &[u8; 20]) -> Option<u64> {
    if idx.len() < 8 + 256 * 4 || &idx[0..4] != b"\xfftOc" || be32(idx, 4)? != 2 {
        return None;
    }
    let fan = 8;
    let total = be32(idx, fan + 255 * 4)? as usize;
    let first = oid[0] as usize;
    let mut lo = if first == 0 {
        0
    } else {
        be32(idx, fan + (first - 1) * 4)? as usize
    };
    let mut hi = be32(idx, fan + first * 4)? as usize;
    let oids = fan + 256 * 4;
    if oids + total * 20 > idx.len() || hi > total || lo > hi {
        return None;
    }
    let mut found = None;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry = &idx[oids + mid * 20..oids + mid * 20 + 20];
        match entry.cmp(&oid[..]) {
            std::cmp::Ordering::Equal => {
                found = Some(mid);
                break;
            }
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    let i = found?;
    let offs = oids + total * 20 + total * 4; // after oids + crc32 table
    let raw = be32(idx, offs + i * 4)?;
    if raw & 0x8000_0000 == 0 {
        return Some(raw as u64);
    }
    // MSB set → index into the 8-byte large-offset table.
    let large = offs + total * 4 + (raw & 0x7fff_ffff) as usize * 8;
    if large + 8 > idx.len() {
        return None;
    }
    let b = &idx[large..large + 8];
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

// ---- packfile varints (streamed) — same encodings proven in the scratch verifier -

/// Read a pack object header `(type, uncompressed_size)`; `None` on truncation.
fn read_obj_header_stream(r: &mut impl Read) -> Option<(u8, usize)> {
    let b = read_u8(r)?;
    let typ = (b >> 4) & 0x7;
    let mut size = (b & 0x0f) as usize;
    let mut shift = 4u32;
    let mut cont = b & 0x80 != 0;
    while cont {
        let b = read_u8(r)?;
        size |= ((b & 0x7f) as usize).checked_shl(shift)?;
        shift += 7;
        cont = b & 0x80 != 0;
    }
    Some((typ, size))
}

/// Read the OFS_DELTA negative-offset varint (git's `(offset+1)<<7` encoding).
fn read_ofs_stream(r: &mut impl Read) -> Option<u64> {
    let mut c = read_u8(r)?;
    let mut off = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = read_u8(r)?;
        off = ((off + 1) << 7) | (c & 0x7f) as u64;
    }
    Some(off)
}

fn read_u8(r: &mut impl Read) -> Option<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).ok()?;
    Some(b[0])
}

// ---- delta application (base-128 size varint + copy/insert) — proven in scratch ---

/// Apply a git delta to `base`, capping the result at `max_bytes`. `None` on any
/// malformed instruction, a base-size mismatch, or an over-cap result (fail-safe).
fn apply_delta(base: &[u8], delta: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
    let (src_size, mut pos) = size_varint(delta, 0)?;
    if src_size != base.len() {
        return None;
    }
    let (dst_size, p) = size_varint(delta, pos)?;
    pos = p;
    if dst_size > max_bytes {
        return None;
    }
    let mut out = Vec::with_capacity(dst_size);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut off = 0usize;
            let mut size = 0usize;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    off |= (*delta.get(pos)? as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (1 << (4 + i)) != 0 {
                    size |= (*delta.get(pos)? as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off.checked_add(size)?;
            if end > base.len() {
                return None;
            }
            out.extend_from_slice(&base[off..end]);
        } else if cmd != 0 {
            let n = cmd as usize;
            let end = pos.checked_add(n)?;
            if end > delta.len() {
                return None;
            }
            out.extend_from_slice(&delta[pos..end]);
            pos = end;
        } else {
            return None; // 0x00 is reserved
        }
        if out.len() > max_bytes {
            return None;
        }
    }
    if out.len() != dst_size {
        return None;
    }
    Some(out)
}

/// Base-128 little-endian size varint (delta headers). `None` on truncation/overflow.
fn size_varint(d: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    let (mut val, mut shift) = (0usize, 0u32);
    loop {
        let b = *d.get(pos)?;
        pos += 1;
        val |= ((b & 0x7f) as usize).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some((val, pos));
        }
        shift += 7;
    }
}

// ---- small helpers -------------------------------------------------------------

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a 40-char lowercase-or-upper hex oid into 20 bytes. `None` if not 40 hex.
fn hex_to_oid(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    let bytes = hex.as_bytes();
    for i in 0..20 {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn oid_to_hex(oid: &[u8; 20]) -> String {
    oid.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_oid_round_trips() {
        let hex = "f4d85c4c39741dd07abdd3e51bbec22d5f72f38d";
        let oid = hex_to_oid(hex).unwrap();
        assert_eq!(oid_to_hex(&oid), hex);
        assert!(hex_to_oid("nothex").is_none());
        assert!(hex_to_oid("f4d8").is_none()); // too short
    }

    #[test]
    fn size_varint_decodes_known_values() {
        assert_eq!(size_varint(&[0x80, 0x80, 0x04], 0), Some((0x10000, 3)));
        assert_eq!(size_varint(&[11], 0), Some((11, 1)));
        assert_eq!(size_varint(&[], 0), None);
    }

    #[test]
    fn obj_header_decodes_type_and_size() {
        // cont|type3|low4=1 , 0|size-hi=1 → blob(3), size = 1 | (1<<4) = 17
        assert_eq!(
            read_obj_header_stream(&mut &[0b1011_0001u8, 0b0000_0001][..]),
            Some((3, 17))
        );
        // single byte: type3 size5
        assert_eq!(
            read_obj_header_stream(&mut &[0b0011_0101u8][..]),
            Some((3, 5))
        );
    }

    #[test]
    fn ofs_varint_round_trips() {
        for &n in &[0u64, 1, 127, 128, 300, 16384, 1_000_000] {
            let enc = encode_ofs(n);
            assert_eq!(read_ofs_stream(&mut &enc[..]), Some(n), "n={n}");
        }
    }

    #[test]
    fn delta_apply_insert_copy_and_rejects_bad_base() {
        let base = b"hello world";
        // insert 'X' then copy full base
        assert_eq!(
            apply_delta(base, &[11, 12, 0x01, b'X', 0x90, 11], 1024).as_deref(),
            Some(&b"Xhello world"[..])
        );
        // copy middle slice off=6 size=5 → "world"
        assert_eq!(
            apply_delta(base, &[11, 5, 0x91, 6, 5], 1024).as_deref(),
            Some(&b"world"[..])
        );
        // wrong base size → None
        assert!(apply_delta(b"short", &[11, 12, 0x01, b'X', 0x90, 11], 1024).is_none());
        // result over cap → None
        assert!(apply_delta(base, &[11, 12, 0x01, b'X', 0x90, 11], 4).is_none());
    }

    #[test]
    fn idx_v2_lookup_finds_and_misses() {
        let (idx, oid_a, oid_b) = build_idx();
        assert_eq!(idx_lookup(&idx, &oid_a), Some(0x1234));
        assert_eq!(idx_lookup(&idx, &oid_b), Some(0x9abc));
        assert_eq!(idx_lookup(&idx, &[0xff; 20]), None);
        assert_eq!(idx_lookup(b"short", &oid_a), None); // truncated idx → None, no panic
    }

    // git's offset varint encoder (inverse of read_ofs_stream), for round-trips.
    fn encode_ofs(mut n: u64) -> Vec<u8> {
        let mut tmp = vec![(n & 0x7f) as u8];
        while n >> 7 != 0 {
            n = (n >> 7) - 1;
            tmp.push(0x80 | (n & 0x7f) as u8);
        }
        tmp.reverse();
        tmp
    }

    fn build_idx() -> (Vec<u8>, [u8; 20], [u8; 20]) {
        let mut oid_a = [0u8; 20];
        oid_a[0] = 0x10;
        let mut oid_b = [0u8; 20];
        oid_b[0] = 0x80;
        let mut idx = Vec::new();
        idx.extend_from_slice(b"\xfftOc");
        idx.extend_from_slice(&2u32.to_be_bytes());
        for i in 0..256u32 {
            let c: u32 = if i < 0x10 {
                0
            } else if i < 0x80 {
                1
            } else {
                2
            };
            idx.extend_from_slice(&c.to_be_bytes());
        }
        idx.extend_from_slice(&oid_a);
        idx.extend_from_slice(&oid_b);
        idx.extend_from_slice(&0u32.to_be_bytes());
        idx.extend_from_slice(&0u32.to_be_bytes());
        idx.extend_from_slice(&0x1234u32.to_be_bytes());
        idx.extend_from_slice(&0x9abcu32.to_be_bytes());
        idx.extend_from_slice(&[0u8; 40]);
        (idx, oid_a, oid_b)
    }
}
