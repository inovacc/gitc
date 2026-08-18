//! Adversarial / fuzz coverage (goal §35, §50): feed malformed and random bytes to
//! the untrusted-input git parsers and assert they never panic — they must return
//! an error, a partial result, or `None`, but never crash on attacker-controlled
//! repository bytes. Deterministic (a fixed-seed xorshift PRNG) so failures
//! reproduce; a panic anywhere fails the test.

#![cfg(test)]

use std::path::PathBuf;

/// A tiny deterministic PRNG (xorshift64*) — no external `rand`, no `Math.random`.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() & 0xff) as u8).collect()
    }
    fn len(&mut self, cap: usize) -> usize {
        (self.next_u64() as usize) % (cap + 1)
    }
}

fn tmp(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("gitc_fuzz_{tag}_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn gitindex_parse_never_panics_on_garbage() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..4000 {
        let n = rng.len(1024);
        let buf = rng.bytes(n);
        let _ = crate::gitindex::parse(&buf); // must return, never panic
    }
    // Structured-but-malicious: valid "DIRC" magic, sane version, absurd entry count.
    let mut b = b"DIRC".to_vec();
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&[0u8; 16]);
    let _ = crate::gitindex::parse(&b);
    // Truncated right after the header.
    let _ = crate::gitindex::parse(b"DIRC\0\0\0\x02\0\0\0\x01");
}

#[test]
fn gitobj_read_object_never_panics_on_malformed_loose() {
    let dir = tmp("loose");
    let gitdir = dir.join(".git");
    let objs = gitdir.join("objects").join("ab");
    std::fs::create_dir_all(&objs).unwrap();
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);
    for i in 0..800u64 {
        // A loose object path is objects/<2 hex>/<38 hex>; write garbage there.
        let rest = format!("{i:038x}");
        let n = rng.len(400);
        std::fs::write(objs.join(&rest), rng.bytes(n)).unwrap();
        let oid = format!("ab{rest}");
        // Random bytes are not valid zlib → Err/None, never a panic.
        let _ = crate::gitobj::read_object(&gitdir, &oid, 1 << 20);
        let _ = crate::gitobj::read_blob(&gitdir, &oid, 1 << 20);
    }
    // A non-hex / short oid must also be handled gracefully.
    let _ = crate::gitobj::read_object(&gitdir, "not-an-oid", 1 << 20);
    let _ = crate::gitobj::read_object(&gitdir, "", 1 << 20);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gitpack_read_object_never_panics_on_malformed_pack() {
    let dir = tmp("pack");
    let gitdir = dir.join(".git");
    let packs = gitdir.join("objects").join("pack");
    std::fs::create_dir_all(&packs).unwrap();
    let mut rng = Rng::new(0x0BAD_F00D_1234_5678);
    // A garbage idx/pack pair must fail resolution, not crash the reader.
    let stem = format!("pack-{}", "a".repeat(40));
    std::fs::write(packs.join(format!("{stem}.idx")), rng.bytes(512)).unwrap();
    std::fs::write(packs.join(format!("{stem}.pack")), rng.bytes(512)).unwrap();
    for i in 0..200u64 {
        let oid = format!("{i:040x}");
        let _ = crate::gitobj::read_object(&gitdir, &oid, 1 << 20);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
