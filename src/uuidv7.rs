//! Port of Go `internal/uuidv7` — RFC 9562 version-7 UUIDs: a 48-bit millisecond
//! timestamp prefix followed by random bits. Because the timestamp leads, the
//! values are time-ordered and lexicographically sortable — gitc uses that to name
//! each managed-git install directory so they sort chronologically and the oldest
//! can be garbage-collected. std + the OS CSPRNG (`getrandom`), no other deps.

use std::time::{SystemTime, UNIX_EPOCH};

/// Failure generating a UUID — Go returns `error` from a failed `rand.Read`.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "uuidv7: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Go `New` — a new UUIDv7 as its canonical 36-char hyphenated string.
pub fn new() -> Result<String, Error> {
    let mut b = [0u8; 16];

    // Milliseconds fit in 48 bits until year 10889 (matches the Go `//nolint` note).
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    b[0] = (ms >> 40) as u8;
    b[1] = (ms >> 32) as u8;
    b[2] = (ms >> 24) as u8;
    b[3] = (ms >> 16) as u8;
    b[4] = (ms >> 8) as u8;
    b[5] = ms as u8;

    getrandom::getrandom(&mut b[6..]).map_err(|e| Error(format!("read random: {e}")))?;

    b[6] = (b[6] & 0x0f) | 0x70; // version 7 in the high nibble
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant (10xxxxxx)

    Ok(format(&b))
}

/// Render the 16 bytes as 8-4-4-4-12 lowercase hex (Go `format`).
fn format(b: &[u8; 16]) -> String {
    let groups: [&[u8]; 5] = [&b[0..4], &b[4..6], &b[6..8], &b[8..10], &b[10..16]];
    let mut out = String::with_capacity(36);
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        for byte in *group {
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Go test's canonical regex, as an explicit check (no regex dep):
    /// `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.
    fn is_canonical(id: &str) -> bool {
        let g: Vec<&str> = id.split('-').collect();
        if g.len() != 5 {
            return false;
        }
        let lens = [8usize, 4, 4, 4, 12];
        for (grp, &want) in g.iter().zip(lens.iter()) {
            if grp.len() != want || !grp.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return false;
            }
        }
        // version 7 nibble, then RFC 4122 variant nibble in [89ab].
        g[2].starts_with('7') && matches!(g[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')
    }

    #[test]
    fn new_format_and_version() {
        let id = new().expect("New");
        assert!(is_canonical(&id), "id {id:?} is not a canonical v7 UUID");
    }

    #[test]
    fn new_unique_and_ordered() {
        let mut seen = std::collections::HashSet::new();
        let mut prev = String::new();
        for _ in 0..1000 {
            let id = new().expect("New");
            assert!(seen.insert(id.clone()), "duplicate id generated: {id}");
            // The ms-timestamp prefix means ids never sort before an earlier one
            // from a prior millisecond; within one ms the random tail may reorder,
            // so only assert the timestamp prefix is non-decreasing.
            if !prev.is_empty() {
                assert!(
                    id[..12] >= prev[..12],
                    "timestamp prefix went backwards: {prev} before {id}"
                );
            }
            prev = id;
        }
    }
}
