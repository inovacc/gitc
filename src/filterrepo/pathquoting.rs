//! C-style path quoting for the fast-import stream (Rust port of git-filter-repo).
//!
//! The C-style path quoting `git fast-export` uses when a path contains bytes
//! that require escaping. A quoted path starts with a double quote; all other
//! paths are emitted verbatim. Operates on raw bytes.

/// Reproduces fast-export's C-style path quoting. Stateless.
pub struct PathQuoting;

impl PathQuoting {
    /// Convert a possibly quoted path back to its raw byte form. Input that does
    /// not start with a double quote is returned unchanged.
    pub fn dequote(&self, quoted: &[u8]) -> Vec<u8> {
        if quoted.is_empty() || quoted[0] != b'"' {
            return quoted.to_vec();
        }
        // Strip the surrounding quotes (trailing quote only if present).
        let inner: &[u8] = if quoted.len() >= 2 && quoted[quoted.len() - 1] == b'"' {
            &quoted[1..quoted.len() - 1]
        } else {
            &quoted[1..]
        };

        let mut out = Vec::with_capacity(inner.len());
        let mut i = 0;
        while i < inner.len() {
            if inner[i] != b'\\' || i + 1 >= inner.len() {
                out.push(inner[i]);
                i += 1;
                continue;
            }
            let next = inner[i + 1];
            // Three-digit octal escape \NNN.
            if is_octal(next)
                && i + 3 < inner.len()
                && is_octal(inner[i + 2])
                && is_octal(inner[i + 3])
            {
                let v =
                    (inner[i + 1] - b'0') * 64 + (inner[i + 2] - b'0') * 8 + (inner[i + 3] - b'0');
                out.push(v);
                i += 4;
                continue;
            }
            if let Some(b) = named_unescape(next) {
                out.push(b);
                i += 2;
                continue;
            }
            // Unknown escape: keep the escaped byte literally.
            out.push(next);
            i += 2;
        }
        out
    }

    /// Quote a path only when fast-import requires it (the path begins with a
    /// double quote or contains a newline). When quoting is required, every byte
    /// is escaped via the escape table.
    pub fn enquote(&self, path: &[u8]) -> Vec<u8> {
        if path.is_empty() {
            return path.to_vec();
        }
        if path[0] != b'"' && !path.contains(&b'\n') {
            return path.to_vec();
        }
        let mut buf = Vec::with_capacity(path.len() + 2);
        buf.push(b'"');
        for &b in path {
            escape_byte(b, &mut buf);
        }
        buf.push(b'"');
        buf
    }
}

fn is_octal(b: u8) -> bool {
    b >= b'0' && b <= b'7'
}

/// The byte a C-style named escape letter represents (`\a \b \f \n \r \t \v \" \\`).
fn named_unescape(letter: u8) -> Option<u8> {
    match letter {
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'f' => Some(0x0c),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'v' => Some(0x0b),
        b'"' => Some(b'"'),
        b'\\' => Some(b'\\'),
        _ => None,
    }
}

/// Append the fast-import escape for byte `b`: a named C escape where one exists,
/// a three-digit octal `\NNN` for 0x7f-0xff, else the byte itself (0x00-0x7e).
fn escape_byte(b: u8, out: &mut Vec<u8>) {
    match b {
        0x07 => out.extend_from_slice(b"\\a"),
        0x08 => out.extend_from_slice(b"\\b"),
        0x0c => out.extend_from_slice(b"\\f"),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        b'\t' => out.extend_from_slice(b"\\t"),
        0x0b => out.extend_from_slice(b"\\v"),
        b'"' => out.extend_from_slice(b"\\\""),
        b'\\' => out.extend_from_slice(b"\\\\"),
        _ if b < 0x7f => out.push(b),
        _ => {
            out.push(b'\\');
            out.push(b'0' + ((b >> 6) & 7));
            out.push(b'0' + ((b >> 3) & 7));
            out.push(b'0' + (b & 7));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PQ: PathQuoting = PathQuoting;

    #[test]
    fn dequote_cases() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"simple.txt", b"simple.txt"),
            (b"\"simple.txt\"", b"simple.txt"),
            (b"\"a\\nb\"", b"a\nb"),
            (b"\"a\\tb\"", b"a\tb"),
            (b"\"a\\\"b\"", b"a\"b"),
            (b"\"a\\\\b\"", b"a\\b"),
            (b"\"caf\\303\\251.txt\"", b"caf\xc3\xa9.txt"),
        ];
        for (input, want) in cases {
            assert_eq!(
                &PQ.dequote(input),
                want,
                "dequote({:?})",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn enquote_cases() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"simple.txt", b"simple.txt"),
            (b"my file.txt", b"my file.txt"), // space is not quoted
            (b"caf\xc3\xa9.txt", b"caf\xc3\xa9.txt"), // utf8 not quoted
            (b"a\nb", b"\"a\\nb\""),          // newline quoted
            (b"\"x", b"\"\\\"x\""),           // leading quote quoted
        ];
        for (input, want) in cases {
            assert_eq!(
                &PQ.enquote(input),
                want,
                "enquote({:?})",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn round_trip() {
        let raws: &[&[u8]] = &[
            b"plain",
            b"a\nb",
            b"caf\xc3\xa9",
            &[0x00, 0x01, 0xff, b'"', b'\\', b'\n'],
        ];
        for raw in raws {
            let got = PQ.dequote(&PQ.enquote(raw));
            assert_eq!(&got, raw, "round trip: raw={:?}", raw);
        }
    }
}
