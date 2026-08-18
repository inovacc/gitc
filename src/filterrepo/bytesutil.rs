//! Byte helpers for the fast-import stream codec (Rust port of git-filter-repo).
//!
//! Byte helpers for the fast-import stream codec: lossless [`decode`] for human
//! error messages, and [`glob_to_regex`] translating a shell glob (raw bytes) to
//! an anchored RE2 source. Operates purely on raw bytes — no newline translation
//! (byte-exact round-tripping is essential on platforms whose text mode rewrites
//! line endings).

/// Render a raw byte string for human-readable error messages. Valid UTF-8 is
/// returned as-is; invalid bytes are preserved via a `\xNN` escape, so the
/// operation is lossless and never panics.
pub fn decode(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match decode_rune(&b[i..]) {
            Some((ch, size)) => {
                out.push(ch);
                i += size;
            }
            None => {
                // Emit the raw byte as \xNN (a backslashreplace policy).
                out.push('\\');
                out.push('x');
                out.push(HEX[(b[i] >> 4) as usize] as char);
                out.push(HEX[(b[i] & 0xf) as usize] as char);
                i += 1;
            }
        }
    }
    out
}

/// Decode one UTF-8 scalar from the front of `b` (mirrors Go `utf8.DecodeRune`):
/// `Some((char, width))` for a valid encoding, `None` for an invalid lead/byte
/// (Go's `(RuneError, 1)` case — the caller emits `\xNN` and advances one byte).
fn decode_rune(b: &[u8]) -> Option<(char, usize)> {
    let max = b.len().min(4);
    for size in 1..=max {
        if let Ok(s) = std::str::from_utf8(&b[..size]) {
            if let Some(ch) = s.chars().next() {
                // Guard against a multi-byte prefix that happens to be valid as a
                // shorter char (can't occur once we return at the first size).
                if ch.len_utf8() == size {
                    return Some((ch, size));
                }
            }
        }
    }
    None
}

/// Translate a shell glob (raw bytes) into an anchored, dot-all RE2 source
/// (fnmatch semantics: `*` = any run incl. separators/newlines, `?` = one byte,
/// `[...]`/`[!...]` = a class, everything else literal). Returns raw bytes — a
/// glob may contain non-UTF-8 bytes, so the pattern is not a `String`.
pub fn glob_to_regex(glob: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(glob.len() + 8);
    out.extend_from_slice(br"(?s)\A");

    let n = glob.len();
    let mut i = 0;
    while i < n {
        let c = glob[i];
        i += 1;
        match c {
            b'*' => out.extend_from_slice(b".*"),
            b'?' => out.push(b'.'),
            b'[' => {
                let mut j = i;
                if j < n && (glob[j] == b'!' || glob[j] == b'^') {
                    j += 1;
                }
                if j < n && glob[j] == b']' {
                    j += 1;
                }
                while j < n && glob[j] != b']' {
                    j += 1;
                }
                if j >= n {
                    // No closing bracket: treat '[' as a literal.
                    out.extend_from_slice(br"\[");
                    continue;
                }
                let mut stuff = &glob[i..j];
                i = j + 1;

                out.push(b'[');
                if !stuff.is_empty() && stuff[0] == b'!' {
                    out.push(b'^');
                    stuff = &stuff[1..];
                } else if !stuff.is_empty() && stuff[0] == b'^' {
                    out.push(b'\\');
                }
                for &b in stuff {
                    if b == b'\\' {
                        out.extend_from_slice(br"\\");
                    } else {
                        out.push(b);
                    }
                }
                out.push(b']');
            }
            _ => escape_regex_byte(c, &mut out),
        }
    }

    out.extend_from_slice(br"\z");
    out
}

/// Append a regex fragment matching exactly the literal byte `c`, escaping any
/// RE2 metacharacter.
fn escape_regex_byte(c: u8, out: &mut Vec<u8>) {
    if matches!(
        c,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
    ) {
        out.push(b'\\');
    }
    out.push(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_to_regex_is_anchored_and_dotall() {
        let src = glob_to_regex(b"*.txt");
        assert!(
            src.starts_with(br"(?s)\A"),
            "glob regex must be anchored at start"
        );
        assert!(src.ends_with(br"\z"), "glob regex must be anchored at end");
        // '*' -> '.*'
        assert!(
            src.windows(2).any(|w| w == b".*"),
            "'*' not translated to '.*'"
        );
        // The literal '.' in ".txt" is escaped.
        assert!(
            std::str::from_utf8(&src).unwrap().contains(r"\.txt"),
            "literal '.' must be escaped: {:?}",
            String::from_utf8_lossy(&src)
        );
    }

    #[test]
    fn glob_char_class_and_negation() {
        assert_eq!(glob_to_regex(b"[abc]"), br"(?s)\A[abc]\z".to_vec());
        assert_eq!(glob_to_regex(b"[!a]"), br"(?s)\A[^a]\z".to_vec());
        // Unclosed '[' is a literal.
        assert_eq!(glob_to_regex(b"a["), br"(?s)\Aa\[\z".to_vec());
        // '?' -> '.'
        assert_eq!(glob_to_regex(b"a?b"), br"(?s)\Aa.b\z".to_vec());
    }

    #[test]
    fn decode_valid_utf8_passthrough() {
        assert_eq!(decode(b"caf\xc3\xa9.txt"), "café.txt");
        assert_eq!(decode(b"plain"), "plain");
    }

    #[test]
    fn decode_invalid_bytes_are_hex_escaped() {
        // A lone 0xff is invalid UTF-8 -> \xff; surrounding ASCII survives.
        assert_eq!(decode(b"a\xffb"), r"a\xffb");
        // An encoded U+FFFD (EF BF BD) is a real char, not an escape.
        assert_eq!(decode(b"\xef\xbf\xbd"), "\u{fffd}");
    }
}
