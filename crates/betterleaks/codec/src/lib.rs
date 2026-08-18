//! Faithful 1:1 Rust port of Go `github.com/betterleaks/betterleaks/detect/codec`.
//!
//! A multi-pass, in-place decoder that finds and decodes base64 / hex / percent /
//! unicode (`U+XXXX`, `\uXXXX`) segments in text, iterating until stable.
//!
//! Parity notes (see PORT-TRACK.md):
//! - The Go `logging.Trace()...` call in `findEncodedSegments` is deliberately
//!   dropped (non-observable debug tracing; no test asserts it).
//! - base64 / hex / percent / unicode decoders are hand-rolled (std-first, zero
//!   third-party deps). The base64 decoder reproduces Go `encoding/base64`
//!   `StdEncoding` (padded) then `RawURLEncoding` (unpadded) semantics.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Byte classification (ports the Go `init()` lookup tables)
// ---------------------------------------------------------------------------

#[inline]
fn is_hex_char(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

#[inline]
fn is_b64_char(b: u8) -> bool {
    // 0-9, A-Z, a-z, _, /, +, -   (matches Go's [\w\/+-] set)
    matches!(b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'/' | b'+' | b'-')
}

#[inline]
fn is_b64_not_hex(b: u8) -> bool {
    // b64 chars that are NOT hex: G-Z, g-z, _, /, +, -
    matches!(b, b'G'..=b'Z' | b'g'..=b'z' | b'_' | b'/' | b'+' | b'-')
}

#[inline]
fn is_whitespace(b: u8) -> bool {
    // space, tab, \n, \r, \f, \v
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
}

/// Ports Go's `printableASCII` table: `'\x08' < b && b < '\x7f'`.
#[inline]
fn printable(b: u8) -> bool {
    b > 0x08 && b < 0x7f
}

/// Ports Go's `isPrintableASCII([]byte)`.
#[inline]
fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&c| printable(c))
}

/// Ports Go's `hasByte(data, byteset)`.
#[inline]
fn has_byte(data: &[u8], f: fn(u8) -> bool) -> bool {
    data.iter().any(|&c| f(c))
}

#[inline]
fn likely_base64(b: u8) -> bool {
    // Go: `0123456789+/-_`
    matches!(b, b'0'..=b'9' | b'+' | b'/' | b'-' | b'_')
}

#[inline]
fn likely_hex(b: u8) -> bool {
    // Go: `0123456789`
    b.is_ascii_digit()
}

/// Ports Go's `hexMap`: hex nibble value or 0xff for a non-hex byte.
#[inline]
const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'A'..=b'F' => b - b'A' + 10,
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0xff,
    }
}

/// Reproduces Go's `string([]byte)` for our decoded values. Analysis shows every
/// decoded/passthrough byte sequence produced here is valid UTF-8 (unicode decode
/// emits UTF-8 runes; hex/base64 are printable-ASCII-guarded; percent passthrough
/// copies whole chars from a valid `&str`), so the lossy fallback is never taken.
#[inline]
fn bytes_to_string(b: Vec<u8>) -> String {
    match String::from_utf8(b) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// startEnd
// ---------------------------------------------------------------------------

/// Ports Go's `startEnd`. Uses `i64` because `sub`/`overflow` can go negative
/// (metadata arithmetic in `toOriginal`); slicing sites use non-negative values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StartEnd {
    start: i64,
    end: i64,
}

impl StartEnd {
    #[inline]
    fn new(start: i64, end: i64) -> Self {
        StartEnd { start, end }
    }

    #[inline]
    fn sub(self, o: StartEnd) -> StartEnd {
        StartEnd::new(self.start - o.start, self.end - o.end)
    }

    #[inline]
    fn add(self, o: StartEnd) -> StartEnd {
        StartEnd::new(self.start + o.start, self.end + o.end)
    }

    #[inline]
    fn overlaps(self, o: StartEnd) -> bool {
        o.start <= self.end && o.end >= self.start
    }

    #[inline]
    fn contains(self, o: StartEnd) -> bool {
        self.start <= o.start && o.end <= self.end
    }

    #[inline]
    fn overflow(self, o: StartEnd) -> StartEnd {
        self.merge(o).sub(self)
    }

    #[inline]
    fn merge(self, o: StartEnd) -> StartEnd {
        StartEnd::new(self.start.min(o.start), self.end.max(o.end))
    }
}

impl std::fmt::Display for StartEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{},{}]", self.start, self.end)
    }
}

// ---------------------------------------------------------------------------
// Encoding kinds (bit flags, ports encodings.go)
// ---------------------------------------------------------------------------

const PERCENT_KIND: i64 = 1;
const UNICODE_KIND: i64 = 2;
const HEX_KIND: i64 = 4;
const BASE64_KIND: i64 = 8;

const ENCODING_NAMES: [&str; 4] = ["percent", "unicode", "hex", "base64"];

/// Ports Go's `encodingKind.String()` (`int(math.Log2(float64(e)))` index).
fn encoding_kind_string(e: i64) -> String {
    let i = (e as f64).log2() as usize;
    if i >= ENCODING_NAMES.len() {
        return String::new();
    }
    ENCODING_NAMES[i].to_string()
}

/// Ports Go's `encodingKind.kinds()`.
fn encoding_kind_kinds(e: i64) -> Vec<i64> {
    let mut kinds = Vec::new();
    for i in 0..ENCODING_NAMES.len() {
        let kind = e & 2i64.pow(i as u32);
        if kind != 0 {
            kinds.push(kind);
        }
    }
    kinds
}

/// Precedence: percent=4, unicode=3, hex=2, base64=1 (ports the `encodings` table).
fn precedence_for(kind: i64) -> i32 {
    match kind {
        PERCENT_KIND => 4,
        UNICODE_KIND => 3,
        HEX_KIND => 2,
        BASE64_KIND => 1,
        _ => 0,
    }
}

fn decode_for_kind(kind: i64, v: &str) -> String {
    match kind {
        PERCENT_KIND => decode_percent(v),
        UNICODE_KIND => decode_unicode(v),
        HEX_KIND => decode_hex(v),
        BASE64_KIND => decode_base64(v),
        _ => String::new(),
    }
}

/// Ports Go's `encodingMatch` (an encoding + a `startEnd`).
#[derive(Clone, Copy, Debug)]
struct EncodingMatch {
    kind: i64,
    precedence: i32,
    start: usize,
    end: usize,
}

impl EncodingMatch {
    #[inline]
    fn se(&self) -> StartEnd {
        StartEnd::new(self.start as i64, self.end as i64)
    }
}

// ---------------------------------------------------------------------------
// hex decode (ports hex.go)
// ---------------------------------------------------------------------------

fn decode_hex(encoded_value: &str) -> String {
    let e = encoded_value.as_bytes();
    let size = e.len();
    if !size.is_multiple_of(2) {
        return String::new();
    }
    if !has_byte(e, likely_hex) {
        return String::new();
    }

    let mut decoded = vec![0u8; size / 2];
    let mut i = 0;
    while i < size {
        let n1 = hex_val(e[i]);
        let n2 = hex_val(e[i + 1]);
        if n1 | n2 == 0xff {
            return String::new();
        }
        let b = (n1 << 4) | n2;
        if !printable(b) {
            return String::new();
        }
        decoded[i / 2] = b;
        i += 2;
    }

    bytes_to_string(decoded)
}

// ---------------------------------------------------------------------------
// percent decode (ports percent.go)
// ---------------------------------------------------------------------------

fn decode_percent(encoded_value: &str) -> String {
    let e = encoded_value.as_bytes();
    let enc_len = e.len();
    let mut decoded = vec![0u8; enc_len];
    let mut dec_index = 0usize;
    let mut enc_index = 0usize;

    while enc_index < enc_len {
        if e[enc_index] == b'%' && enc_index + 2 < enc_len {
            let n1 = hex_val(e[enc_index + 1]);
            let n2 = hex_val(e[enc_index + 2]);
            if n1 | n2 != 0xff {
                let b = (n1 << 4) | n2;
                if !printable(b) {
                    return String::new();
                }
                decoded[dec_index] = b;
                enc_index += 3;
                dec_index += 1;
                continue;
            }
        }
        decoded[dec_index] = e[enc_index];
        enc_index += 1;
        dec_index += 1;
    }

    decoded.truncate(dec_index);
    bytes_to_string(decoded)
}

// ---------------------------------------------------------------------------
// unicode decode (ports unicode.go)
// ---------------------------------------------------------------------------

/// Ports Go's `parseHex4`.
fn parse_hex4(s: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > s.len() {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..4 {
        let n = hex_val(s[offset + i]);
        if n == 0xff {
            return None;
        }
        val = (val << 4) | n as u32;
    }
    Some(val)
}

/// Ports Go's `utf8.EncodeRune`: invalid runes (only surrogates are reachable
/// here, since values are 0..=0xFFFF) become RuneError (U+FFFD).
fn push_rune(buf: &mut Vec<u8>, r: u32) {
    let ch = char::from_u32(r).unwrap_or('\u{FFFD}');
    let mut tmp = [0u8; 4];
    buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
}

fn decode_unicode(encoded_value: &str) -> String {
    if encoded_value.contains("U+") {
        return decode_unicode_code_points(encoded_value);
    }
    if encoded_value.contains("\\u") || encoded_value.contains("\\U") {
        return decode_unicode_escapes(encoded_value);
    }
    encoded_value.to_string()
}

fn decode_unicode_code_points(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut buf: Vec<u8> = Vec::with_capacity(n);

    let mut i = 0usize;
    let mut changed = false;
    while i < n {
        if i + 5 < n && b[i] == b'U' && b[i + 1] == b'+' {
            if let Some(r) = parse_hex4(b, i + 2) {
                changed = true;
                push_rune(&mut buf, r);
                i += 6;
                // Skip a single separator space/tab, but only if the next thing
                // is another U+XXXX (avoids eating meaningful trailing spaces).
                if i < n && (b[i] == b' ' || b[i] == b'\t') && i + 6 < n && b[i + 1] == b'U' && b[i + 2] == b'+' {
                    i += 1;
                }
                continue;
            }
        }
        buf.push(b[i]);
        i += 1;
    }

    if !changed {
        return s.to_string();
    }
    bytes_to_string(buf)
}

fn decode_unicode_escapes(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut buf: Vec<u8> = Vec::with_capacity(n);

    let mut i = 0usize;
    let mut changed = false;
    while i < n {
        if b[i] == b'\\' {
            // \\uXXXX (double backslash + u + 4 hex)
            if i + 6 < n && b[i + 1] == b'\\' {
                let uc = b[i + 2];
                if uc == b'u' || uc == b'U' {
                    if let Some(r) = parse_hex4(b, i + 3) {
                        changed = true;
                        push_rune(&mut buf, r);
                        i += 7;
                        continue;
                    }
                }
            }
            // \uXXXX (single backslash + u + 4 hex)
            if i + 5 < n {
                let uc = b[i + 1];
                if uc == b'u' || uc == b'U' {
                    if let Some(r) = parse_hex4(b, i + 2) {
                        changed = true;
                        push_rune(&mut buf, r);
                        i += 6;
                        continue;
                    }
                }
            }
        }
        buf.push(b[i]);
        i += 1;
    }

    if !changed {
        return s.to_string();
    }
    bytes_to_string(buf)
}

// ---------------------------------------------------------------------------
// base64 decode (ports base64.go; hand-rolled to match encoding/base64)
// ---------------------------------------------------------------------------

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const fn build_map(alpha: &[u8; 64]) -> [u8; 256] {
    let mut m = [0xffu8; 256];
    let mut i = 0;
    while i < 64 {
        m[alpha[i] as usize] = i as u8;
        i += 1;
    }
    m
}

const STD_MAP: [u8; 256] = build_map(STD_ALPHABET);
const URL_MAP: [u8; 256] = build_map(URL_ALPHABET);

/// Faithful port of Go `encoding/base64`'s `decode`/`decodeQuantum`. `pad` is
/// `Some(b'=')` for `StdEncoding`, `None` for `RawURLEncoding`. Returns `None` on
/// any `CorruptInputError` (matching Go: `DecodeString` returns an error, which
/// `decodeBase64` treats as failure).
fn base64_decode(src: &[u8], map: &[u8; 256], pad: Option<u8>) -> Option<Vec<u8>> {
    let n = src.len();
    let mut out: Vec<u8> = Vec::with_capacity(n / 4 * 3 + 3);
    let mut si = 0usize;

    while si < n {
        // --- decodeQuantum ---
        let mut dbuf = [0u8; 4];
        let mut dlen = 4usize;
        let mut trailing_garbage = false;
        let mut j = 0usize;

        loop {
            if j >= 4 {
                break;
            }
            if si == n {
                if j == 0 {
                    return Some(out);
                }
                if j == 1 || pad.is_some() {
                    return None;
                }
                dlen = j;
                break;
            }
            let inb = src[si];
            si += 1;
            let o = map[inb as usize];
            if o != 0xff {
                dbuf[j] = o;
                j += 1;
                continue;
            }
            if inb == b'\n' || inb == b'\r' {
                continue; // net j unchanged (Go: j--/continue)
            }
            if pad != Some(inb) {
                return None;
            }
            // reached padding
            if j == 0 || j == 1 {
                return None;
            }
            if j == 2 {
                // expect a second '='
                while si < n && (src[si] == b'\n' || src[si] == b'\r') {
                    si += 1;
                }
                if si == n {
                    return None;
                }
                if pad != Some(src[si]) {
                    return None;
                }
                si += 1;
            }
            while si < n && (src[si] == b'\n' || src[si] == b'\r') {
                si += 1;
            }
            if si < n {
                trailing_garbage = true;
            }
            dlen = j;
            break;
        }

        // Convert 4x 6-bit values into up to 3 bytes.
        let val = (dbuf[0] as u32) << 18
            | (dbuf[1] as u32) << 12
            | (dbuf[2] as u32) << 6
            | (dbuf[3] as u32);
        let b0 = ((val >> 16) & 0xff) as u8;
        let b1 = ((val >> 8) & 0xff) as u8;
        let b2 = (val & 0xff) as u8;

        match dlen {
            4 => {
                out.push(b0);
                out.push(b1);
                out.push(b2);
            }
            3 => {
                out.push(b0);
                out.push(b1);
                if pad.is_some() && b2 != 0 {
                    return None;
                }
            }
            2 => {
                out.push(b0);
                if pad.is_some() && (b1 != 0 || b2 != 0) {
                    return None;
                }
            }
            _ => {}
        }

        if trailing_garbage {
            return None;
        }
    }

    Some(out)
}

fn decode_base64(encoded_value: &str) -> String {
    let b = encoded_value.as_bytes();
    // Exit early if it doesn't seem like base64.
    if !has_byte(b, likely_base64) {
        return String::new();
    }

    // Try standard base64 decoding.
    if let Some(decoded) = base64_decode(b, &STD_MAP, Some(b'=')) {
        if is_printable_ascii(&decoded) {
            return bytes_to_string(decoded);
        }
    }

    // Try base64url (raw, unpadded) decoding.
    if let Some(decoded) = base64_decode(b, &URL_MAP, None) {
        if is_printable_ascii(&decoded) {
            return bytes_to_string(decoded);
        }
    }

    String::new()
}

// ---------------------------------------------------------------------------
// findEncodingMatches (ports the byte-level scanner in encodings.go)
// ---------------------------------------------------------------------------

fn find_encoding_matches(data: &str) -> Vec<EncodingMatch> {
    let d = data.as_bytes();
    let n = d.len();
    if n == 0 {
        return Vec::new();
    }

    let mut all: Vec<EncodingMatch> = Vec::new();
    let mut i = 0usize;

    while i < n {
        let c = d[i];

        // --- Percent encoding: %XX ---
        if c == b'%' && i + 2 < n && is_hex_char(d[i + 1]) && is_hex_char(d[i + 2]) {
            let start = i;
            let mut last_percent_end = i + 3;
            let mut j = i + 3;
            while j < n && d[j] != b'\n' {
                if d[j] == b'%' && j + 2 < n && is_hex_char(d[j + 1]) && is_hex_char(d[j + 2]) {
                    last_percent_end = j + 3;
                }
                j += 1;
            }
            all.push(EncodingMatch {
                kind: PERCENT_KIND,
                precedence: precedence_for(PERCENT_KIND),
                start,
                end: last_percent_end,
            });
            i = last_percent_end;
            continue;
        }

        // --- Unicode code points: U+XXXX ---
        if c == b'U'
            && i + 5 < n
            && d[i + 1] == b'+'
            && is_hex_char(d[i + 2])
            && is_hex_char(d[i + 3])
            && is_hex_char(d[i + 4])
            && is_hex_char(d[i + 5])
        {
            let after_hex = i + 6;
            if after_hex >= n || is_whitespace(d[after_hex]) {
                let start = i;
                let mut end = after_hex;
                let mut j = after_hex;
                while j < n {
                    if !is_whitespace(d[j]) {
                        break;
                    }
                    let mut ws = j;
                    while ws < n && is_whitespace(d[ws]) {
                        ws += 1;
                    }
                    if ws + 5 < n
                        && d[ws] == b'U'
                        && d[ws + 1] == b'+'
                        && is_hex_char(d[ws + 2])
                        && is_hex_char(d[ws + 3])
                        && is_hex_char(d[ws + 4])
                        && is_hex_char(d[ws + 5])
                    {
                        let next_after = ws + 6;
                        if next_after >= n || is_whitespace(d[next_after]) {
                            end = next_after;
                            j = next_after;
                            continue;
                        }
                    }
                    break;
                }
                all.push(EncodingMatch {
                    kind: UNICODE_KIND,
                    precedence: precedence_for(UNICODE_KIND),
                    start,
                    end,
                });
                i = end;
                continue;
            }
        }

        // --- Unicode escapes: \uXXXX or \\uXXXX ---
        if c == b'\\' {
            let mut matched = false;
            // \\uXXXX (double backslash)
            if i + 7 < n && d[i + 1] == b'\\' {
                let uc = d[i + 2];
                if (uc == b'u' || uc == b'U')
                    && is_hex_char(d[i + 3])
                    && is_hex_char(d[i + 4])
                    && is_hex_char(d[i + 5])
                    && is_hex_char(d[i + 6])
                {
                    let start = i;
                    let mut end = i + 7;
                    let mut j = end;
                    while j < n {
                        if j + 6 < n && d[j] == b'\\' && d[j + 1] == b'\\' {
                            let uc2 = d[j + 2];
                            if (uc2 == b'u' || uc2 == b'U')
                                && is_hex_char(d[j + 3])
                                && is_hex_char(d[j + 4])
                                && is_hex_char(d[j + 5])
                                && is_hex_char(d[j + 6])
                            {
                                end = j + 7;
                                j = end;
                                continue;
                            }
                        }
                        if j + 5 < n && d[j] == b'\\' {
                            let uc2 = d[j + 1];
                            if (uc2 == b'u' || uc2 == b'U')
                                && is_hex_char(d[j + 2])
                                && is_hex_char(d[j + 3])
                                && is_hex_char(d[j + 4])
                                && is_hex_char(d[j + 5])
                            {
                                end = j + 6;
                                j = end;
                                continue;
                            }
                        }
                        break;
                    }
                    all.push(EncodingMatch {
                        kind: UNICODE_KIND,
                        precedence: precedence_for(UNICODE_KIND),
                        start,
                        end,
                    });
                    i = end;
                    matched = true;
                }
            }
            // \uXXXX (single backslash)
            if !matched && i + 5 < n {
                let uc = d[i + 1];
                if (uc == b'u' || uc == b'U')
                    && is_hex_char(d[i + 2])
                    && is_hex_char(d[i + 3])
                    && is_hex_char(d[i + 4])
                    && is_hex_char(d[i + 5])
                {
                    let start = i;
                    let mut end = i + 6;
                    let mut j = end;
                    while j < n {
                        if j + 6 < n && d[j] == b'\\' && d[j + 1] == b'\\' {
                            let uc2 = d[j + 2];
                            if (uc2 == b'u' || uc2 == b'U')
                                && is_hex_char(d[j + 3])
                                && is_hex_char(d[j + 4])
                                && is_hex_char(d[j + 5])
                                && is_hex_char(d[j + 6])
                            {
                                end = j + 7;
                                j = end;
                                continue;
                            }
                        }
                        if j + 5 < n && d[j] == b'\\' {
                            let uc2 = d[j + 1];
                            if (uc2 == b'u' || uc2 == b'U')
                                && is_hex_char(d[j + 2])
                                && is_hex_char(d[j + 3])
                                && is_hex_char(d[j + 4])
                                && is_hex_char(d[j + 5])
                            {
                                end = j + 6;
                                j = end;
                                continue;
                            }
                        }
                        break;
                    }
                    all.push(EncodingMatch {
                        kind: UNICODE_KIND,
                        precedence: precedence_for(UNICODE_KIND),
                        start,
                        end,
                    });
                    i = end;
                    matched = true;
                }
            }
            if matched {
                continue;
            }
        }

        // --- Hex / Base64 runs ---
        if is_b64_char(c) {
            let start = i;
            let mut all_hex = !is_b64_not_hex(c);
            i += 1;
            while i < n && is_b64_char(d[i]) {
                if is_b64_not_hex(d[i]) {
                    all_hex = false;
                }
                i += 1;
            }
            let run_len = i - start;
            let mut end = i;

            // Count trailing '=' (up to 2) for base64 padding.
            let mut eq_count = 0;
            while eq_count < 2 && end < n && d[end] == b'=' {
                eq_count += 1;
                end += 1;
            }

            if all_hex && run_len >= 32 {
                all.push(EncodingMatch {
                    kind: HEX_KIND,
                    precedence: precedence_for(HEX_KIND),
                    start,
                    end: start + run_len,
                });
            } else if run_len >= 16 {
                all.push(EncodingMatch {
                    kind: BASE64_KIND,
                    precedence: precedence_for(BASE64_KIND),
                    start,
                    end,
                });
            }
            continue;
        }

        i += 1;
    }

    let total_matches = all.len();
    if total_matches <= 1 {
        return all;
    }

    // Filter out lower-precedence matches that overlap their neighbors.
    let mut filtered: Vec<EncodingMatch> = Vec::with_capacity(all.len());
    for idx in 0..total_matches {
        let m = all[idx];
        if idx > 0 {
            let prev = all[idx - 1];
            if m.se().overlaps(prev.se()) && prev.precedence > m.precedence {
                continue;
            }
        }
        if idx + 1 < total_matches {
            let next = all[idx + 1];
            if m.se().overlaps(next.se()) && next.precedence > m.precedence {
                continue;
            }
        }
        filtered.push(m);
    }

    filtered
}

// ---------------------------------------------------------------------------
// EncodedSegment (ports segment.go)
// ---------------------------------------------------------------------------

/// A portion of text that is encoded in some way.
///
/// Faithful port of Go's `EncodedSegment`. `predecessors` is stored by value
/// (owned `Vec`) rather than by pointer; this preserves `toOriginal` recursion
/// semantics without a borrow graph.
#[derive(Clone, Debug)]
pub struct EncodedSegment {
    predecessors: Vec<EncodedSegment>,
    original: StartEnd,
    encoded: StartEnd,
    decoded: StartEnd,
    decoded_value: String,
    encodings: i64,
    depth: i64,
}

/// Ports Go's `toOriginal`.
fn to_original(predecessors: &[EncodedSegment], decoded: StartEnd) -> StartEnd {
    if predecessors.is_empty() {
        return decoded;
    }

    let mut encoded = StartEnd::new(0, 0);

    for p in predecessors {
        if !p.decoded.overlaps(decoded) {
            continue;
        }
        if p.decoded.contains(decoded) {
            return p.original;
        }
        if encoded.end == 0 {
            encoded = p.encoded.add(p.decoded.overflow(decoded));
        } else {
            encoded = encoded.merge(p.encoded.add(p.decoded.overflow(decoded)));
        }
    }

    if encoded.end == 0 {
        return decoded;
    }

    to_original(&predecessors[0].predecessors, encoded)
}

/// Ports Go's `Tags`.
pub fn tags(segments: &[EncodedSegment]) -> Vec<String> {
    if segments.is_empty() {
        return Vec::new();
    }

    let depth = segments[0].depth;

    let mut encodings = segments[0].encodings;
    for s in &segments[1..] {
        encodings |= s.encodings;
    }

    let kinds = encoding_kind_kinds(encodings);
    let mut tags = vec![String::new(); kinds.len() + 1];

    let last = tags.len() - 1;
    tags[last] = format!("decode-depth:{}", depth);
    for (i, kind) in kinds.iter().enumerate() {
        tags[i] = format!("decoded:{}", encoding_kind_string(*kind));
    }

    tags
}

/// Ports Go's `CurrentLine`.
pub fn current_line(segments: &[EncodedSegment], current_raw: &str) -> String {
    if segments.is_empty() {
        return current_raw.to_string();
    }

    let raw = current_raw.as_bytes();
    let mut start = 0usize;
    let mut end = raw.len();

    let mut decoded = segments[0].decoded;
    for s in &segments[1..] {
        decoded = decoded.merge(s.decoded);
    }

    // Find the start of the range.
    let mut i = decoded.start;
    while i > -1 {
        if raw[i as usize] == b'\n' {
            start = i as usize;
            break;
        }
        i -= 1;
    }

    // Find the end of the range.
    let mut i = decoded.end;
    while (i as usize) < end {
        if raw[i as usize] == b'\n' {
            end = i as usize;
            break;
        }
        i += 1;
    }

    bytes_to_string(raw[start..end].to_vec())
}

/// Ports Go's `AdjustMatchIndex`.
pub fn adjust_match_index(segments: &[EncodedSegment], match_index: &[i64]) -> Vec<i64> {
    if segments.is_empty() {
        return match_index.to_vec();
    }

    let m = StartEnd::new(match_index[0], match_index[1]);
    let adjusted = to_original(segments, m);
    vec![adjusted.start, adjusted.end]
}

/// Ports Go's `SegmentsWithDecodedOverlap`.
pub fn segments_with_decoded_overlap(
    segments: &[EncodedSegment],
    start: i64,
    end: i64,
) -> Vec<EncodedSegment> {
    let se = StartEnd::new(start, end);
    segments
        .iter()
        .filter(|s| s.decoded.overlaps(se))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Decoder (ports decoder.go)
// ---------------------------------------------------------------------------

/// Decodes various types of data in place.
#[derive(Debug, Default)]
pub struct Decoder {
    decoded_map: HashMap<String, String>,
}

impl Decoder {
    /// Creates a default decoder (ports Go's `NewDecoder`).
    pub fn new() -> Self {
        Decoder {
            decoded_map: HashMap::new(),
        }
    }

    /// Returns the data with values decoded in place along with the encoded
    /// segment metadata for the next pass of decoding (ports Go's `Decode`).
    pub fn decode(
        &mut self,
        data: &str,
        predecessors: &[EncodedSegment],
    ) -> (String, Vec<EncodedSegment>) {
        let segments = self.find_encoded_segments(data, predecessors);

        if !segments.is_empty() {
            let d = data.as_bytes();
            let mut result: Vec<u8> = Vec::with_capacity(d.len());
            let mut encoded_start = 0usize;
            for segment in &segments {
                let s = segment.encoded.start as usize;
                let e = segment.encoded.end as usize;
                result.extend_from_slice(&d[encoded_start..s]);
                result.extend_from_slice(segment.decoded_value.as_bytes());
                encoded_start = e;
            }
            result.extend_from_slice(&d[encoded_start..]);
            return (bytes_to_string(result), segments);
        }

        (data.to_string(), segments)
    }

    /// Ports Go's `findEncodedSegments`.
    fn find_encoded_segments(
        &mut self,
        data: &str,
        predecessors: &[EncodedSegment],
    ) -> Vec<EncodedSegment> {
        if data.is_empty() {
            return Vec::new();
        }

        let mut decoded_shift: i64 = 0;
        let encoding_matches = find_encoding_matches(data);
        let mut segments: Vec<EncodedSegment> = Vec::with_capacity(encoding_matches.len());

        for m in &encoding_matches {
            let encoded_value = &data[m.start..m.end];
            let decoded_value = match self.decoded_map.get(encoded_value) {
                Some(v) => v.clone(),
                None => {
                    let v = decode_for_kind(m.kind, encoded_value);
                    self.decoded_map.insert(encoded_value.to_string(), v.clone());
                    v
                }
            };

            if decoded_value.is_empty() {
                continue;
            }

            let start = m.start as i64;
            let encoded_len = (m.end - m.start) as i64;
            let decoded_len = decoded_value.len() as i64;

            let mut segment = EncodedSegment {
                predecessors: predecessors.to_vec(),
                original: to_original(predecessors, StartEnd::new(start, m.end as i64)),
                encoded: StartEnd::new(start, m.end as i64),
                decoded: StartEnd::new(start + decoded_shift, start + decoded_shift + decoded_len),
                decoded_value,
                encodings: m.kind,
                depth: 1,
            };

            // Shift decoded start and ends based on size changes.
            decoded_shift += decoded_len - encoded_len;

            // Adjust depth and encoding if applicable.
            if !segment.predecessors.is_empty() {
                segment.depth = 1 + segment.predecessors[0].depth;
                for p in &segment.predecessors {
                    if segment.encoded.overlaps(p.decoded) {
                        segment.encodings |= p.encodings;
                    }
                }
            }

            segments.push(segment);
            // NOTE: Go emits a `logging.Trace()...` here; deliberately dropped
            // (non-observable debug tracing — see PORT-TRACK.md).
        }

        segments
    }
}

#[cfg(test)]
mod tests;
