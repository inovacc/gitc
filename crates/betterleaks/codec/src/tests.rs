//! Faithful port of Go `detect/codec/decoder_test.go` (`TestDecode`).
//!
//! Every case is run three ways, exactly like the Go table test: (1) raw,
//! (2) wrapped with `url.PathEscape` (percent decoding), (3) wrapped with
//! `hex.EncodeToString` (hex decoding) — via a `full_decode` driver that loops
//! `Decode` until it returns zero segments.

use super::*;

/// Loops `decode` until it returns zero segments (ports the test's `fullDecode`).
fn full_decode(decoder: &mut Decoder, data: &str) -> String {
    let mut data = data.to_string();
    let mut segments: Vec<EncodedSegment> = Vec::new();
    loop {
        let (next, segs) = decoder.decode(&data, &segments);
        data = next;
        segments = segs;
        if segments.is_empty() {
            return data;
        }
    }
}

/// Hand-rolled `encoding/hex.EncodeToString` (lowercase hex).
fn hex_encode_to_string(data: &[u8]) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(LOWER[(b >> 4) as usize] as char);
        s.push(LOWER[(b & 0x0f) as usize] as char);
    }
    s
}

/// Hand-rolled `net/url.PathEscape` (`escape` with `encodePathSegment` mode).
fn path_escape(s: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if should_escape_path_segment(c) {
            out.push('%');
            out.push(UPPER[(c >> 4) as usize] as char);
            out.push(UPPER[(c & 0x0f) as usize] as char);
        } else {
            // Only ASCII bytes ever reach here (non-ASCII is always escaped),
            // so `c as char` is a faithful byte-to-char mapping.
            out.push(c as char);
        }
    }
    out
}

/// Ports Go's `shouldEscape(c, encodePathSegment)`.
fn should_escape_path_segment(c: u8) -> bool {
    // §2.3 Unreserved characters (alphanumerics)
    if c.is_ascii_alphanumeric() {
        return false;
    }
    match c {
        // §2.3 Unreserved marks
        b'-' | b'_' | b'.' | b'~' => false,
        // §2.2 Reserved characters escaped in a path segment
        b'/' | b';' | b',' | b'?' => true,
        // §2.2 Reserved characters NOT escaped in a path segment
        b'$' | b'&' | b'+' | b':' | b'=' | b'@' => false,
        // Everything else must be escaped.
        _ => true,
    }
}

fn cases() -> Vec<(String, String, &'static str)> {
    // Shared whitespace for the multiline slack-message case: a newline followed
    // by tab indentation (matches the Go raw-string continuation line). Using the
    // identical prefix in both chunk and expected preserves parity — whitespace
    // is passthrough for the decoder.
    let ws = "\n\t\t\t\t\t";
    let multiline_chunk = format!(
        "Many substrings in this slack message could be base64 decoded{ws}but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded."
    );
    let multiline_expected = format!(
        "Many substrings in this slack message could be base64 decoded{ws}but only this encapsulated secret should be decoded."
    );

    vec![
        (
            "bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=".to_string(),
            "longer-encoded-secret-test".to_string(),
            "only b64 chunk",
        ),
        (
            "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=".to_string(),
            "token: longer-encoded-secret-test".to_string(),
            "mixed content",
        ),
        (String::new(), String::new(), "no chunk"),
        (
            "some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=".to_string(),
            "some-encoded-secret=test-secret-value".to_string(),
            "env var (looks like all b64 decodable but has `=` in the middle)",
        ),
        (
            "some-encoded-secret=\"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=\"".to_string(),
            "some-encoded-secret=\"longer-encoded-secret-test\"".to_string(),
            "has longer b64 inside",
        ),
        (multiline_chunk, multiline_expected, "many possible substrings"),
        (
            "bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q".to_string(),
            "longer-encoded-secret-test".to_string(),
            "b64-url-safe: only b64 chunk",
        ),
        (
            "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q".to_string(),
            "token: longer-encoded-secret-test".to_string(),
            "b64-url-safe: mixed content",
        ),
        (
            "some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=".to_string(),
            "some-encoded-secret=test-secret-value".to_string(),
            "b64-url-safe: env var",
        ),
        (
            "some-encoded-secret=\"bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q\"".to_string(),
            "some-encoded-secret=\"longer-encoded-secret-test\"".to_string(),
            "b64-url-safe: has longer b64 inside",
        ),
        (
            "Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM".to_string(),
            "gitleaks>>finds-secrets".to_string(),
            "b64-url-safe: hyphen url b64",
        ),
        (
            "YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_".to_string(),
            "b64urlsafe-test-secret-underscores??".to_string(),
            "b64-url-safe: underscore url b64",
        ),
        (
            "a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3".to_string(),
            "a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3".to_string(),
            "invalid base64 string",
        ),
        (
            "secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22".to_string(),
            "secret=\"q$!@#$%^&*( asdf\"".to_string(),
            "url encoded value",
        ),
        (
            "secret=\"466973684D617048756E6B79212121363334\"".to_string(),
            "secret=\"FishMapHunky!!!634\"".to_string(),
            "hex encoded value",
        ),
        (
            "secret=U+0061 U+0062 U+0063 U+0064 U+0065 U+0066".to_string(),
            "secret=abcdef".to_string(),
            "unicode encoded value",
        ),
        (
            "secret=\\\\u0068\\\\u0065\\\\u006c\\\\u006c\\\\u006f\\\\u0020\\\\u0077\\\\u006f\\\\u0072\\\\u006c\\\\u0064\\\\u0020\\\\u0064\\\\u0075\\\\u0064\\\\u0065".to_string(),
            "secret=hello world dude".to_string(),
            "unicode encoded value backslashed",
        ),
        (
            "secret=\\u0068\\u0065\\u006c\\u006c\\u006f\\u0020\\u0077\\u006f\\u0072\\u006c\\u0064 6C6F76656C792070656F706C65206F66206561727468".to_string(),
            "secret=hello world lovely people of earth".to_string(),
            "unicode encoded value backslashed mixed w/ hex",
        ),
    ]
}

#[test]
fn decode_raw() {
    let mut decoder = Decoder::new();
    for (chunk, expected, name) in cases() {
        assert_eq!(expected, full_decode(&mut decoder, &chunk), "raw: {name}");
    }
}

#[test]
fn decode_percent_wrapped() {
    let mut decoder = Decoder::new();
    for (chunk, expected, name) in cases() {
        let encoded_chunk = path_escape(&chunk);
        assert_eq!(
            expected,
            full_decode(&mut decoder, &encoded_chunk),
            "percent-wrapped: {name}"
        );
    }
}

#[test]
fn decode_hex_wrapped() {
    let mut decoder = Decoder::new();
    for (chunk, expected, name) in cases() {
        let encoded_chunk = hex_encode_to_string(chunk.as_bytes());
        assert_eq!(
            expected,
            full_decode(&mut decoder, &encoded_chunk),
            "hex-wrapped: {name}"
        );
    }
}

// Differential parity: goldens captured from the Go source's `fullDecode` driver
// on NOVEL inputs NOT in the table above, probing the unsampled tail. They cover
// the base64 length/entropy heuristic (Go leaves SHORT tokens undecoded — even
// `dmFsaWQtdG9rZW4=` passes through unchanged), the iterate-until-stable
// multi-pass (`JTcz…` base64 -> `%73…` percent -> `secret`), and mixed
// decode/passthrough in one line. The Rust port must reproduce Go byte-for-byte,
// including the non-decodes.
#[test]
fn diff_novel_inputs_match_go_golden() {
    let cases = [
        ("user=YWRtaW4= pw=%73%65%63%72%65%74", "user=YWRtaW4= pw=secret"),
        ("mix AB and Y2hhaW4=", "mix AB and Y2hhaW4="),
        (
            "raw=notbase64!! ok=dmFsaWQtdG9rZW4=",
            "raw=notbase64!! ok=dmFsaWQtdG9rZW4=",
        ),
        ("deep=JTczJTY1JTYzJTcyJTY1JTc0", "deep=secret"),
    ];
    for (input, want) in cases {
        let mut decoder = Decoder::new();
        assert_eq!(want, full_decode(&mut decoder, input), "diff: {input}");
    }
}

// Characterization test for the exported segment functions (`tags`,
// `current_line`, `adjust_match_index`, `segments_with_decoded_overlap`), which
// have NO source test in Go's `decoder_test.go`. Goldens captured from the Go
// source by decoding a real input to segments and calling each function.
#[test]
fn segment_functions_match_go_golden() {
    let mut decoder = Decoder::new();
    let raw = "hello dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 world";
    let (decoded, segs) = decoder.decode(raw, &[]);

    assert_eq!(decoded, "hello this encapsulated secret world");
    assert_eq!(segs.len(), 1);

    // Tags: encodings + decode depth.
    assert_eq!(tags(&segs), vec!["decoded:base64", "decode-depth:1"]);
    // CurrentLine: no newlines ⇒ the whole decoded line.
    assert_eq!(current_line(&segs, &decoded), "hello this encapsulated secret world");
    // AdjustMatchIndex: a decoded-range match [6,10] maps back to the original
    // base64 token span [6,38].
    assert_eq!(adjust_match_index(&segs, &[6, 10]), vec![6_i64, 38]);
    // SegmentsWithDecodedOverlap: overlaps the decoded region [6,30], not [0,3].
    assert_eq!(segments_with_decoded_overlap(&segs, 6, 10).len(), 1);
    assert_eq!(segments_with_decoded_overlap(&segs, 0, 3).len(), 0);

    // Empty-segment behaviors (each function's early-return path).
    let empty: Vec<EncodedSegment> = Vec::new();
    assert!(tags(&empty).is_empty());
    assert_eq!(current_line(&empty, "abc"), "abc");
    assert_eq!(adjust_match_index(&empty, &[3, 7]), vec![3_i64, 7]);
    assert_eq!(segments_with_decoded_overlap(&empty, 0, 5).len(), 0);
}
