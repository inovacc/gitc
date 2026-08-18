//! AWS Signature Version 4 request signing (faithful 1:1 port of Go `internal/sigv4`).
//!
//! SigV4 is the request-signing scheme used by S3, STS, and every S3-compatible
//! object store (R2, MinIO, B2, etc.). The algorithm and credentials are
//! per-service: the signing math is identical, but credentials issued by one
//! provider only authenticate against that provider's endpoints.
//!
//! Spec: <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>
//!
//! Reshape note (vs Go): Go's `Sign` took a `*http.Request`; Rust std has no HTTP
//! type, so this port defines a minimal [`Request`] with the same observable
//! header semantics (case-insensitive lookup, multi-value join with `,`) and
//! `sign(&mut req, ...)` mutates headers in place, mirroring Go's in-place `Sign`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Lowercase-hex SHA-256 of the empty string, used as the canonical payload
/// hash for requests with no body.
pub const EMPTY_PAYLOAD_SHA: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Error returned by [`sign`]. Mirrors the single Go failure mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigV4Error {
    /// Access key or secret key was empty.
    MissingCredentials,
}

impl fmt::Display for SigV4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Exact Go error text, preserved for 1:1 observable behavior.
            SigV4Error::MissingCredentials => f.write_str("sigv4: missing access key or secret"),
        }
    }
}

impl std::error::Error for SigV4Error {}

/// Static SigV4 credentials. `session_token` is optional and only populated for
/// temporary credentials (STS, IAM Roles Anywhere, etc.); empty ⇒ omitted.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: String,
}

impl Credentials {
    /// Static credentials with no session token (mirrors the common Go literal
    /// `Credentials{AccessKey: .., SecretKey: ..}`).
    pub fn new(access_key: &str, secret_key: &str) -> Self {
        Credentials {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            session_token: String::new(),
        }
    }
}

/// A civil UTC timestamp broken into fields. Replaces Go's `time.Time` argument
/// to `signAt`; [`Timestamp::now`] mirrors `time.Now().UTC()`.
#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Timestamp {
    /// Current UTC time.
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        Timestamp {
            year,
            month,
            day,
            hour: (rem / 3600) as u32,
            minute: ((rem % 3600) / 60) as u32,
            second: (rem % 60) as u32,
        }
    }

    /// `20060102T150405Z`
    fn amz_date(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// `20060102`
    fn date_stamp(&self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }
}

/// Convert days since the Unix epoch (1970-01-01) to `(year, month, day)`.
/// Howard Hinnant's `civil_from_days` algorithm — pure std, no calendar crate.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// A minimal HTTP request: enough of Go's `*http.Request` for SigV4. Headers use
/// case-insensitive name lookup and preserve insertion for multi-value join.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub host: String,
    pub path: String,
    pub raw_query: String,
    headers: Vec<(String, Vec<String>)>,
}

impl Request {
    /// Parse `scheme://host/path?query` into a request (mirrors
    /// `http.NewRequest(method, url, nil)` for the static URLs this port needs).
    pub fn new(method: &str, url: &str) -> Self {
        let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let host = &after[..end];
        let rest = &after[end..];
        let (path_part, query) = match rest.split_once('?') {
            Some((p, q)) => (p, q.split_once('#').map(|(q, _)| q).unwrap_or(q)),
            None => (rest.split_once('#').map(|(p, _)| p).unwrap_or(rest), ""),
        };
        let path = if path_part.is_empty() {
            "/".to_string()
        } else {
            path_part.to_string()
        };
        Request {
            method: method.to_string(),
            host: host.to_string(),
            path,
            raw_query: query.to_string(),
            headers: Vec::new(),
        }
    }

    /// Every header, flattened, for a caller that must actually SEND the
    /// request.
    ///
    /// The crate was ported without a sender — signing was verified against AWS
    /// test vectors, which need only the canonical string — so nothing needed
    /// this until the S3 source arrived. It returns one entry per VALUE, since
    /// a header may legitimately repeat.
    pub fn headers(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .flat_map(|(name, values)| values.iter().map(move |v| (name.clone(), v.clone())))
            .collect()
    }

    /// Set a header, replacing any existing value(s) (mirrors `Header.Set`).
    pub fn set_header(&mut self, name: &str, value: &str) {
        for (n, vs) in self.headers.iter_mut() {
            if n.eq_ignore_ascii_case(name) {
                *vs = vec![value.to_string()];
                return;
            }
        }
        self.headers.push((name.to_string(), vec![value.to_string()]));
    }

    /// First value of a header, or `""` if absent (mirrors `Header.Get`).
    pub fn header(&self, name: &str) -> String {
        for (n, vs) in &self.headers {
            if n.eq_ignore_ascii_case(name) {
                return vs.first().cloned().unwrap_or_default();
            }
        }
        String::new()
    }
}

/// Sign `req` in place using SigV4 for the given region and service (uses the
/// current UTC time). Pass `None`/empty `body` for empty payloads.
pub fn sign(
    req: &mut Request,
    body: Option<&[u8]>,
    region: &str,
    service: &str,
    creds: Credentials,
) -> Result<(), SigV4Error> {
    sign_at(req, body, region, service, creds, Timestamp::now())
}

/// [`sign`] with an injected timestamp (for testing).
fn sign_at(
    req: &mut Request,
    body: Option<&[u8]>,
    region: &str,
    service: &str,
    creds: Credentials,
    now: Timestamp,
) -> Result<(), SigV4Error> {
    if creds.access_key.is_empty() || creds.secret_key.is_empty() {
        return Err(SigV4Error::MissingCredentials);
    }
    let amz_date = now.amz_date();
    let date_stamp = now.date_stamp();

    let payload_hash = match body {
        Some(b) if !b.is_empty() => sha256_hex(b),
        _ => EMPTY_PAYLOAD_SHA.to_string(),
    };

    req.set_header("X-Amz-Date", &amz_date);
    req.set_header("X-Amz-Content-Sha256", &payload_hash);
    if !creds.session_token.is_empty() {
        req.set_header("X-Amz-Security-Token", &creds.session_token);
    }

    let (canonical_headers, signed_headers) = canonical_headers(req);
    let canonical_query = canonical_query(&req.raw_query);
    let canonical_uri = canonical_uri(&req.path);

    let canonical_request = [
        req.method.as_str(),
        &canonical_uri,
        &canonical_query,
        &canonical_headers,
        &signed_headers,
        &payload_hash,
    ]
        .join("\n");

    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = [
        ALGORITHM,
        &amz_date,
        &scope,
        &sha256_hex(canonical_request.as_bytes()),
    ]
        .join("\n");

    let signing_key = derive_signing_key(&creds.secret_key, &date_stamp, region, service);
    let signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    req.set_header(
        "Authorization",
        &format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key
        ),
    );
    Ok(())
}

/// SigV4 signing key for the given secret, date (`YYYYMMDD`), region, and service.
pub fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// HMAC-SHA256(data) keyed with key.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase-hex SHA-256 hash of data.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

/// Lowercase-hex encode (replaces `encoding/hex.EncodeToString`; no crate).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn canonical_headers(req: &Request) -> (String, String) {
    // (lowercased-name, joined-value)
    let mut headers: Vec<(String, String)> = vec![("host".to_string(), req.host.clone())];
    for (name, values) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "host" || lower == "authorization" {
            continue;
        }
        // Sign only the headers SigV4 callers set deliberately (host, x-amz-*,
        // content-*); skip Accept-Encoding/User-Agent etc. so middleware that
        // populates them later doesn't invalidate the signature.
        if !lower.starts_with("x-amz-") && !lower.starts_with("content-") {
            continue;
        }
        headers.push((lower, values.join(",")));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut cb = String::new();
    let mut sb = String::new();
    for (i, (k, v)) in headers.iter().enumerate() {
        cb.push_str(k);
        cb.push(':');
        cb.push_str(collapse_whitespace(v).trim());
        cb.push('\n');
        if i > 0 {
            sb.push(';');
        }
        sb.push_str(k);
    }
    (cb, sb)
}

/// Collapse runs of spaces/tabs into a single space (SigV4 canonicalization).
fn collapse_whitespace(s: &str) -> String {
    let mut b = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.bytes() {
        if c == b' ' || c == b'\t' {
            if !prev_space {
                b.push(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        b.push(c as char);
    }
    b
}

fn canonical_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    // Parse into a key -> sorted-values map, decoding percent-escapes and '+'.
    let mut map: Vec<(String, Vec<String>)> = Vec::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        match map.iter_mut().find(|(key, _)| *key == k) {
            Some((_, vals)) => vals.push(v),
            None => map.push((k, vec![v])),
        }
    }
    if map.is_empty() {
        return String::new();
    }
    map.sort_by(|a, b| a.0.cmp(&b.0));

    let mut b = String::new();
    for (i, (k, vs)) in map.iter().enumerate() {
        let mut vs = vs.clone();
        vs.sort();
        for (j, v) in vs.iter().enumerate() {
            if i > 0 || j > 0 {
                b.push('&');
            }
            b.push_str(&uri_encode(k, true));
            b.push('=');
            b.push_str(&uri_encode(v, true));
        }
    }
    b
}

/// URI-encode the path once (S3-style; `/` preserved between segments).
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    uri_encode(path, false)
}

/// AWS-spec URI encoding: unreserved chars (`A-Z a-z 0-9 - _ . ~`) pass through;
/// everything else is percent-encoded per byte. With `encode_slash=false`
/// (path components), `/` is preserved.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut b = String::with_capacity(s.len());
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                b.push(c as char)
            }
            b'/' if !encode_slash => b.push('/'),
            _ => b.push_str(&format!("%{c:02X}")),
        }
    }
    b
}

/// Minimal percent-decode (with `+` → space, as in query parsing). No crate.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if let (Some(h), Some(l)) = (
                    hex_val(bytes.get(i + 1).copied()),
                    hex_val(bytes.get(i + 2).copied()),
                ) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: Option<u8>) -> Option<u8> {
    match b {
        Some(c @ b'0'..=b'9') => Some(c - b'0'),
        Some(c @ b'a'..=b'f') => Some(c - b'a' + 10),
        Some(c @ b'A'..=b'F') => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical AWS test vector.
    #[test]
    fn derive_signing_key_golden_vector() {
        let got = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";
        assert_eq!(want, hex_encode(&got));
    }

    #[test]
    fn uri_encode_cases() {
        let cases = [
            ("foo/bar.txt", false, "foo/bar.txt"),
            ("foo/bar.txt", true, "foo%2Fbar.txt"),
            ("hello world", false, "hello%20world"),
            ("a+b=c", false, "a%2Bb%3Dc"),
            ("unicode-café", false, "unicode-caf%C3%A9"),
        ];
        for (input, encode_slash, want) in cases {
            assert_eq!(want, uri_encode(input, encode_slash), "input {input}");
        }
    }

    #[test]
    fn sign_sets_required_headers() {
        let mut req = Request::new("GET", "https://mybucket.s3.us-east-1.amazonaws.com/?list-type=2");
        let creds = Credentials::new("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        sign(&mut req, None, "us-east-1", "s3", creds).unwrap();

        let auth = req.header("Authorization");
        assert!(auth.contains(&format!("{ALGORITHM} ")));
        assert!(auth.contains("Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth.contains("/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert_eq!(EMPTY_PAYLOAD_SHA, req.header("X-Amz-Content-Sha256"));
        assert!(!req.header("X-Amz-Date").is_empty());
    }

    #[test]
    fn sign_includes_session_token_when_set() {
        let mut req = Request::new("GET", "https://example.s3.us-east-1.amazonaws.com/");
        let mut creds = Credentials::new("ak", "sk");
        creds.session_token = "tok".to_string();
        sign(&mut req, None, "us-east-1", "s3", creds).unwrap();
        assert_eq!("tok", req.header("X-Amz-Security-Token"));
        assert!(req
            .header("Authorization")
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"));
    }

    #[test]
    fn sign_missing_creds_errors() {
        let mut req = Request::new("GET", "https://example.s3.us-east-1.amazonaws.com/");
        assert!(sign(&mut req, None, "us-east-1", "s3", Credentials::new("", "")).is_err());
    }

    // Same request + same time ⇒ same Authorization header.
    #[test]
    fn sign_deterministic() {
        let ts = Timestamp { year: 2025, month: 1, day: 2, hour: 3, minute: 4, second: 5 };
        let mk = || {
            let mut r = Request::new("POST", "https://sts.amazonaws.com/");
            r.set_header("Content-Type", "application/x-www-form-urlencoded");
            r
        };
        let creds = Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let body = b"Action=GetCallerIdentity&Version=2011-06-15";
        let mut r1 = mk();
        let mut r2 = mk();
        sign_at(&mut r1, Some(body), "us-east-1", "sts", creds.clone(), ts).unwrap();
        sign_at(&mut r2, Some(body), "us-east-1", "sts", creds, ts).unwrap();
        assert_eq!(r1.header("Authorization"), r2.header("Authorization"));
        assert!(r1
            .header("Authorization")
            .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
    }

    // Differential parity: golden captured from the Go source (`signAt`) on a
    // novel input NOT covered by the ported tests — query key+value sort with a
    // `%2F`-escaped value, multiple signed headers (incl. a spaced value), a
    // non-empty body hash, and a non-us-east-1 region. The Rust port must
    // reproduce the Go `Authorization` byte-for-byte.
    #[test]
    fn diff_novel_input_matches_go_golden() {
        let ts = Timestamp { year: 2025, month: 6, day: 15, hour: 12, minute: 30, second: 45 };
        let mut req = Request::new(
            "POST",
            "https://logs.s3.eu-west-1.amazonaws.com/upload/path?prefix=logs%2Fapp&max-keys=100",
        );
        req.set_header("Content-Type", "text/plain");
        req.set_header("X-Amz-Meta-Foo", "Bar Baz");
        let creds = Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        sign_at(&mut req, Some(b"hello world"), "eu-west-1", "s3", creds, ts).unwrap();

        assert_eq!(
            req.header("Authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20250615/eu-west-1/s3/aws4_request, \
             SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-foo, \
             Signature=81f56978d333aebbc09df1a6f2612901e93728ee451bc6ffa26715702b45d3a6"
        );
        assert_eq!(
            req.header("X-Amz-Content-Sha256"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(req.header("X-Amz-Date"), "20250615T123045Z");
    }
}
