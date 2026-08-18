//! Port of Go's VALIDATION bindings — `bindings_http`, `bindings_crypto`,
//! `bindings_base64`, `bindings_hex`, `bindings_json`, `bindings_time`,
//! `bindings_env`, `bindings_strings` and `bindings_validate`, plus the
//! validation-only builtins from `runtime.go`'s `validationBindings`.
//!
//! This is what a `validate = '''…'''` expression can actually DO. The
//! 186 shipped expressions between them use `http.get`/`http.post`,
//! `base64.encode`, `crypto.hmacSha256`/`hmacSha1`/`sha1`,
//! `strings.urlQueryEscape`, `json.string`, `hex.encode`, `time.nowUnix`,
//! `time.nowRFC3339`, `env.getOrDefault`, `validate.unknown`, and the builtins
//! `bytes`, `size`, `replace`, `split`, `substring`, `lastIndexOf`, `contains`
//! and `any`.
//!
//! ## The network is a seam, not a hard-wired call
//!
//! [`HttpClient`] is a trait. Everything here — building the request, reading
//! the response into `{status, json, headers, body}`, deciding what counts as
//! valid — is testable against a stub, and the real client is injected by the
//! caller. Validation makes live requests to third-party providers; a test
//! suite that needed those would never run.
//!
//! ## Two deliberate refusals
//!
//! * **`env.get` without an allowlist is an ERROR**, not an empty string. A
//!   validation expression is config, and config that can read arbitrary
//!   environment variables is an exfiltration primitive. Go requires
//!   `--validation-env-vars` and so does this.
//! * **A non-JSON response body yields an empty JSON object**, matching Go, so
//!   `r.json?.error ?? "…"` degrades instead of failing. That IS the common
//!   case: an invalid credential usually gets an HTML error page.

use crate::eval::{EvalError, Value};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// One outbound validation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    /// The rule this request belongs to, for the per-rule rate limit.
    ///
    /// Carried ON THE REQUEST rather than set on the client beforehand. A
    /// client is shared by every pool worker, so a "current rule" field on it
    /// is a race: two workers validating different rules would overwrite each
    /// others value between the set and the send.
    pub rule_id: String,
    /// Header order is irrelevant to a server but not to a test, so it is
    /// stable.
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: i64,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Why a request did not produce a response.
///
/// Two cases, kept apart because they are different ANSWERS and must not share
/// a validation status. Go distinguishes them and so does this: a budget
/// refusal becomes `needs_validation` with the target and the counts, telling
/// the user to check that one by hand, while a transport failure becomes
/// `error`. Collapsing them would report "your scan hit its own limit" as "this
/// credential is broken".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// DNS, TLS, connection, timeout — the request was attempted and failed.
    Transport(String),
    /// The request was REFUSED before it left, by the per-target budget.
    LimitHit(crate::validation_limits::ValidationRequestLimitHit),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Transport(m) => f.write_str(m),
            HttpError::LimitHit(h) => write!(f, "{h}"),
        }
    }
}

/// The network seam.
pub trait HttpClient: Send + Sync {
    /// A transport-level failure is an `Err`; an HTTP error STATUS is an `Ok`
    /// with that status, because a 401 is a perfectly good answer to "is this
    /// secret live?".
    ///
    /// The budget refusal travels in the RETURN VALUE rather than through state
    /// on the client. One client is shared by every pool worker, so a
    /// "most recent hit" field on it is a race — the refusal would land on
    /// whichever finding read it first, which is not necessarily the one that
    /// was refused. That race existed here and the differential caught it: the
    /// refusal was attributed to the finding that had succeeded.
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// Go `maxResponseBody` — validation reads at most this much of a response.
///
/// A provider that streams megabytes at an unauthenticated request would
/// otherwise let one finding consume the scan.
pub const MAX_RESPONSE_BODY: usize = 1 << 20;

/// Everything a validation expression may reach outside itself.
pub struct ValidationEnv<'a> {
    pub http: &'a dyn HttpClient,
    /// Go `AllowedEnv`. EMPTY means `env.get` fails rather than reads.
    pub allowed_env: std::collections::BTreeSet<String>,
    /// Injected so `time.nowUnix()` is testable; Go calls `time.Now()`.
    pub now_unix: &'a dyn Fn() -> i64,
    /// The rule being validated, for the request limiter's per-rule rate.
    pub rule_id: String,
}

impl std::fmt::Debug for ValidationEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationEnv")
            .field("allowed_env", &self.allowed_env)
            .field("rule_id", &self.rule_id)
            .finish_non_exhaustive()
    }
}

/// Go `buildResponseMap` — the `r` a validation expression works with.
///
/// `r.json` is an empty MAP when the body is not JSON, never an error. An
/// invalid credential usually gets an HTML error page, and every expression
/// that reads `r.json?.error` has to survive that.
pub fn build_response(resp: &HttpResponse) -> Value {
    let body_text = String::from_utf8_lossy(&resp.body).into_owned();
    let json = parse_json(&body_text).unwrap_or_else(|| {
        logging::debug()
            .int("status", resp.status)
            .msg("http response body is not valid JSON, falling back to empty object");
        Value::Map(BTreeMap::new())
    });

    let mut headers = BTreeMap::new();
    for (k, v) in &resp.headers {
        // Go lower-cases every header name; a validation expression reading
        // `r.headers["x-ratelimit-remaining"]` depends on it.
        headers.insert(k.to_lowercase(), Value::Str(v.clone()));
    }

    let mut m = BTreeMap::new();
    m.insert("status".to_string(), Value::Num(resp.status as f64));
    m.insert("json".to_string(), json);
    m.insert("headers".to_string(), Value::Map(headers));
    m.insert("body".to_string(), Value::Str(body_text));
    Value::Map(m)
}

/// Go `unknownResult` — the fallback every expression ends with.
///
/// It turns "I could not tell" into a REASON, which is the difference between
/// a report saying `needs_validation: rate limited` and one silently listing
/// the finding as unvalidated.
pub fn unknown_result(resp: &Value) -> Value {
    let mut m = BTreeMap::new();
    m.insert("result".to_string(), Value::str("unknown"));
    if let Value::Map(r) = resp {
        if let Some(status) = r.get("status") {
            let reason = match status {
                Value::Num(n) if *n == 429.0 => "rate limited".to_string(),
                Value::Num(n) if n.fract() == 0.0 => format!("HTTP {}", *n as i64),
                other => format!("HTTP {}", display(other)),
            };
            m.insert("reason".to_string(), Value::Str(reason));
        }
    }
    Value::Map(m)
}

/// A minimal JSON reader producing [`Value`].
///
/// Hand-written rather than routed through `serde_json` because `Value` is this
/// crate's own type: going through `serde_json::Value` would mean a second full
/// tree and a conversion, for a document that is already being walked once.
/// `exprruntime` also deliberately carries no serialization dependency.
pub fn parse_json(text: &str) -> Option<Value> {
    let b = text.as_bytes();
    let mut i = 0usize;
    let v = json_value(b, &mut i)?;
    json_ws(b, &mut i);
    if i != b.len() {
        return None;
    }
    Some(v)
}

fn json_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn json_value(b: &[u8], i: &mut usize) -> Option<Value> {
    json_ws(b, i);
    match *b.get(*i)? {
        b'{' => {
            *i += 1;
            let mut m = BTreeMap::new();
            json_ws(b, i);
            if b.get(*i) == Some(&b'}') {
                *i += 1;
                return Some(Value::Map(m));
            }
            loop {
                json_ws(b, i);
                let Some(Value::Str(k)) = json_value(b, i) else {
                    return None;
                };
                json_ws(b, i);
                if b.get(*i) != Some(&b':') {
                    return None;
                }
                *i += 1;
                let v = json_value(b, i)?;
                m.insert(k, v);
                json_ws(b, i);
                match b.get(*i) {
                    Some(b',') => *i += 1,
                    Some(b'}') => {
                        *i += 1;
                        return Some(Value::Map(m));
                    }
                    _ => return None,
                }
            }
        }
        b'[' => {
            *i += 1;
            let mut items = Vec::new();
            json_ws(b, i);
            if b.get(*i) == Some(&b']') {
                *i += 1;
                return Some(Value::List(items));
            }
            loop {
                items.push(json_value(b, i)?);
                json_ws(b, i);
                match b.get(*i) {
                    Some(b',') => *i += 1,
                    Some(b']') => {
                        *i += 1;
                        return Some(Value::List(items));
                    }
                    _ => return None,
                }
            }
        }
        b'"' => json_string(b, i).map(Value::Str),
        b't' => {
            expect_word(b, i, b"true")?;
            Some(Value::Bool(true))
        }
        b'f' => {
            expect_word(b, i, b"false")?;
            Some(Value::Bool(false))
        }
        b'n' => {
            expect_word(b, i, b"null")?;
            Some(Value::Nil)
        }
        _ => {
            let start = *i;
            if b.get(*i) == Some(&b'-') {
                *i += 1;
            }
            while *i < b.len()
                && matches!(b[*i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                *i += 1;
            }
            if *i == start {
                return None;
            }
            std::str::from_utf8(&b[start..*i])
                .ok()?
                .parse::<f64>()
                .ok()
                .map(Value::Num)
        }
    }
}

fn expect_word(b: &[u8], i: &mut usize, word: &[u8]) -> Option<()> {
    if b.len() < *i + word.len() || &b[*i..*i + word.len()] != word {
        return None;
    }
    *i += word.len();
    Some(())
}

fn json_string(b: &[u8], i: &mut usize) -> Option<String> {
    if b.get(*i) != Some(&b'"') {
        return None;
    }
    *i += 1;
    let mut out = String::new();
    loop {
        match *b.get(*i)? {
            b'"' => {
                *i += 1;
                return Some(out);
            }
            b'\\' => {
                *i += 1;
                match *b.get(*i)? {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex = std::str::from_utf8(b.get(*i + 1..*i + 5)?).ok()?;
                        let cp = u32::from_str_radix(hex, 16).ok()?;
                        *i += 4;
                        // A lone surrogate is replaced rather than rejected —
                        // refusing the whole document over one bad escape would
                        // lose a response that is otherwise perfectly readable.
                        out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                    }
                    _ => return None,
                }
                *i += 1;
            }
            _ => {
                // Copy the whole UTF-8 sequence.
                let rest = std::str::from_utf8(&b[*i..]).ok()?;
                let ch = rest.chars().next()?;
                out.push(ch);
                *i += ch.len_utf8();
            }
        }
    }
}

/// Go `json.Marshal` of a STRING — `json.string(s)`, used to embed a secret in
/// a request body safely.
///
/// HTML-escaped, as Go's encoder is by default. That is the whole reason this
/// is not `format!("{s:?}")`: a secret containing `<` would produce a body Go
/// and this port disagree on.
pub fn go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go `url.QueryEscape`.
///
/// NOT the same as percent-encoding a path: a space becomes `+`, and the
/// unreserved set is exactly `A-Za-z0-9-_.~`. Getting this wrong produces a
/// request that a provider answers with 400, which reads as "invalid secret".
pub fn url_query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Go `hex.EncodeToString` — lower-case, no separators.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Go `time.Now().UTC().Format(time.RFC3339)`.
pub fn rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// RFC 1123 in UTC - `Mon, 02 Jan 2006 15:04:05 GMT`.
///
/// Azure signs over this exact spelling, so the day and month NAMES matter and
/// the timezone is the literal `GMT` rather than `+0000`. A signature computed
/// over any other rendering is rejected, which would read as "invalid key".
pub fn rfc1123_utc(unix_secs: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let weekday = ((days.rem_euclid(7) + 4) % 7) as usize;
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Howard Hinnant''s `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// How a value prints when concatenated into a URL or a header.
pub fn display(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        // Go prints an integral float without a decimal point.
        Value::Num(n) if n.fract() == 0.0 && n.is_finite() => format!("{}", *n as i64),
        Value::Num(n) => format!("{n}"),
        Value::Bool(b) => b.to_string(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Nil => String::new(),
        Value::List(_) | Value::Map(_) => String::new(),
    }
}

/// Coerce to bytes for the crypto and encoding functions.
fn as_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b.clone(),
        other => display(other).into_bytes(),
    }
}

/// Is this one of the validation-namespace functions?
///
/// Kept next to the dispatcher so the two lists cannot drift: a name that
/// dispatches here must be accepted by `config check`, and a name accepted
/// there must dispatch.
pub fn is_validation_function(name: &str) -> bool {
    matches!(
        name,
        "http.get"
            | "http.post"
            | "validate.unknown"
            | "unknown"
            | "base64.encode"
            | "base64.decode"
            | "hex.encode"
            | "json.string"
            | "crypto.md5"
            | "crypto.sha1"
            | "crypto.hmacSha1"
            | "crypto.hmacSha256"
            | "crypto.hmac_sha256"
            | "strings.urlQueryEscape"
            | "strings.url_query_escape"
            | "strings.obfuscate"
            | "obfuscate"
            | "time.nowUnix"
            | "time.now_unix"
            | "time.nowRFC3339"
            | "env.get"
            | "env_get"
            | "env.getOrDefault"
    )
}

/// Dispatch a validation-namespace function.
///
/// Returns `Ok(None)` when the name is not one of ours, so the caller can fall
/// through to the filter builtins rather than this deciding what is unknown.
pub fn call_validation(
    name: &str,
    args: &[Value],
    env: Option<&ValidationEnv>,
) -> Result<Option<Value>, EvalError> {
    let arity = |want: usize| -> Result<(), EvalError> {
        if args.len() != want {
            return Err(EvalError::Arity {
                name: name.to_string(),
                want,
                got: args.len(),
            });
        }
        Ok(())
    };
    // A validation-only function called from a FILTER expression has no
    // environment. Saying so beats a confusing type error.
    let need_env = || -> Result<&ValidationEnv, EvalError> {
        env.ok_or_else(|| {
            EvalError::Type(format!(
                "{name} is only available in a validate expression"
            ))
        })
    };

    let out = match name {
        // ── http ────────────────────────────────────────────────────────────
        "http.get" | "http.post" => {
            let is_post = name == "http.post";
            if is_post {
                arity(3)?;
            } else {
                arity(2)?;
            }
            let env = need_env()?;
            let req = HttpRequest {
                method: if is_post { "POST" } else { "GET" }.to_string(),
                url: display(&args[0]),
                rule_id: env.rule_id.clone(),
                headers: match &args[1] {
                    Value::Map(m) => m.iter().map(|(k, v)| (k.clone(), display(v))).collect(),
                    // Go's mapToStringAny returns an EMPTY map for anything
                    // else rather than failing, and `{}` is written often.
                    _ => BTreeMap::new(),
                },
                body: if is_post { display(&args[2]) } else { String::new() },
            };
            let mut resp = env.http.send(&req).map_err(|e| match e {
                // The budget refusal keeps its identity all the way up, so the
                // evaluator can turn it into `needs_validation` rather than
                // `error`.
                HttpError::LimitHit(hit) => EvalError::ValidationLimit(Box::new(hit)),
                HttpError::Transport(m) => EvalError::Type(format!("{name}: {m}")),
            })?;
            if resp.body.len() > MAX_RESPONSE_BODY {
                resp.body.truncate(MAX_RESPONSE_BODY);
            }
            Some(build_response(&resp))
        }

        // ── validate ────────────────────────────────────────────────────────
        "validate.unknown" | "unknown" => {
            arity(1)?;
            Some(unknown_result(&args[0]))
        }

        // ── base64 / hex ────────────────────────────────────────────────────
        "base64.encode" => {
            arity(1)?;
            Some(Value::Str(
                base64::engine::general_purpose::STANDARD.encode(as_bytes(&args[0])),
            ))
        }
        "base64.decode" => {
            arity(1)?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(display(&args[0]))
                .map_err(|e| EvalError::Type(format!("base64.decode: {e}")))?;
            Some(Value::Bytes(decoded))
        }
        "hex.encode" => {
            arity(1)?;
            Some(Value::Str(hex_encode(&as_bytes(&args[0]))))
        }

        // ── json ────────────────────────────────────────────────────────────
        "json.string" => {
            arity(1)?;
            Some(Value::Str(go_json_string(&display(&args[0]))))
        }

        // ── crypto ──────────────────────────────────────────────────────────
        // Every one returns BYTES, because the catalogue pipes them straight
        // into hex.encode or base64.encode.
        "crypto.md5" => {
            arity(1)?;
            Some(Value::Bytes(
                md5::Md5::digest(as_bytes(&args[0])).to_vec(),
            ))
        }
        "crypto.sha1" => {
            arity(1)?;
            Some(Value::Bytes(Sha1::digest(as_bytes(&args[0])).to_vec()))
        }
        "crypto.hmacSha1" => {
            arity(2)?;
            let mut mac = Hmac::<Sha1>::new_from_slice(&as_bytes(&args[0]))
                .map_err(|e| EvalError::Type(format!("crypto.hmacSha1: {e}")))?;
            mac.update(&as_bytes(&args[1]));
            Some(Value::Bytes(mac.finalize().into_bytes().to_vec()))
        }
        "crypto.hmacSha256" | "crypto.hmac_sha256" => {
            arity(2)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(&as_bytes(&args[0]))
                .map_err(|e| EvalError::Type(format!("crypto.hmacSha256: {e}")))?;
            mac.update(&as_bytes(&args[1]));
            Some(Value::Bytes(mac.finalize().into_bytes().to_vec()))
        }

        // ── strings ─────────────────────────────────────────────────────────
        "strings.urlQueryEscape" | "strings.url_query_escape" => {
            arity(1)?;
            Some(Value::Str(url_query_escape(&display(&args[0]))))
        }
        // Reachable bare as well as under `strings.`, as Go binds both.
        "strings.obfuscate" | "obfuscate" => {
            arity(1)?;
            Some(Value::Str(crate::obfuscate::obfuscate(
                &display(&args[0]),
                &crate::obfuscate::SystemRandom,
            )))
        }

        // ── time ────────────────────────────────────────────────────────────
        // Go returns nowUnix as a STRING, which matters: the catalogue
        // concatenates it into signatures and URLs.
        "time.nowUnix" | "time.now_unix" => {
            arity(0)?;
            Some(Value::Str((need_env()?.now_unix)().to_string()))
        }
        "time.nowRFC3339" => {
            arity(0)?;
            Some(Value::Str(rfc3339_utc((need_env()?.now_unix)())))
        }

        // ── env ─────────────────────────────────────────────────────────────
        // The allowlist is the security control, not a convenience: a validate
        // expression is CONFIG, and config that can read arbitrary environment
        // variables is an exfiltration primitive.
        "env.get" | "env_get" => {
            arity(1)?;
            let env = need_env()?;
            let key = display(&args[0]);
            if env.allowed_env.is_empty() {
                return Err(EvalError::Type(
                    "env: no validation env allowlist configured (use --validation-env-vars)"
                        .to_string(),
                ));
            }
            if !env.allowed_env.contains(&key) {
                return Err(EvalError::Type(format!(
                    "env: {key:?} not in validation env allowlist"
                )));
            }
            Some(Value::Str(std::env::var(&key).unwrap_or_default()))
        }
        // getOrDefault never errors — a missing or disallowed name falls back,
        // which is why the catalogue uses it for optional base URLs.
        "env.getOrDefault" => {
            arity(2)?;
            let env = need_env()?;
            let key = display(&args[0]);
            let fallback = display(&args[1]);
            let value = if env.allowed_env.is_empty() || !env.allowed_env.contains(&key) {
                fallback
            } else {
                std::env::var(&key).unwrap_or(fallback)
            };
            Some(Value::Str(value))
        }

        _ => None,
    };
    Ok(out)
}

#[cfg(test)]
mod tests;
