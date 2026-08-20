use super::*;

/// A stub provider. Records what was asked and answers from a script, so the
/// whole validation path is exercised without a network.
struct StubHttp {
    response: HttpResponse,
    seen: std::sync::Mutex<Vec<HttpRequest>>,
}

impl StubHttp {
    fn new(status: i64, body: &str) -> StubHttp {
        StubHttp {
            response: HttpResponse {
                status,
                headers: BTreeMap::new(),
                body: body.as_bytes().to_vec(),
            },
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn last(&self) -> HttpRequest {
        self.seen.lock().unwrap().last().cloned().expect("a request")
    }
}

impl HttpClient for StubHttp {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        self.seen.lock().unwrap().push(req.clone());
        Ok(self.response.clone())
    }
}

fn env_with<'a>(http: &'a dyn HttpClient, now: &'a dyn Fn() -> i64) -> ValidationEnv<'a> {
    ValidationEnv {
        http,
        allowed_env: Default::default(),
        now_unix: now,
        rule_id: "test-rule".to_string(),
    }
}

/// `r` is `{status, json, headers, body}`, with header names LOWER-CASED —
/// an expression reading `r.headers["x-ratelimit-remaining"]` depends on it.
#[test]
fn a_response_becomes_the_expected_shape() {
    let mut headers = BTreeMap::new();
    headers.insert("X-RateLimit-Remaining".to_string(), "42".to_string());
    let resp = HttpResponse {
        status: 200,
        headers,
        body: br#"{"features":["a"],"n":3}"#.to_vec(),
    };
    let Value::Map(m) = build_response(&resp) else {
        panic!("a map")
    };
    assert_eq!(m["status"], Value::Num(200.0));
    assert_eq!(m["body"], Value::str(r#"{"features":["a"],"n":3}"#));
    let Value::Map(h) = &m["headers"] else {
        panic!("headers is a map")
    };
    assert_eq!(h["x-ratelimit-remaining"], Value::str("42"));
    let Value::Map(j) = &m["json"] else {
        panic!("json is a map")
    };
    assert_eq!(j["n"], Value::Num(3.0));
}

/// A non-JSON body must give an EMPTY object, not an error. This is the
/// ordinary case: an invalid credential usually gets an HTML error page, and
/// every expression reading `r.json?.error` has to survive it.
#[test]
fn a_non_json_body_degrades_to_an_empty_object() {
    let resp = HttpResponse {
        status: 401,
        headers: BTreeMap::new(),
        body: b"<html>Unauthorized</html>".to_vec(),
    };
    let Value::Map(m) = build_response(&resp) else {
        panic!("a map")
    };
    assert_eq!(m["json"], Value::Map(BTreeMap::new()));
    assert_eq!(m["body"], Value::str("<html>Unauthorized</html>"));
}

/// `validate.unknown(r)` turns "I could not tell" into a REASON. Without it a
/// report lists the finding as unvalidated with no explanation.
#[test]
fn unknown_result_names_the_reason() {
    let resp = |status: f64| {
        let mut m = BTreeMap::new();
        m.insert("status".to_string(), Value::Num(status));
        Value::Map(m)
    };

    let Value::Map(m) = unknown_result(&resp(429.0)) else {
        panic!()
    };
    assert_eq!(m["result"], Value::str("unknown"));
    assert_eq!(m["reason"], Value::str("rate limited"), "429 is special-cased");

    let Value::Map(m) = unknown_result(&resp(503.0)) else {
        panic!()
    };
    assert_eq!(m["reason"], Value::str("HTTP 503"));

    // No status at all — no reason key, rather than "HTTP ".
    let Value::Map(m) = unknown_result(&Value::Map(BTreeMap::new())) else {
        panic!()
    };
    assert!(!m.contains_key("reason"));
}

#[test]
fn json_parsing_covers_what_a_provider_returns() {
    assert_eq!(parse_json("null"), Some(Value::Nil));
    assert_eq!(parse_json("true"), Some(Value::Bool(true)));
    assert_eq!(parse_json("-1.5e2"), Some(Value::Num(-150.0)));
    assert_eq!(parse_json(r#""a\"b\né""#), Some(Value::str("a\"b\né")));
    assert_eq!(
        parse_json("[1, 2]"),
        Some(Value::List(vec![Value::Num(1.0), Value::Num(2.0)]))
    );
    assert_eq!(parse_json("  {  }  "), Some(Value::Map(BTreeMap::new())));
    // Nested, with whitespace everywhere it is legal.
    let v = parse_json("{\n  \"a\": { \"b\": [true, null] }\n}").unwrap();
    let Value::Map(m) = v else { panic!() };
    let Value::Map(inner) = &m["a"] else { panic!() };
    assert_eq!(
        inner["b"],
        Value::List(vec![Value::Bool(true), Value::Nil])
    );

    // Trailing content is a REJECTION, not a partial parse — otherwise an HTML
    // page starting with `{` would look like a JSON object.
    assert_eq!(parse_json("{} trailing"), None);
    assert_eq!(parse_json("{\"a\":1,}"), None, "no trailing comma");
    assert_eq!(parse_json(""), None);
    assert_eq!(parse_json("<html>"), None);
}

/// Go's encoder HTML-escapes by default. A secret containing `<` would
/// otherwise produce a request body Go and this port disagree on.
#[test]
fn json_string_escapes_the_way_go_does() {
    assert_eq!(go_json_string("plain"), "\"plain\"");
    assert_eq!(go_json_string("a\"b"), "\"a\\\"b\"");
    assert_eq!(go_json_string("a<b>c&d"), "\"a\\u003cb\\u003ec\\u0026d\"");
    assert_eq!(go_json_string("a\nb"), "\"a\\nb\"");
    assert_eq!(go_json_string("é"), "\"é\"", "non-ASCII is not escaped");
}

/// `url.QueryEscape`, which is NOT generic percent-encoding: a space becomes
/// `+`. Getting this wrong yields a 400 that reads as "invalid secret".
#[test]
fn url_query_escape_matches_go() {
    assert_eq!(url_query_escape("abc-_.~"), "abc-_.~");
    assert_eq!(url_query_escape("a b"), "a+b");
    assert_eq!(url_query_escape("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
    assert_eq!(url_query_escape("é"), "%C3%A9");
    assert_eq!(url_query_escape("+"), "%2B");
}

#[test]
fn rfc3339_matches_go_for_utc() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    // 2003-10-19T04:05:06Z
    assert_eq!(
        rfc3339_utc(12_344 * 86_400 + 4 * 3600 + 5 * 60 + 6),
        "2003-10-19T04:05:06Z"
    );
}

fn call(name: &str, args: &[Value], env: Option<&ValidationEnv>) -> Value {
    call_validation(name, args, env)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .unwrap_or_else(|| panic!("{name} is not a validation function"))
}

/// The crypto bindings return BYTES, because the catalogue pipes them straight
/// into hex.encode or base64.encode. Vectors are the published ones.
#[test]
fn crypto_matches_the_published_vectors() {
    let b = |s: &str| Value::str(s);

    assert_eq!(
        call("hex.encode", &[call("crypto.sha1", &[b("abc")], None)], None),
        Value::str("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(
        call("hex.encode", &[call("crypto.md5", &[b("abc")], None)], None),
        Value::str("900150983cd24fb0d6963f7d28e17f72")
    );
    // RFC 2202 HMAC-SHA1 test case 1.
    assert_eq!(
        call(
            "hex.encode",
            &[call(
                "crypto.hmacSha1",
                &[Value::Bytes(vec![0x0b; 20]), b("Hi There")],
                None
            )],
            None
        ),
        Value::str("b617318655057264e28bc0b6fb378c8ef146be00")
    );
    // RFC 4231 HMAC-SHA256 test case 1.
    assert_eq!(
        call(
            "hex.encode",
            &[call(
                "crypto.hmacSha256",
                &[Value::Bytes(vec![0x0b; 20]), b("Hi There")],
                None
            )],
            None
        ),
        Value::str("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

/// An HMAC is BINARY. Round-tripping it through a `String` would corrupt it,
/// which is why `Value::Bytes` exists.
#[test]
fn a_binary_digest_survives_base64() {
    let digest = call(
        "crypto.hmacSha256",
        &[Value::str("key"), Value::str("message")],
        None,
    );
    let Value::Bytes(raw) = &digest else {
        panic!("crypto returns bytes")
    };
    assert_eq!(raw.len(), 32);
    assert_eq!(
        call("base64.encode", &[digest.clone()], None),
        Value::str("bp7ym3X//Ft6uuUn1Y/a2y/kLnIZARl2kXNDBl9Y7Uo=")
    );
    // And a round trip through base64 gives the same bytes back.
    let decoded = call(
        "base64.decode",
        &[call("base64.encode", &[digest.clone()], None)],
        None,
    );
    assert_eq!(decoded, digest);
}

/// http.get builds the request the expression described, and `r` comes back in
/// the expected shape.
#[test]
fn http_get_sends_the_request_and_returns_a_response() {
    let http = StubHttp::new(200, r#"{"ok":true}"#);
    let now = || 1_700_000_000i64;
    let env = env_with(&http, &now);

    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_string(), Value::str("Bearer abc"));
    headers.insert("Accept".to_string(), Value::str("application/json"));

    let r = call(
        "http.get",
        &[Value::str("https://api.example.com/v1"), Value::Map(headers)],
        Some(&env),
    );

    let sent = http.last();
    assert_eq!(sent.method, "GET");
    assert_eq!(sent.url, "https://api.example.com/v1");
    assert_eq!(sent.headers["Authorization"], "Bearer abc");
    assert_eq!(sent.body, "");

    let Value::Map(m) = r else { panic!() };
    assert_eq!(m["status"], Value::Num(200.0));
}

#[test]
fn http_post_carries_a_body() {
    let http = StubHttp::new(201, "{}");
    let now = || 0i64;
    let env = env_with(&http, &now);
    call(
        "http.post",
        &[
            Value::str("https://api.example.com/e"),
            Value::Map(BTreeMap::new()),
            Value::str(r#"{"a":1}"#),
        ],
        Some(&env),
    );
    let sent = http.last();
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.body, r#"{"a":1}"#);
}

/// A transport failure is an ERROR the expression cannot swallow; an HTTP error
/// STATUS is a perfectly good answer. Conflating them would turn a network
/// outage into "every secret is invalid".
#[test]
fn a_transport_failure_is_an_error_but_a_401_is_not() {
    struct Broken;
    impl HttpClient for Broken {
        fn send(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Transport("dial tcp: no such host".to_string()))
        }
    }
    let broken = Broken;
    let now = || 0i64;
    let env = env_with(&broken, &now);
    let err = call_validation(
        "http.get",
        &[Value::str("https://nope.invalid"), Value::Map(BTreeMap::new())],
        Some(&env),
    )
    .unwrap_err();
    assert!(format!("{err}").contains("no such host"), "{err}");

    let http = StubHttp::new(401, "nope");
    let env = env_with(&http, &now);
    let r = call(
        "http.get",
        &[Value::str("https://api.example.com"), Value::Map(BTreeMap::new())],
        Some(&env),
    );
    let Value::Map(m) = r else { panic!() };
    assert_eq!(m["status"], Value::Num(401.0), "a 401 is an ANSWER");
}

/// A provider that streams megabytes at an unauthenticated request must not let
/// one finding consume the scan.
#[test]
fn an_oversized_response_body_is_truncated() {
    let http = StubHttp::new(200, &"x".repeat(MAX_RESPONSE_BODY + 5_000));
    let now = || 0i64;
    let env = env_with(&http, &now);
    let r = call(
        "http.get",
        &[Value::str("https://api.example.com"), Value::Map(BTreeMap::new())],
        Some(&env),
    );
    let Value::Map(m) = r else { panic!() };
    let Value::Str(body) = &m["body"] else { panic!() };
    assert_eq!(body.len(), MAX_RESPONSE_BODY);
}

/// The allowlist is the security control. A validate expression is CONFIG, and
/// config that can read arbitrary environment variables is an exfiltration
/// primitive — so no allowlist means `env.get` FAILS rather than returning "".
#[test]
fn env_get_refuses_without_an_allowlist() {
    let http = StubHttp::new(200, "{}");
    let now = || 0i64;
    let env = env_with(&http, &now);

    let err = call_validation("env.get", &[Value::str("HOME")], Some(&env)).unwrap_err();
    assert!(format!("{err}").contains("no validation env allowlist"), "{err}");

    let mut allowed = env_with(&http, &now);
    allowed.allowed_env.insert("BL_TEST_ALLOWED".to_string());
    let err = call_validation("env.get", &[Value::str("HOME")], Some(&allowed)).unwrap_err();
    assert!(
        format!("{err}").contains("not in validation env allowlist"),
        "an allowlist that does not name it is still a refusal: {err}"
    );

    std::env::set_var("BL_TEST_ALLOWED", "value-here");
    assert_eq!(
        call("env.get", &[Value::str("BL_TEST_ALLOWED")], Some(&allowed)),
        Value::str("value-here")
    );
    std::env::remove_var("BL_TEST_ALLOWED");
}

/// `getOrDefault` never errors — which is why the catalogue uses it for
/// optional base URLs. A disallowed name silently falls back.
#[test]
fn env_get_or_default_falls_back_instead_of_failing() {
    let http = StubHttp::new(200, "{}");
    let now = || 0i64;
    let env = env_with(&http, &now);
    assert_eq!(
        call(
            "env.getOrDefault",
            &[Value::str("NOT_ALLOWED"), Value::str("https://api.github.com")],
            Some(&env)
        ),
        Value::str("https://api.github.com")
    );
}

/// A validation-only function reached from a FILTER expression has no
/// environment, and says so.
#[test]
fn a_validation_function_outside_validation_says_so() {
    let err = call_validation(
        "http.get",
        &[Value::str("https://x"), Value::Map(BTreeMap::new())],
        None,
    )
    .unwrap_err();
    assert!(
        format!("{err}").contains("only available in a validate expression"),
        "{err}"
    );
}

/// `time.nowUnix` returns a STRING — the catalogue concatenates it into
/// signatures and URLs, where a float would produce `1700000000` vs `1.7e9`.
#[test]
fn time_bindings_return_what_the_catalogue_concatenates() {
    let http = StubHttp::new(200, "{}");
    let now = || 1_700_000_000i64;
    let env = env_with(&http, &now);
    assert_eq!(
        call("time.nowUnix", &[], Some(&env)),
        Value::str("1700000000")
    );
    assert_eq!(
        call("time.nowRFC3339", &[], Some(&env)),
        Value::str("2023-11-14T22:13:20Z")
    );
}

/// An unrecognised name is not ours — the caller falls through to the filter
/// builtins and ultimately to its own unknown-function error.
#[test]
fn an_unrelated_name_is_declined_rather_than_claimed() {
    assert_eq!(call_validation("entropy", &[Value::str("x")], None), Ok(None));
}
