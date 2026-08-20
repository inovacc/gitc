//! Real shipped validation expressions, evaluated end to end against a stubbed
//! provider.
//!
//! The corpus test proves all 186 PARSE. This proves they RUN: grammar,
//! bindings and evaluator together, producing the result map a report would
//! actually carry. Parsing without evaluating would be the same class of
//! half-verification this port keeps finding in the original — something that
//! looks complete and does nothing.

use exprruntime::bindings_validation::{HttpClient, HttpError, HttpRequest, HttpResponse, ValidationEnv};
use exprruntime::{Context, Value};
use std::collections::BTreeMap;

struct Stub {
    status: i64,
    body: String,
    seen: std::sync::Mutex<Vec<HttpRequest>>,
}

impl Stub {
    fn new(status: i64, body: &str) -> Stub {
        Stub {
            status,
            body: body.to_string(),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl HttpClient for Stub {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        self.seen.lock().unwrap().push(req.clone());
        Ok(HttpResponse {
            status: self.status,
            headers: BTreeMap::new(),
            body: self.body.as_bytes().to_vec(),
        })
    }
}

/// Evaluate `src` with `secret` against a stub answering `status`/`body`.
fn run(src: &str, secret: &str, status: i64, body: &str) -> (Value, Vec<HttpRequest>) {
    let program = exprruntime::compile(src)
        .expect("the expression must compile")
        .expect("and not be empty");
    let stub = Stub::new(status, body);
    let now = || 1_700_000_000i64;
    let env = ValidationEnv {
        http: &stub,
        allowed_env: Default::default(),
        now_unix: &now,
        rule_id: "test-rule".to_string(),
    };
    let mut ctx = Context::with_secret(secret);
    ctx.validation = Some(&env);
    let out = exprruntime::eval_validation(&program, &mut ctx).expect("evaluation");
    let seen = stub.seen.lock().unwrap().clone();
    (out, seen)
}

fn result_of(v: &Value) -> &str {
    match v {
        Value::Map(m) => match m.get("result") {
            Some(Value::Str(s)) => s,
            other => panic!("result is not a string: {other:?}"),
        },
        other => panic!("not a result map: {other:?}"),
    }
}

fn reason_of(v: &Value) -> String {
    match v {
        Value::Map(m) => match m.get("reason") {
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// The 1Password rule, verbatim from the shipped catalogue. It exercises a
/// `let`, string concatenation into a header, `&&`, the `contains` OPERATOR, a
/// chained ternary, `in` over a status set, map literals and
/// `validate.unknown`.
const ONEPASSWORD: &str = r#"
let r = http.get("https://events.1password.com/api/v2/auth/introspect", {
    "Accept": "application/json",
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"features\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
"#;

#[test]
fn a_live_credential_validates() {
    let (out, seen) = run(ONEPASSWORD, "ops_abc123", 200, r#"{"features":["events"]}"#);
    assert_eq!(result_of(&out), "valid");

    // The secret reached the provider in the header the expression built.
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["Authorization"], "Bearer ops_abc123");
    assert_eq!(seen[0].method, "GET");
}

#[test]
fn a_rejected_credential_is_invalid_with_a_reason() {
    let (out, _) = run(ONEPASSWORD, "ops_bad", 401, "unauthorized");
    assert_eq!(result_of(&out), "invalid");
    assert_eq!(reason_of(&out), "Unauthorized");
}

/// A 200 whose body does NOT carry the marker falls through to `unknown` —
/// which is the branch that stops a wrong "valid" from being reported.
#[test]
fn a_200_without_the_marker_is_unknown_not_valid() {
    let (out, _) = run(ONEPASSWORD, "ops_x", 200, r#"{"something":"else"}"#);
    assert_eq!(result_of(&out), "unknown");
    assert_eq!(reason_of(&out), "HTTP 200");
}

/// A rate limit must be distinguishable from a rejection. Reporting 429 as
/// "invalid" would tell a user their live credential is dead.
#[test]
fn a_rate_limit_is_unknown_and_says_so() {
    let (out, _) = run(ONEPASSWORD, "ops_x", 429, "slow down");
    assert_eq!(result_of(&out), "unknown");
    assert_eq!(reason_of(&out), "rate limited");
}

/// The Amplitude rule — `http.post` with a JSON body assembled by string
/// concatenation and `json.string`, plus `?.` / `??` on the response.
const AMPLITUDE: &str = r#"
let r = http.post("https://api2.amplitude.com/2/httpapi", {
    "Content-Type": "application/json",
    "Accept": "*/*"
  },
  "{" +
    "\"api_key\":" + json.string(finding["secret"]) + "," +
    "\"events\":[{" +
      "\"user_id\":\"203201202\"," +
      "\"device_id\":\"C8F9E604-F01A-4BD9-95C6-8E5357DF265D\"," +
      "\"event_type\":\"watch_tutorial\"" +
    "}]" +
  "}"); r.status == 200 && (r.body contains "\"code\":200") ? {
    "result": "valid"
  } : r.status in [400, 401, 403] ? {
    "result": "invalid",
    "reason": (r.json?.error ?? "Unauthorized")
  } : validate.unknown(r)
"#;

#[test]
fn a_post_body_is_assembled_and_sent() {
    let (out, seen) = run(AMPLITUDE, "amp_key_1", 200, r#"{"code":200}"#);
    assert_eq!(result_of(&out), "valid");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].headers["Content-Type"], "application/json");
    assert!(
        seen[0].body.contains(r#""api_key":"amp_key_1""#),
        "the secret is JSON-encoded into the body: {}",
        seen[0].body
    );
    // And the body is real JSON, which is the point of json.string.
    assert!(
        exprruntime::bindings_validation::parse_json(&seen[0].body).is_some(),
        "the assembled body must parse: {}",
        seen[0].body
    );
}

/// `r.json?.error ?? "Unauthorized"` reads the provider's own message when
/// there is one.
#[test]
fn the_providers_own_error_message_is_used_when_present() {
    let (out, _) = run(AMPLITUDE, "amp_bad", 400, r#"{"error":"invalid api key"}"#);
    assert_eq!(result_of(&out), "invalid");
    assert_eq!(reason_of(&out), "invalid api key");
}

/// And falls back when the body is not JSON at all — the ordinary case for a
/// rejected credential.
#[test]
fn the_fallback_reason_survives_a_non_json_error_page() {
    let (out, _) = run(AMPLITUDE, "amp_bad", 403, "<html>Forbidden</html>");
    assert_eq!(result_of(&out), "invalid");
    assert_eq!(reason_of(&out), "Unauthorized");
}

/// A secret containing JSON metacharacters must not be able to break out of the
/// body it is embedded in. This is `json.string` doing its job, and it is the
/// difference between a validation request and an injection.
#[test]
fn a_secret_with_metacharacters_cannot_break_the_body() {
    let nasty = r#"a","events":[],"x":"b"#;
    let (_, seen) = run(AMPLITUDE, nasty, 200, r#"{"code":200}"#);
    let body = &seen[0].body;
    let parsed = exprruntime::bindings_validation::parse_json(body)
        .unwrap_or_else(|| panic!("the body must still be valid JSON: {body}"));
    let Value::Map(m) = parsed else { panic!() };
    assert_eq!(
        m["api_key"],
        Value::Str(nasty.to_string()),
        "the secret stays one string rather than becoming structure"
    );
    // The events array is the one the expression wrote, not the injected empty
    // one.
    let Value::List(events) = &m["events"] else {
        panic!("events is a list")
    };
    assert_eq!(events.len(), 1, "injection did not replace the events");
}

/// The Algolia rule — the ONLY shipped expression using a predicate closure,
/// `any(acl, {# not in public_acls})`, plus `?.` on an indexed component and
/// `??` on a missing list.
const ALGOLIA: &str = r#"
let r = http.get("https://" + (components["algolia-application-id"]?.secret ?? "") + ".algolia.net/1/keys/" + finding["secret"], {
    "Accept": "application/json",
    "X-Algolia-API-Key": finding["secret"],
    "X-Algolia-Application-Id": (components["algolia-application-id"]?.secret ?? "")
  }); let acl = r.json?.acl ?? [];
  let public_acls = ["search", "browse", "listIndexes", "settings"];
  let has_sensitive_acl = any(acl, {# not in public_acls});
  r.status == 200 && has_sensitive_acl ? {
    "result": "valid",
    "acl": acl
  } : r.status == 200 && "search" in acl ? {
    "result": "invalid",
    "reason": "Public Algolia Search API key",
    "acl": acl
  } : validate.unknown(r)
"#;

#[test]
fn the_predicate_closure_rule_runs() {
    // A write-capable ACL contains something outside the public set.
    let (out, _) = run(ALGOLIA, "algolia_key", 200, r#"{"acl":["search","addObject"]}"#);
    assert_eq!(result_of(&out), "valid", "addObject is not a public ACL");

    // A search-only key is a PUBLIC key, which the rule reports as invalid
    // rather than as a leak.
    let (out, _) = run(ALGOLIA, "algolia_key", 200, r#"{"acl":["search"]}"#);
    assert_eq!(result_of(&out), "invalid");
    assert_eq!(reason_of(&out), "Public Algolia Search API key");

    // No acl at all — `?? []` yields an empty list, `any` is false, and
    // `"search" in []` is false, so it falls through to unknown.
    let (out, _) = run(ALGOLIA, "algolia_key", 200, "{}");
    assert_eq!(result_of(&out), "unknown");
}

/// A missing component resolves to `""` through `?.` + `??` rather than
/// erroring — the rule still runs, it just builds a useless URL.
#[test]
fn a_missing_component_degrades_instead_of_failing() {
    let (_, seen) = run(ALGOLIA, "k", 200, "{}");
    assert_eq!(seen[0].url, "https://.algolia.net/1/keys/k");
}
