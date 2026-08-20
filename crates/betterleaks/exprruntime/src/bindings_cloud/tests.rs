use super::*;
use crate::bindings_validation::HttpResponse;

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
    fn last(&self) -> HttpRequest {
        self.seen.lock().unwrap().last().cloned().expect("a request")
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

fn env<'a>(http: &'a dyn HttpClient, now: &'a dyn Fn() -> i64) -> ValidationEnv<'a> {
    ValidationEnv {
        http,
        allowed_env: Default::default(),
        now_unix: now,
        rule_id: "test-rule".to_string(),
    }
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(m) => m.get(key),
        _ => None,
    }
}

fn s(v: &Value, key: &str) -> String {
    match field(v, key) {
        Some(Value::Str(x)) => x.clone(),
        _ => String::new(),
    }
}

fn n(v: &Value, key: &str) -> f64 {
    match field(v, key) {
        Some(Value::Num(x)) => *x,
        _ => f64::NAN,
    }
}

// ── AWS ─────────────────────────────────────────────────────────────────────

const STS_OK: &str = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/Alice</Arn>
    <UserId>AIDAEXAMPLEUSERID</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"#;

const STS_DENIED: &str = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
</ErrorResponse>"#;

/// A live key comes back with the identity it belongs to — which is what makes
/// the finding actionable: the ACCOUNT is what a responder needs.
#[test]
fn aws_validate_returns_the_caller_identity() {
    let http = Stub::new(200, STS_OK);
    let now = || 1_700_000_000i64;
    let e = env(&http, &now);

    let out = call_cloud(
        "aws.validate",
        &[Value::str("AKIAEXAMPLE"), Value::str("secret")],
        Some(&e),
    )
    .unwrap()
    .unwrap();

    assert_eq!(n(&out, "status"), 200.0);
    assert_eq!(s(&out, "arn"), "arn:aws:iam::123456789012:user/Alice");
    assert_eq!(s(&out, "account"), "123456789012");
    assert_eq!(s(&out, "userid"), "AIDAEXAMPLEUSERID");
}

/// The request is a SIGNED POST to STS. Without Authorization and X-Amz-Date
/// the endpoint answers 403 for every key, live or dead, and every finding
/// would read as invalid.
#[test]
fn aws_validate_signs_the_request() {
    let http = Stub::new(200, STS_OK);
    let now = || 1_700_000_000i64;
    let e = env(&http, &now);
    call_cloud(
        "aws.validate",
        &[Value::str("AKIAEXAMPLE"), Value::str("secret")],
        Some(&e),
    )
    .unwrap();

    let req = http.last();
    assert_eq!(req.method, "POST");
    assert_eq!(req.url, "https://sts.amazonaws.com/");
    assert_eq!(req.body, "Action=GetCallerIdentity&Version=2011-06-15");
    let auth = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone())
        .expect("a SigV4 Authorization header");
    assert!(auth.starts_with("AWS4-HMAC-SHA256 "), "{auth}");
    assert!(auth.contains("Credential=AKIAEXAMPLE/"), "{auth}");
    assert!(auth.contains("/us-east-1/sts/aws4_request"), "{auth}");
    assert!(
        req.headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("x-amz-date")),
        "the signed date must be present: {:?}",
        req.headers.keys().collect::<Vec<_>>()
    );
}

/// The error CODE is what separates a dead key from a live-but-restricted one,
/// and those are very different findings.
#[test]
fn aws_validate_surfaces_the_sts_error_code() {
    let http = Stub::new(403, STS_DENIED);
    let now = || 0i64;
    let e = env(&http, &now);
    let out = call_cloud(
        "aws.validate",
        &[Value::str("AKIABAD"), Value::str("nope")],
        Some(&e),
    )
    .unwrap()
    .unwrap();

    assert_eq!(n(&out, "status"), 403.0);
    assert_eq!(s(&out, "error_code"), "InvalidClientTokenId");
    assert_eq!(
        s(&out, "error_message"),
        "The security token included in the request is invalid."
    );
}

/// A WAF or proxy in front of STS answers HTML. Go says so explicitly rather
/// than reporting an empty error code.
#[test]
fn aws_validate_names_a_non_xml_error() {
    let http = Stub::new(503, "<html><body>Service Unavailable</body></html>");
    let now = || 0i64;
    let e = env(&http, &now);
    let out = call_cloud(
        "aws.validate",
        &[Value::str("AKIA"), Value::str("s")],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s(&out, "error_message"), "Non-XML error response received");
    assert_eq!(s(&out, "error_code"), "");
}

/// A transport failure is `status: 0`, never an exception. `0` is how a rule
/// distinguishes "the provider said no" from "we never got to ask".
#[test]
fn a_transport_failure_is_status_zero() {
    struct Dead;
    impl HttpClient for Dead {
        fn send(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Transport("no route to host".into()))
        }
    }
    let dead = Dead;
    let now = || 0i64;
    let e = env(&dead, &now);
    for (name, args) in [
        ("aws.validate", vec![Value::str("a"), Value::str("b")]),
        (
            "azure.validateStorage",
            vec![Value::str("acct"), Value::str("a2V5")],
        ),
    ] {
        let out = call_cloud(name, &args, Some(&e)).unwrap().unwrap();
        assert_eq!(n(&out, "status"), 0.0, "{name}");
    }
}

/// The XML reader handles namespaced tags, attributes and entities — STS uses
/// all three.
#[test]
fn the_xml_reader_handles_what_these_apis_send() {
    assert_eq!(
        xml_text("<a:Code xmlns:a='x'>Denied</a:Code>", "Code").as_deref(),
        Some("Denied")
    );
    assert_eq!(
        xml_text("<Message>a &amp; b &lt;c&gt;</Message>", "Message").as_deref(),
        Some("a & b <c>")
    );
    assert_eq!(xml_text("<Other>x</Other>", "Code"), None);
    // A self-closing tag has no text and must not be reported as empty.
    assert_eq!(xml_text("<Code/><Other>y</Other>", "Code"), None);
    // The declaration is skipped rather than treated as an element.
    assert_eq!(
        xml_text("<?xml version='1.0'?><Code>Z</Code>", "Code").as_deref(),
        Some("Z")
    );
}

// ── Azure ───────────────────────────────────────────────────────────────────

/// A connection-string value routinely ends in `=` (it is base64), so only the
/// FIRST `=` separates. Splitting on every `=` truncates the key and every
/// signature computed from it is wrong.
#[test]
fn an_azure_connection_string_splits_on_the_first_equals_only() {
    let parsed = parse_azure_connection_string(
        "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc/def+ghi=",
    );
    assert_eq!(parsed["Endpoint"], "sb://ns.servicebus.windows.net/");
    assert_eq!(parsed["SharedAccessKeyName"], "RootManageSharedAccessKey");
    assert_eq!(
        parsed["SharedAccessKey"], "abc/def+ghi=",
        "the trailing padding must survive"
    );
}

/// The SAS token shape Azure expects. The signature is over
/// `urlencoded(uri)\nexpiry`, and every component is url-encoded again in the
/// token itself.
#[test]
fn an_sas_token_has_the_shape_azure_expects() {
    // "key" base64-encoded, so the HMAC key is the three bytes `key`.
    let token = azure_sas_token(
        "https://ns.servicebus.windows.net",
        "RootManageSharedAccessKey",
        "a2V5",
        1_700_003_600,
    )
    .expect("a token");

    assert!(token.starts_with("SharedAccessSignature sr="), "{token}");
    assert!(
        token.contains("sr=https%3A%2F%2Fns.servicebus.windows.net"),
        "the resource uri is encoded: {token}"
    );
    assert!(token.contains("&se=1700003600"), "{token}");
    assert!(
        token.contains("&skn=RootManageSharedAccessKey"),
        "{token}"
    );
    // The signature is deterministic for a fixed uri, key and expiry.
    let again = azure_sas_token(
        "https://ns.servicebus.windows.net",
        "RootManageSharedAccessKey",
        "a2V5",
        1_700_003_600,
    )
    .unwrap();
    assert_eq!(token, again);
}

/// A key that is not base64 cannot produce a signature, and saying `InvalidKey`
/// beats sending an unsigned request that comes back 403.
#[test]
fn a_non_base64_azure_key_is_named_rather_than_sent() {
    let http = Stub::new(200, "");
    let now = || 0i64;
    let e = env(&http, &now);
    let out = call_cloud(
        "azure.validateStorage",
        &[Value::str("acct"), Value::str("not base64 !!!")],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(n(&out, "status"), 0.0);
    assert_eq!(s(&out, "error_code"), "InvalidKey");
    assert!(
        http.seen.lock().unwrap().is_empty(),
        "nothing should have been sent"
    );
}

/// Missing inputs are refused before a request, with the reason.
#[test]
fn missing_azure_inputs_are_refused() {
    let http = Stub::new(200, "");
    let now = || 0i64;
    let e = env(&http, &now);
    for (name, args) in [
        (
            "azure.validateStorage",
            vec![Value::str(""), Value::str("a2V5")],
        ),
        (
            "azure.validateServicePrincipal",
            vec![Value::str("t"), Value::str(""), Value::str("s")],
        ),
        (
            "azure.validateAppConfig",
            vec![Value::str("https://x"), Value::str("id"), Value::str("")],
        ),
        (
            "azure.validateServiceBusSAS",
            vec![Value::str("Endpoint=sb://x/")],
        ),
    ] {
        let out = call_cloud(name, &args, Some(&e)).unwrap().unwrap();
        assert_eq!(n(&out, "status"), 0.0, "{name}");
        assert_eq!(s(&out, "error_code"), "MissingInput", "{name}");
    }
    assert!(http.seen.lock().unwrap().is_empty());
}

/// Azure storage signs with Shared Key, and the request must carry the date it
/// signed over — a mismatch is rejected regardless of the key.
#[test]
fn azure_storage_sends_a_shared_key_signature() {
    let http = Stub::new(200, "<EnumerationResults/>");
    let now = || 1_700_000_000i64;
    let e = env(&http, &now);
    call_cloud(
        "azure.validateStorage",
        &[Value::str("myacct"), Value::str("a2V5")],
        Some(&e),
    )
    .unwrap();

    let req = http.last();
    assert_eq!(req.url, "https://myacct.blob.core.windows.net/?comp=list");
    assert!(
        req.headers["Authorization"].starts_with("SharedKey myacct:"),
        "{}",
        req.headers["Authorization"]
    );
    // RFC 1123, which is what the signature was computed over.
    assert_eq!(req.headers["x-ms-date"], "Tue, 14 Nov 2023 22:13:20 GMT");
    assert_eq!(req.headers["x-ms-version"], "2021-08-06");
}

/// Azure's identity endpoint answers JSON errors; the app-config one nests
/// them. Both spellings are read, because a rule reading `error_code` should
/// not have to know which service answered.
#[test]
fn azure_json_errors_are_read_in_both_shapes() {
    let http = Stub::new(401, r#"{"error":"invalid_client","error_description":"AADSTS7000215"}"#);
    let now = || 0i64;
    let e = env(&http, &now);
    let out = call_cloud(
        "azure.validateServicePrincipal",
        &[Value::str("t"), Value::str("c"), Value::str("s")],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s(&out, "error_code"), "invalid_client");
    assert_eq!(s(&out, "error_message"), "AADSTS7000215");

    let http = Stub::new(401, r#"{"error":{"code":"Unauthorized","message":"bad signature"}}"#);
    let e = env(&http, &now);
    let out = call_cloud(
        "azure.validateAppConfig",
        &[
            Value::str("https://x.azconfig.io"),
            Value::str("id"),
            Value::str("a2V5"),
        ],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s(&out, "error_code"), "Unauthorized");
    assert_eq!(s(&out, "error_message"), "bad signature");
}

// ── GCP ─────────────────────────────────────────────────────────────────────

/// A 2048-bit test key, generated for this test only. It signs nothing real.
const TEST_RSA_PKCS8: &str = include_str!("../../testdata/test_rsa_pkcs8.pem");

#[test]
fn gcp_validate_refuses_a_credential_it_cannot_use() {
    let http = Stub::new(200, "{}");
    let now = || 0i64;
    let e = env(&http, &now);

    // Not JSON at all.
    let out = call_cloud("gcp.validate", &[Value::str("not json")], Some(&e))
        .unwrap()
        .unwrap();
    assert_eq!(s(&out, "error_code"), "InvalidCredentialJSON");

    // JSON, but missing the fields that matter.
    let out = call_cloud(
        "gcp.validate",
        &[Value::str(r#"{"type":"service_account"}"#)],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s(&out, "error_code"), "MissingGCPFields");

    // Present but unusable — a key that will not parse must be NAMED, not sent
    // as an unsigned assertion that comes back 400.
    let out = call_cloud(
        "gcp.validate",
        &[Value::str(
            r#"{"client_email":"a@b.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"}"#,
        )],
        Some(&e),
    )
    .unwrap()
    .unwrap();
    assert_eq!(s(&out, "error_code"), "InvalidPrivateKey");

    assert!(
        http.seen.lock().unwrap().is_empty(),
        "none of those should have produced a request"
    );
}

/// The real path: a parseable key produces a signed JWT assertion, posted as a
/// bearer grant.
#[test]
fn gcp_validate_signs_and_exchanges_a_jwt() {
    let http = Stub::new(200, r#"{"access_token":"ya29.x","expires_in":3599}"#);
    let now = || 1_700_000_000i64;
    let e = env(&http, &now);

    let credential = format!(
        r#"{{"client_email":"svc@proj.iam.gserviceaccount.com","private_key":{},"token_uri":"https://oauth2.googleapis.com/token"}}"#,
        go_json_string(TEST_RSA_PKCS8)
    );
    let out = call_cloud("gcp.validate", &[Value::Str(credential)], Some(&e))
        .unwrap()
        .unwrap();

    assert_eq!(n(&out, "status"), 200.0);
    assert_eq!(s(&out, "client_email"), "svc@proj.iam.gserviceaccount.com");

    let req = http.last();
    assert_eq!(req.method, "POST");
    assert_eq!(req.url, "https://oauth2.googleapis.com/token");
    assert!(
        req.body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"),
        "{}",
        req.body
    );
    assert!(req.body.contains("&assertion="), "{}", req.body);
}

/// The JWT itself: three base64url segments, an RS256 header, and claims that
/// bind the assertion to this service account, this audience and this hour.
#[test]
fn the_gcp_jwt_has_the_right_shape_and_claims() {
    let jwt = gcp_service_account_jwt(
        "svc@proj.iam.gserviceaccount.com",
        TEST_RSA_PKCS8,
        "https://oauth2.googleapis.com/token",
        1_700_000_000,
    )
    .expect("the test key must sign");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "header.payload.signature");

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = String::from_utf8(b64.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header, r#"{"alg":"RS256","typ":"JWT"}"#);

    let claims = String::from_utf8(b64.decode(parts[1]).unwrap()).unwrap();
    let Some(Value::Map(c)) = parse_json(&claims) else {
        panic!("claims must be JSON: {claims}")
    };
    assert_eq!(c["iss"], Value::str("svc@proj.iam.gserviceaccount.com"));
    assert_eq!(c["aud"], Value::str("https://oauth2.googleapis.com/token"));
    assert_eq!(c["iat"], Value::Num(1_700_000_000.0));
    // One hour, which is the maximum Google accepts.
    assert_eq!(c["exp"], Value::Num(1_700_003_600.0));

    // 2048-bit RSA signature, base64url without padding.
    assert_eq!(b64.decode(parts[2]).unwrap().len(), 256);
    assert!(!parts[2].contains('='), "base64url is unpadded");
    assert!(!parts[2].contains('+') && !parts[2].contains('/'), "url-safe alphabet");
}

/// A credential whose PEM still has escaped newlines — what a hand-edited or
/// double-encoded credential looks like — must still parse. Refusing it would
/// report a live key as unvalidatable.
#[test]
fn an_escaped_newline_pem_still_parses() {
    let escaped = TEST_RSA_PKCS8.replace('\n', "\\n");
    assert!(
        gcp_service_account_jwt("a@b", &escaped, "https://x", 0).is_some(),
        "the escaped form must be recovered"
    );
}

/// A validation-only binding reached without an environment says so.
#[test]
fn the_cloud_bindings_need_a_validation_environment() {
    let err = call_cloud("aws.validate", &[Value::str("a"), Value::str("b")], None).unwrap_err();
    assert!(
        format!("{err}").contains("only available in a validate expression"),
        "{err}"
    );
}

/// An unrelated name is declined rather than claimed.
#[test]
fn an_unrelated_name_is_declined() {
    assert_eq!(call_cloud("http.get", &[], None), Ok(None));
}
