//! Port of Go `bindings_aws.go`, `bindings_azure.go` and `bindings_gcp.go` —
//! the validation bindings that build a SIGNED request rather than pasting a
//! bearer token into a header.
//!
//! Seven of the 186 shipped expressions use these, and they are the seven where
//! "just send the secret" does not work: a cloud credential is a signing key,
//! not a password, so proving it is live means producing a correct signature.
//!
//! | Binding | What it signs with |
//! |---|---|
//! | `aws.validate(id, secret)` | SigV4 over an STS `GetCallerIdentity` POST |
//! | `azure.validateStorage(account, key)` | Shared Key, HMAC-SHA256 over a canonicalised request |
//! | `azure.validateServiceBusSAS(conn)` | an SAS token, HMAC-SHA256 over `uri\nexpiry` |
//! | `azure.validateAppConfig(endpoint, id, secret)` | HMAC-SHA256 over a content digest |
//! | `azure.validateServicePrincipal(tenant, id, secret)` | no signature — an OAuth client-credentials POST |
//! | `gcp.validate(credential_json)` | an RS256 JWT assertion, exchanged for a token |
//!
//! ## Each returns a MAP, never an error
//!
//! Every one answers with `{status, …}` and uses `status: 0` for "the request
//! could not be made at all" — a malformed credential, an unparseable key, a
//! network failure. That is Go's shape and it is load-bearing: the expression
//! that called it decides what a status means, and an exception here would rob
//! it of that decision. `status: 0` is how a rule distinguishes "the provider
//! said no" from "we never got to ask".

use crate::bindings_validation::{
    display, go_json_string, parse_json, url_query_escape, HttpClient, HttpError, HttpRequest,
    ValidationEnv,
};
use crate::eval::{EvalError, Value};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Go `defaultSTSEndpoint`.
const DEFAULT_STS_ENDPOINT: &str = "https://sts.amazonaws.com/";
/// Go `stsRequestBody`.
const STS_REQUEST_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// The names this module owns.
pub fn is_cloud_name(name: &str) -> bool {
    matches!(
        name,
        "aws.validate"
            | "gcp.validate"
            | "azure.validateStorage"
            | "azure.validateServicePrincipal"
            | "azure.validateAppConfig"
            | "azure.validateServiceBusSAS"
    )
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The "could not even ask" answer.
fn status_zero() -> Value {
    map(vec![("status", Value::Num(0.0))])
}

pub fn call_cloud(
    name: &str,
    args: &[Value],
    env: Option<&ValidationEnv>,
) -> Result<Option<Value>, EvalError> {
    if !is_cloud_name(name) {
        return Ok(None);
    }
    let env = env.ok_or_else(|| {
        EvalError::Type(format!("{name} is only available in a validate expression"))
    })?;
    let want = |n: usize| -> Result<(), EvalError> {
        if args.len() != n {
            return Err(EvalError::Arity {
                name: name.to_string(),
                want: n,
                got: args.len(),
            });
        }
        Ok(())
    };

    let out = match name {
        "aws.validate" => {
            want(2)?;
            aws_validate(env, &display(&args[0]), &display(&args[1]))?
        }
        "gcp.validate" => {
            want(1)?;
            gcp_validate(env, &display(&args[0]))?
        }
        "azure.validateStorage" => {
            want(2)?;
            azure_validate_storage(env, &display(&args[0]), &display(&args[1]))?
        }
        "azure.validateServicePrincipal" => {
            want(3)?;
            azure_validate_service_principal(
                env,
                &display(&args[0]),
                &display(&args[1]),
                &display(&args[2]),
            )?
        }
        "azure.validateAppConfig" => {
            want(3)?;
            azure_validate_app_config(
                env,
                &display(&args[0]),
                &display(&args[1]),
                &display(&args[2]),
            )?
        }
        "azure.validateServiceBusSAS" => {
            want(1)?;
            azure_validate_service_bus_sas(env, &display(&args[0]))?
        }
        _ => unreachable!("guarded by is_cloud_name"),
    };
    Ok(Some(out))
}

/// Send, propagating only a BUDGET refusal as an error. Every other failure
/// becomes `status: 0`, because the expression decides what a failure means.
fn send(env: &ValidationEnv, req: &HttpRequest) -> Result<Option<(i64, Vec<u8>)>, EvalError> {
    match env.http.send(req) {
        Ok(r) => Ok(Some((r.status, r.body))),
        Err(HttpError::LimitHit(hit)) => Err(EvalError::ValidationLimit(Box::new(hit))),
        Err(HttpError::Transport(_)) => Ok(None),
    }
}

// ── AWS ─────────────────────────────────────────────────────────────────────

/// Go `awsValidate` — a SigV4-signed `GetCallerIdentity`.
///
/// Returns the caller's ARN, account and user id on success, and the STS error
/// code on rejection. The `error_code` is what lets a rule tell an INVALID key
/// (`InvalidClientTokenId`) from a valid-but-restricted one (`AccessDenied`),
/// which are very different findings.
fn aws_validate(
    env: &ValidationEnv,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<Value, EvalError> {
    let mut req = httpclient_request(
        "POST",
        DEFAULT_STS_ENDPOINT,
        STS_REQUEST_BODY.as_bytes().to_vec(),
    );
    req.headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    let mut signable = sigv4::Request::new("POST", DEFAULT_STS_ENDPOINT);
    for (k, v) in &req.headers {
        signable.set_header(k, v);
    }
    if sigv4::sign(
        &mut signable,
        Some(STS_REQUEST_BODY.as_bytes()),
        "us-east-1",
        "sts",
        sigv4::Credentials::new(access_key_id, secret_access_key),
    )
    .is_err()
    {
        return Ok(status_zero());
    }
    // The signer adds Authorization, X-Amz-Date and the payload hash; carry
    // every header it produced, not just the ones we set.
    for (k, v) in signable.headers() {
        req.headers.insert(k, v);
    }

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let text = String::from_utf8_lossy(&body);

    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    if status == 200 {
        // Absent fields stay absent rather than becoming "", so an expression
        // reading `?.arn` can tell "no ARN" from "empty ARN".
        for (key, tag) in [("arn", "Arn"), ("account", "Account"), ("userid", "UserId")] {
            if let Some(v) = xml_text(&text, tag) {
                out.insert(key.to_string(), Value::Str(v));
            }
        }
    } else {
        match (xml_text(&text, "Code"), xml_text(&text, "Message")) {
            (Some(code), message) => {
                out.insert("error_code".to_string(), Value::Str(code));
                out.insert(
                    "error_message".to_string(),
                    Value::Str(message.unwrap_or_default()),
                );
            }
            // Go's fallback: a WAF or proxy in front of STS answers with HTML,
            // and saying so beats reporting an empty error code.
            _ => {
                out.insert("error_code".to_string(), Value::str(""));
                out.insert(
                    "error_message".to_string(),
                    Value::str("Non-XML error response received"),
                );
            }
        }
    }
    Ok(Value::Map(out))
}

/// The text of the first `<tag>…</tag>`.
///
/// A deliberately small reader rather than a full XML parser: these responses
/// have a fixed shape defined by AWS, only six elements are ever read, and the
/// alternative is an XML dependency in the expression crate for six lookups.
/// It handles the namespaced form (`<sts:Arn>`) because STS uses one.
fn xml_text(doc: &str, tag: &str) -> Option<String> {
    let mut from = 0usize;
    while let Some(open) = doc[from..].find('<') {
        let start = from + open + 1;
        let end = doc[start..].find('>')? + start;
        let inner = &doc[start..end];
        if inner.starts_with('/') || inner.starts_with('?') || inner.starts_with('!') {
            from = end + 1;
            continue;
        }
        // A self-closing element has NO text, and must not be reported as
        // empty — the check is against the raw inner, because trimming the
        // slash off first would make it unrecognisable.
        let self_closing = inner.trim_end().ends_with('/');
        // Strip attributes and any namespace prefix.
        let name = inner.split_whitespace().next().unwrap_or("");
        let name = name.trim_end_matches('/');
        let local = name.rsplit(':').next().unwrap_or(name);
        if local == tag && !self_closing {
            let close = doc[end + 1..].find("</")? + end + 1;
            return Some(unescape_xml(&doc[end + 1..close]));
        }
        from = end + 1;
    }
    None
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` LAST, or `&amp;lt;` would become `<`.
        .replace("&amp;", "&")
}

// ── Azure ───────────────────────────────────────────────────────────────────

fn hmac_sha256_base64(base64_key: &str, message: &str) -> Option<String> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(base64_key)
        .ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).ok()?;
    mac.update(message.as_bytes());
    Some(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// Go `parseAzureConnectionString` — `Key=Value;Key=Value`.
///
/// A value may itself contain `=` (a base64 key routinely ends in one), so only
/// the FIRST `=` separates.
pub fn parse_azure_connection_string(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Go `azureSASToken` — `SharedAccessSignature sr=…&sig=…&se=…&skn=…`.
pub fn azure_sas_token(
    resource_uri: &str,
    key_name: &str,
    base64_key: &str,
    expiry: i64,
) -> Option<String> {
    let encoded = url_query_escape(resource_uri);
    let signature = hmac_sha256_base64(base64_key, &format!("{encoded}\n{expiry}"))?;
    Some(format!(
        "SharedAccessSignature sr={}&sig={}&se={}&skn={}",
        encoded,
        url_query_escape(&signature),
        expiry,
        url_query_escape(key_name)
    ))
}

fn azure_input_error(code: &str) -> Value {
    map(vec![
        ("status", Value::Num(0.0)),
        ("error_code", Value::str(code)),
    ])
}

fn azure_validate_storage(
    env: &ValidationEnv,
    account: &str,
    account_key: &str,
) -> Result<Value, EvalError> {
    if account.is_empty() || account_key.is_empty() {
        return Ok(azure_input_error("MissingInput"));
    }
    let url = format!("https://{account}.blob.core.windows.net/?comp=list");
    let date = crate::bindings_validation::rfc1123_utc((env.now_unix)());

    // The Shared Key string-to-sign: the canonicalised request, then the
    // canonicalised resource. The blank lines are REQUIRED — Azure rejects a
    // signature computed over a shortened form.
    let string_to_sign = format!(
        "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{date}\nx-ms-version:2021-08-06\n/{account}/\ncomp:list"
    );
    let Some(signature) = hmac_sha256_base64(account_key, &string_to_sign) else {
        return Ok(azure_input_error("InvalidKey"));
    };

    let mut req = httpclient_request("GET", &url, Vec::new());
    req.headers.insert("x-ms-date".to_string(), date);
    req.headers
        .insert("x-ms-version".to_string(), "2021-08-06".to_string());
    req.headers.insert(
        "Authorization".to_string(),
        format!("SharedKey {account}:{signature}"),
    );

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    if status != 200 {
        azure_add_xml_error(&mut out, &String::from_utf8_lossy(&body));
    }
    Ok(Value::Map(out))
}

fn azure_validate_service_principal(
    env: &ValidationEnv,
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Value, EvalError> {
    if tenant_id.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return Ok(azure_input_error("MissingInput"));
    }
    let url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        url_query_escape(client_id),
        url_query_escape(client_secret),
        url_query_escape("https://graph.microsoft.com/.default")
    );

    let mut req = httpclient_request("POST", &url, body.into_bytes());
    req.headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    if status != 200 {
        azure_add_json_error(&mut out, &String::from_utf8_lossy(&body));
    }
    Ok(Value::Map(out))
}

fn azure_validate_app_config(
    env: &ValidationEnv,
    endpoint: &str,
    id: &str,
    secret: &str,
) -> Result<Value, EvalError> {
    if endpoint.is_empty() || id.is_empty() || secret.is_empty() {
        return Ok(azure_input_error("MissingInput"));
    }
    let endpoint = endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/kv?api-version=1.0");
    let host = url
        .split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or("")
        .to_string();
    let date = crate::bindings_validation::rfc1123_utc((env.now_unix)());

    // An empty body still has a digest, and it must be the digest of the empty
    // string rather than omitted.
    let content_hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest([]));
    let string_to_sign = format!("GET\n/kv?api-version=1.0\n{date};{host};{content_hash}");
    let Some(signature) = hmac_sha256_base64(secret, &string_to_sign) else {
        return Ok(azure_input_error("InvalidKey"));
    };

    let mut req = httpclient_request("GET", &url, Vec::new());
    req.headers.insert("x-ms-date".to_string(), date);
    req.headers
        .insert("x-ms-content-sha256".to_string(), content_hash);
    req.headers.insert(
        "Authorization".to_string(),
        format!("HMAC-SHA256 Credential={id}&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}"),
    );

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    if status != 200 {
        azure_add_json_error(&mut out, &String::from_utf8_lossy(&body));
    }
    Ok(Value::Map(out))
}

fn azure_validate_service_bus_sas(
    env: &ValidationEnv,
    connection_string: &str,
) -> Result<Value, EvalError> {
    let parts = parse_azure_connection_string(connection_string);
    let (Some(endpoint), Some(key_name), Some(key)) = (
        parts.get("Endpoint"),
        parts.get("SharedAccessKeyName"),
        parts.get("SharedAccessKey"),
    ) else {
        return Ok(azure_input_error("MissingInput"));
    };

    // A Service Bus endpoint is `sb://…`; the management API is HTTPS.
    let https = endpoint.replace("sb://", "https://");
    let https = https.trim_end_matches('/');
    let url = format!("{https}/$Resources/queues?api-version=2017-04&$top=1");

    let expiry = (env.now_unix)() + 3600;
    let Some(token) = azure_sas_token(https, key_name, key, expiry) else {
        return Ok(azure_input_error("InvalidKey"));
    };

    let mut req = httpclient_request("GET", &url, Vec::new());
    req.headers.insert("Authorization".to_string(), token);

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    if status != 200 {
        azure_add_xml_error(&mut out, &String::from_utf8_lossy(&body));
    }
    Ok(Value::Map(out))
}

/// Go `azureAddXMLError` — Azure storage errors are XML.
fn azure_add_xml_error(out: &mut BTreeMap<String, Value>, body: &str) {
    if let Some(code) = xml_text(body, "Code") {
        out.insert("error_code".to_string(), Value::Str(code));
    }
    if let Some(message) = xml_text(body, "Message") {
        out.insert("error_message".to_string(), Value::Str(message));
    }
}

/// Go `azureAddJSONError` — the identity and app-config endpoints answer JSON,
/// and disagree on the field names, so both spellings are read.
fn azure_add_json_error(out: &mut BTreeMap<String, Value>, body: &str) {
    let Some(Value::Map(m)) = parse_json(body) else {
        return;
    };
    for key in ["error", "error_code", "code"] {
        match m.get(key) {
            Some(Value::Str(s)) => {
                out.insert("error_code".to_string(), Value::Str(s.clone()));
                break;
            }
            // The app-config form nests: `{"error": {"code": …}}`.
            Some(Value::Map(inner)) => {
                if let Some(Value::Str(code)) = inner.get("code") {
                    out.insert("error_code".to_string(), Value::Str(code.clone()));
                }
                if let Some(Value::Str(msg)) = inner.get("message") {
                    out.insert("error_message".to_string(), Value::Str(msg.clone()));
                }
                break;
            }
            _ => {}
        }
    }
    for key in ["error_description", "message"] {
        if let Some(Value::Str(s)) = m.get(key) {
            out.insert("error_message".to_string(), Value::Str(s.clone()));
            break;
        }
    }
}

// ── GCP ─────────────────────────────────────────────────────────────────────

/// Go `gcpJWTBearerGrant`.
const GCP_JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Go `gcpValidate` — build an RS256 JWT assertion from the service-account
/// key and exchange it for an access token.
///
/// This is the only binding that needs asymmetric crypto: a GCP service-account
/// credential IS an RSA private key, and the only way to prove it is live is to
/// sign with it.
fn gcp_validate(env: &ValidationEnv, credential_json: &str) -> Result<Value, EvalError> {
    let Some(Value::Map(creds)) = parse_json(credential_json) else {
        return Ok(map(vec![
            ("status", Value::Num(0.0)),
            ("error_code", Value::str("InvalidCredentialJSON")),
        ]));
    };
    let get = |k: &str| match creds.get(k) {
        Some(Value::Str(s)) => s.clone(),
        _ => String::new(),
    };
    let client_email = get("client_email");
    let private_key = get("private_key");
    let token_uri = {
        let t = get("token_uri");
        if t.is_empty() {
            "https://oauth2.googleapis.com/token".to_string()
        } else {
            t
        }
    };
    if client_email.is_empty() || private_key.is_empty() {
        return Ok(map(vec![
            ("status", Value::Num(0.0)),
            ("error_code", Value::str("MissingGCPFields")),
        ]));
    }

    let now = (env.now_unix)();
    let Some(assertion) = gcp_service_account_jwt(&client_email, &private_key, &token_uri, now)
    else {
        return Ok(map(vec![
            ("status", Value::Num(0.0)),
            ("error_code", Value::str("InvalidPrivateKey")),
        ]));
    };

    let body = format!(
        "grant_type={}&assertion={}",
        url_query_escape(GCP_JWT_BEARER_GRANT),
        url_query_escape(&assertion)
    );
    let mut req = httpclient_request("POST", &token_uri, body.into_bytes());
    req.headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    let Some((status, body)) = send(env, &req)? else {
        return Ok(status_zero());
    };
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    out.insert("status".to_string(), Value::Num(status as f64));
    out.insert("client_email".to_string(), Value::Str(client_email));
    if status != 200 {
        azure_add_json_error(&mut out, &String::from_utf8_lossy(&body));
    }
    Ok(Value::Map(out))
}

/// Go `createGCPServiceAccountJWT`.
pub fn gcp_service_account_jwt(
    client_email: &str,
    private_key_pem: &str,
    token_uri: &str,
    now: i64,
) -> Option<String> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = format!(
        "{{\"iss\":{},\"scope\":{},\"aud\":{},\"exp\":{},\"iat\":{}}}",
        go_json_string(client_email),
        go_json_string("https://www.googleapis.com/auth/cloud-platform"),
        go_json_string(token_uri),
        now + 3600,
        now
    );
    let payload = b64.encode(claims.as_bytes());
    let signing_input = format!("{header}.{payload}");

    let key = parse_gcp_private_key(private_key_pem)?;
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature = key
        .sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .ok()?;
    Some(format!("{signing_input}.{}", b64.encode(signature)))
}

/// Go `parseGCPPrivateKey` — PEM, then PKCS#8, then PKCS#1.
///
/// Both orderings matter: Google issues PKCS#8 (`BEGIN PRIVATE KEY`), but a key
/// that has been through a conversion tool is often PKCS#1
/// (`BEGIN RSA PRIVATE KEY`), and refusing the second would report a live
/// credential as unvalidatable.
fn parse_gcp_private_key(pem: &str) -> Option<rsa::RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    // The JSON carries the PEM with escaped newlines; by the time it is parsed
    // they are real, but a hand-edited credential may still have literal `\n`.
    let pem = pem.replace("\\n", "\n");
    rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
        .ok()
        .or_else(|| rsa::RsaPrivateKey::from_pkcs1_pem(&pem).ok())
}

// ── shared ──────────────────────────────────────────────────────────────────

fn httpclient_request(method: &str, url: &str, body: Vec<u8>) -> HttpRequest {
    HttpRequest {
        method: method.to_string(),
        url: url.to_string(),
        rule_id: String::new(),
        headers: BTreeMap::new(),
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Kept so the dispatcher can hand the rule id down without every builder
/// taking it as a parameter.
pub fn with_rule(mut req: HttpRequest, rule_id: &str) -> HttpRequest {
    req.rule_id = rule_id.to_string();
    req
}

/// So `send` can be exercised without a live client.
#[allow(dead_code)]
fn assert_object_safe(_: &dyn HttpClient) {}

#[cfg(test)]
mod tests;
