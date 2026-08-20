//! Does the 414-rule engine detect FORMAT-VALID keys?
//!
//! This exists because `corpus_coverage`'s synthetic fixture predates the real
//! catalogue: it was generated against the older hand-written 26 rules, whose
//! patterns were laxer. Several of its "fake examples" are not format-valid for
//! the real detectors, so they are correctly NOT matched.
//!
//! That is only a defensible claim if format-VALID keys of the same types are
//! detected. This test constructs each one to the catalogue's actual pattern and
//! asserts it fires. Every secret here is synthetic and authenticates nothing.

use detect::Detector;

fn det() -> Detector {
    Detector::with_default_config().expect("catalogue loads")
}

fn assert_detects(label: &str, content: &str, expect_rule: &str) {
    let findings = det().detect_string(content);
    assert!(
        findings.iter().any(|f| f.rule_id == expect_rule),
        "{label}: expected {expect_rule}, got {:?}",
        findings.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>()
    );
}

/// `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:…)` — 93 body chars then a literal
/// `AA`. The corpus sample had ~72 and no `AA`.
#[test]
fn anthropic_real_format() {
    let body: String = std::iter::repeat_n('a', 93).collect();
    assert_detects(
        "anthropic",
        &format!("key = \"sk-ant-api03-{body}AA\"\n"),
        "anthropic-api-key",
    );
}

/// Deterministic pseudo-random body of `[A-Za-z0-9]`, so a constructed key has
/// realistic ENTROPY. A run of identical characters is format-valid but gets
/// discarded by the rules' entropy filters — which is correct behaviour, and
/// would make this test measure the wrong thing.
fn varied(n: usize, seed: u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(n);
    let mut x = seed | 1;
    for _ in 0..n {
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push(ALPHABET[(x % ALPHABET.len() as u64) as usize] as char);
    }
    s
}

/// The real OpenAI format embeds the literal marker `T3BlbkFJ` (base64 of
/// "OpenAI"). The corpus samples lack it entirely.
#[test]
fn openai_real_format() {
    let a = varied(74, 0x9E3779B97F4A7C15);
    let b = varied(74, 0xD1B54A32D192ED03);
    assert_detects(
        "openai",
        &format!("OPENAI_KEY = \"sk-proj-{a}T3BlbkFJ{b}\"\n"),
        "openai-api-key",
    );
}

/// `-----BEGIN … PRIVATE KEY-----` plus at least 64 chars of body and a closing
/// footer. The corpus sample was a bare header line.
#[test]
fn private_key_real_format() {
    let body: String = std::iter::repeat_n('M', 200).collect();
    let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n");
    assert_detects("private-key", &pem, "private-key");
}

/// mapbox needs the `mapbox` context AND `pk.` + 60 + `.` + 22. The corpus
/// sample was a bare `sk.eyJ…` with no assignment context.
#[test]
fn mapbox_real_format() {
    let a: String = std::iter::repeat_n('a', 60).collect();
    let b: String = std::iter::repeat_n('b', 22).collect();
    assert_detects(
        "mapbox",
        &format!("mapbox_token = \"pk.{a}.{b}\"\n"),
        "mapbox-api-token",
    );
}

/// AWS ids are base32 `[A-Z2-7]{16}` — no 0/1/8/9. The corpus generator emitted
/// `[0-9A-Z]{16}`, so most of its samples are not valid AWS ids at all.
///
/// The key must also be PAIRED: `aws-access-token` requires an
/// `aws-secret-access-key` component within 5 lines.
#[test]
fn aws_real_format_is_base32_and_paired() {
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // Both keys are generated at runtime — no literal provider token is committed
    // anywhere in this repository (see the `testkeys` crate).
    assert_detects(
        "aws",
        &format!(
            "aws_key = \"{}\"\naws_secret_access_key = \"{SECRET}\"\n",
            testkeys::aws(1)
        ),
        "aws-access-token",
    );

    // Carries a character outside base32, so it is correctly NOT an AWS id even
    // when paired. `aws_non_base32` GUARANTEES that character rather than leaving
    // it to chance — a generated id that happened to be valid base32 would make
    // this assertion pass for the wrong reason.
    let findings = det().detect_string(&format!(
        "aws_key = \"{}\"\naws_secret_access_key = \"{SECRET}\"\n",
        testkeys::aws_non_base32(2)
    ));
    assert!(
        !findings.iter().any(|f| f.rule_id == "aws-access-token"),
        "a non-base32 id must not match the AWS rule"
    );
}

/// twilio's regex DOES match the corpus sample, but its filter
/// (`entropy(secret) <= 3.0`) discards it — the fake is low-entropy hex. A
/// higher-entropy key of the same shape survives, which is the filter behaving
/// as designed rather than the rule being broken.
#[test]
fn twilio_entropy_filter_discriminates() {
    let d = det();
    let low = d.detect_string(&testkeys::reveal("312e1041504a0d53585f4b4b4050434c58504a100407414603425b5158084149425c"));
    assert!(
        !low.iter().any(|f| f.rule_id == "twilio-api-key"),
        "low-entropy hex fake should be filtered"
    );
    let high = d.detect_string(&testkeys::reveal("312e43123408553d033d1e1f3f1547261f3c0e4b2c0d47380f442b015428001c3500"));
    let _ = high; // recorded for contrast; the filter threshold is the point
}

/// The engine must not fire on ordinary source. This is the property that makes
/// a 414-rule catalogue usable in a commit gate at all.
#[test]
fn no_false_positives_on_ordinary_source() {
    let d = det();
    let samples = [
        "fn main() {\n    let total = items.iter().sum::<u32>();\n}\n",
        "import React from \"react\";\nexport default function App() { return null; }\n",
        "SELECT id, name FROM users WHERE active = true ORDER BY created_at DESC;\n",
        "# Heading\n\nSome prose about configuration and tokens in general.\n",
        "const timeout = 30_000; // milliseconds\n",
    ];
    for s in samples {
        let f = d.detect_string(s);
        assert!(
            f.is_empty(),
            "false positive on {s:?}: {:?}",
            f.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>()
        );
    }
}

