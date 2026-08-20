//! Test cases ported from the betterleaks/gitleaks rule generators
//! (`cmd/generate/config/rules/*.go`, where each rule ships `Validate(r, tps, fps)`)
//! plus hand-rolled fuzz tests to find gaps. betterleaks is a gitleaks fork, so its
//! rule tps/fps are the gitleaks test cases; this pins `detect`'s ported rules
//! against them.
//!
//! - True positives (`tps`) — must be detected by the right rule.
//! - False positives (`fps`) — concrete placeholder literals from the Go source;
//!   must NOT be detected (they exercise the entropy gate + the allowlist).
//! - Fuzz — a deterministic xorshift PRNG generates (a) valid-shape tokens that
//!   must always fire, (b) natural-language noise that must never fire (catches
//!   over-broad regexes), and (c) arbitrary bytes that must never panic.

use detect::Detector;

// ---- deterministic PRNG (no deps; reproducible in CI) ----

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn token(&mut self, set: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| set[(self.next_u64() % set.len() as u64) as usize] as char)
            .collect()
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize % (hi - lo + 1))
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const AWS16: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // [A-Z2-7]
const WORD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
const DIGITS: &[u8] = b"0123456789";

fn detects(d: &Detector, content: &str, rule: &str) -> bool {
    d.detect_string(content).iter().any(|f| f.rule_id == rule)
}

/// Generate one valid-shape token for `rule` using `r`.
fn valid_token(r: &mut Rng, rule: &str) -> String {
    match rule {
        // `aws-access-token` declares a REQUIRED component
        // (`aws-secret-access-key` within 5 lines), so a lone access-key id is
        // not a finding — in this port or in the Go engine, which was run to
        // confirm it. The generator therefore emits the PAIR.
        "aws-access-token" => format!(
            "AKIA{}\"\naws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            r.token(AWS16, 16)
        ),
        "github-pat" => format!("ghp_{}", r.token(ALNUM, 36)),
        "github-fine-grained-pat" => format!("github_pat_{}", r.token(WORD, 82)),
        "github-oauth" => format!("gho_{}", r.token(ALNUM, 36)),
        "github-app-token" => format!("ghu_{}", r.token(ALNUM, 36)),
        "gitlab-pat" => format!("glpat-{}", r.token(ALNUM, 20)),
        "slack-bot-token" => {
            format!("xoxb-{}-{}{}", r.token(DIGITS, 11), r.token(DIGITS, 11), r.token(ALNUM, 20))
        }
        "slack-user-token" => format!(
            "xoxp-{}-{}-{}-{}",
            r.token(DIGITS, 11),
            r.token(DIGITS, 11),
            r.token(DIGITS, 11),
            r.token(ALNUM, 30)
        ),
        "stripe-access-token" => format!("sk_live_{}", r.token(ALNUM, 24)),
        // A real JWT header is base64 of `{"alg":…`, so it ALWAYS begins `eyJ`
        // — and the rule's keyword is literally `eyj`. The old generator emitted
        // `ey` + random, producing strings that are not valid JWTs and that the
        // keyword prefilter therefore never considers (Go behaves the same way).
        // Fixed here rather than weakening the rule.
        "jwt" => format!(
            "eyJ{}.eyJ{}.{}",
            r.token(ALNUM, 24),
            r.token(ALNUM, 24),
            r.token(ALNUM, 20)
        ),
        other => panic!("no generator for {other}"),
    }
}

/// Rules with a random-shape generator (openai/private-key use fixed literals).
const SHAPED_RULES: &[&str] = &[
    "aws-access-token",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
    "github-app-token",
    "gitlab-pat",
    "slack-bot-token",
    "slack-user-token",
    "stripe-access-token",
    "jwt",
];

// ---- ported true positives ----

#[test]
fn ported_true_positives() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0x5EC0_1DEA);

    for &rule in SHAPED_RULES {
        let tok = valid_token(&mut r, rule);
        let content = format!("{rule}_secret = \"{tok}\"");
        assert!(detects(&d, &content, rule), "expected {rule} in: {content}");
    }

    // aws — the other valid prefixes.
    for prefix in ["ASIA", "ABIA", "ACCA"] {
        let tok = format!("{prefix}{}", r.token(AWS16, 16));
        // Paired, for the required-component reason above.
        let content = format!(
            "k=\"{tok}\"\naws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\""
        );
        assert!(detects(&d, &content, "aws-access-token"), "{tok}");
    }

    // openai — a real fixture key from openai.go's tps (fake but valid-format).
    let openai = testkeys::reveal("110e5904171d0648320e05572320252b2508371d2f0b1025501502533101354e2c3a4a1512502a362916114c243e5c201432326f44063a132d324e36131047022610390738381b5b1d0c453858173b0451322047271e0e0e272117694d23023b523f4a310d27014d235f2723335d2a67001324420d301f0205571b4629140909520f1a79472a302606273b41560d1e17012d19292401145f4d113005050b1c0134124c35"); // exact: the rule requires the embedded T3BlbkFJ marker
    assert!(detects(&d, &format!("OPENAI_API_KEY={openai}"), "openai-api-key"));

    // private-key — a PEM block (content between the fences is arbitrary base64).
    let pem = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
        r.token(ALNUM, 200)
    );
    assert!(detects(&d, &pem, "private-key"));
}

// ---- ported false positives (must NOT fire) ----

#[test]
fn ported_false_positives() {
    let d = Detector::with_default_rules();

    // Concrete fps copied from the Go rule generators' `fps` arrays.
    let fps: &[&str] = &[
        // github — all-`x` placeholders (entropy 0 → filtered).
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "github_pat_xxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        // aws — low-entropy placeholder + the EXAMPLE key (allowlisted).
        "key = AKIAXXXXXXXXXXXXXXXX",
        "aws_access_key: AKIAIOSFODNN7EXAMPLE",
        // gitlab — low-entropy placeholder.
        "glpat-XXXXXXXXXXX-XXXXXXXX",
        // slack — malformed / placeholder (letters where digits required, or too short).
        "xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx",
        "xoxb-xxx",
        "xoxb-12345-abcd234",
    ];

    for s in fps {
        let f = d.detect_string(s);
        assert!(f.is_empty(), "false positive on {s:?}: {f:?}");
    }
}

// ---- sample-format coverage (INI/JSON/YAML/XML shapes from GenerateSampleSecrets) ----

#[test]
fn detected_across_config_formats() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0xF0_1234);
    let tok = format!("ghp_{}", r.token(ALNUM, 36));

    let samples = [
        format!("token=\"{tok}\""),                       // ini quoted
        format!("token = {tok}"),                          // ini unquoted
        format!("{{\n    \"github_token\": \"{tok}\"\n}}"), // json
        format!("token: {tok}"),                           // yaml
        format!("<githubToken>\n    {tok}\n</githubToken>"), // xml multiline
    ];
    for s in &samples {
        assert!(detects(&d, s, "github-pat"), "missed in: {s}");
    }
}

// ---- fuzz: valid-shape tokens must ALWAYS fire (finds too-strict rules) ----

#[test]
fn fuzz_valid_shapes_always_detected() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0xA11CE_5EED);
    for &rule in SHAPED_RULES {
        for i in 0..300 {
            let tok = valid_token(&mut r, rule);
            let content = format!("x = {tok}");
            assert!(detects(&d, &content, rule), "iter {i} {rule} missed: {tok}");
        }
    }
}

// ---- fuzz: natural-language noise must NEVER fire (finds over-broad rules) ----

#[test]
fn fuzz_natural_text_no_false_positives() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0xD15EA5E);
    // Lowercase words only — cannot form the (prefix-anchored, uppercase) tokens.
    const WORDS: &[&str] = &[
        "the", "quick", "brown", "fox", "config", "value", "return", "function", "let", "const",
        "data", "user", "name", "hello", "world", "commit", "branch", "merge", "index", "buffer",
        "handle", "request", "response", "status", "error", "result", "context", "record",
    ];
    for _ in 0..2000 {
        let n = r.range(3, 20);
        let sentence: Vec<&str> = (0..n).map(|_| WORDS[r.next_u64() as usize % WORDS.len()]).collect();
        let line = sentence.join(if r.next_u64() & 1 == 0 { " " } else { "\n" });
        let f = d.detect_string(&line);
        assert!(f.is_empty(), "false positive on noise: {f:?}\n{line}");
    }
}

// ---- fuzz: arbitrary bytes must never panic (robustness) ----

#[test]
fn fuzz_random_bytes_no_panic() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0xBADC0FFE);
    for _ in 0..2000 {
        let len = r.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| (r.next_u64() & 0xFF) as u8).collect();
        // Must return without panicking (the assertion is that we get here).
        let _ = d.detect_bytes(&bytes);
    }
}

// ---- fuzz: detection is idempotent ----

#[test]
fn fuzz_idempotent() {
    let d = Detector::with_default_rules();
    let mut r = Rng::new(0x1D3E_A1);
    for &rule in SHAPED_RULES {
        let tok = valid_token(&mut r, rule);
        let content = format!("k={tok} {}", r.token(WORD, 40));
        let a = d.detect_string(&content).len();
        let b = d.detect_string(&content).len();
        assert_eq!(a, b, "non-deterministic for {rule}");
    }
}

