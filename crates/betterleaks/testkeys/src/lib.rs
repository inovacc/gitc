//! Credential-shaped strings for tests, built at **runtime**.
//!
//! # Why this crate exists
//!
//! betterleaks is a secret scanner, so its tests need strings that look exactly
//! like real provider credentials. Committing those literals to a **public**
//! repository has two costs that have nothing to do with the tests:
//!
//! 1. GitHub push protection refuses the push (partner patterns are enforced on
//!    every public repo and cannot be switched off at the repository level), and
//! 2. GitHub *"will always send alerts to partners for detected secrets in public
//!    repositories"* — so every fake AWS/Slack/Stripe token in the tree fires an
//!    abuse alert inside those companies. Unblocking the push does not stop that.
//!
//! So no literal token appears in this repository's source. Every value is
//! assembled here at runtime from a prefix and a character set, or reconstructed
//! from an encoded form. **Nothing here is, or has ever been, a live credential.**
//!
//! # The two techniques, and when each applies
//!
//! - [`generate`] families ([`aws`], [`slack_bot`], …) synthesise a *fresh*
//!   format-valid value. Use these wherever a test just needs "a secret-shaped
//!   string" — the specific characters carry no meaning.
//! - [`reveal`] reconstructs an **exact** previously-recorded value from its
//!   encoded form. Use this where the precise bytes are load-bearing: the
//!   `detect` corpus fixtures pin a *measured* coverage baseline (`jwt` 4/12,
//!   `twilio-sk` 0/12 because entropy ≤ 3.0 discards those particular hex
//!   digits), so regenerating them would silently move the baseline the test
//!   exists to defend.
//!
//! Everything is deterministic: the same seed yields the same value on every run
//! and every platform, so a failure reproduces.

// ── deterministic PRNG ──────────────────────────────────────────────────────

/// SplitMix64 — a tiny, well-distributed, dependency-free generator.
///
/// Deterministic by design: tests that fail must fail identically on a rerun.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator. Any seed is valid.
    pub fn new(seed: u64) -> Rng {
        // Offset the seed so `new(0)` is not a degenerate state.
        Rng(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    /// Next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A string of `n` characters drawn from `alphabet`.
    ///
    /// # Panics
    /// If `alphabet` is empty — a caller asking for characters from nothing is a
    /// bug, and silently returning `""` would produce a token that matches no
    /// pattern and a confusing test failure far from the cause.
    pub fn pick(&mut self, alphabet: &str, n: usize) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        assert!(!chars.is_empty(), "testkeys: empty alphabet");
        (0..n)
            .map(|_| chars[(self.next_u64() % chars.len() as u64) as usize])
            .collect()
    }
}

/// Alphabets, named for the pattern that consumes them.
pub mod alphabet {
    /// `[A-Za-z0-9]`
    pub const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    /// `[A-Za-z0-9_-]` — the URL-safe base64 set, used by JWT and PAT formats.
    pub const ALNUM_URL: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    /// `[a-f0-9]`
    pub const HEX_LOWER: &str = "0123456789abcdef";
    /// `[A-Z2-7]` — RFC 4648 base32, which real AWS key ids actually use.
    pub const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    /// `[0-9A-Z]` — wider than base32; some corpus generators emit this, and the
    /// real AWS rule correctly rejects the values that fall outside base32.
    pub const UPPER_NUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
}

// ── provider formats ────────────────────────────────────────────────────────
//
// Each function documents the shape it produces so a reader can check it against
// the rule without running anything.

/// AWS access key id — `AKIA` + 16 base32 chars. Matches the real catalogue rule.
pub fn aws(seed: u64) -> String {
    format!("AKIA{}", Rng::new(seed).pick(alphabet::BASE32, 16))
}

/// AWS **temporary** access key id — `ASIA` + 16 base32 chars.
pub fn aws_temp(seed: u64) -> String {
    format!("ASIA{}", Rng::new(seed).pick(alphabet::BASE32, 16))
}

/// An `AKIA` id drawn from `[0-9A-Z]` rather than base32.
///
/// The real AWS rule requires base32, so a value from this function is expected
/// **not** to be detected. It exists so a test can assert that rejection on
/// purpose instead of relying on a lucky draw.
pub fn aws_non_base32(seed: u64) -> String {
    let mut r = Rng::new(seed);
    // Force at least one character outside base32 so the rejection is guaranteed
    // rather than probabilistic.
    format!("AKIA{}1{}", r.pick(alphabet::UPPER_NUM, 8), r.pick(alphabet::UPPER_NUM, 7))
}

/// AWS secret access key — 40 chars of `[A-Za-z0-9/+]`.
pub fn aws_secret(seed: u64) -> String {
    Rng::new(seed).pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+", 40)
}

/// Slack bot token — `xoxb-` + digit groups + a 24-char suffix.
pub fn slack_bot(seed: u64) -> String {
    let mut r = Rng::new(seed);
    format!(
        "xoxb-{}-{}-{}",
        r.pick("0123456789", 12),
        r.pick("0123456789", 13),
        r.pick(alphabet::ALNUM, 24)
    )
}

/// Slack user token — `xoxp-` with the same shape as [`slack_bot`].
pub fn slack_user(seed: u64) -> String {
    let mut r = Rng::new(seed);
    format!(
        "xoxp-{}-{}-{}",
        r.pick("0123456789", 12),
        r.pick("0123456789", 13),
        r.pick(alphabet::ALNUM, 24)
    )
}

/// Stripe secret key — `sk_live_` + 24 alphanumerics.
pub fn stripe_secret(seed: u64) -> String {
    format!("sk_live_{}", Rng::new(seed).pick(alphabet::ALNUM, 24))
}

/// Stripe **test** key — `sk_test_` + 24 alphanumerics.
pub fn stripe_test(seed: u64) -> String {
    format!("sk_test_{}", Rng::new(seed).pick(alphabet::ALNUM, 24))
}

/// GitHub personal access token — `ghp_` + 36 alphanumerics.
pub fn github_pat(seed: u64) -> String {
    format!("ghp_{}", Rng::new(seed).pick(alphabet::ALNUM, 36))
}

/// GitHub OAuth token — `gho_` + 36 alphanumerics.
pub fn github_oauth(seed: u64) -> String {
    format!("gho_{}", Rng::new(seed).pick(alphabet::ALNUM, 36))
}

/// GitHub fine-grained PAT — `github_pat_` + 82 chars of `[A-Za-z0-9_]`.
pub fn github_fine(seed: u64) -> String {
    let mut r = Rng::new(seed);
    format!(
        "github_pat_{}_{}",
        r.pick(alphabet::ALNUM, 22),
        r.pick(alphabet::ALNUM, 59)
    )
}

/// npm access token — `npm_` + 36 alphanumerics.
pub fn npm(seed: u64) -> String {
    format!("npm_{}", Rng::new(seed).pick(alphabet::ALNUM, 36))
}

/// Google API key — `AIza` + 35 chars of `[A-Za-z0-9_-]`.
pub fn google_api(seed: u64) -> String {
    format!("AIza{}", Rng::new(seed).pick(alphabet::ALNUM_URL, 35))
}

/// OpenRouter key — `sk-or-v1-` + 64 lowercase hex.
pub fn openrouter(seed: u64) -> String {
    format!("sk-or-v1-{}", Rng::new(seed).pick(alphabet::HEX_LOWER, 64))
}

/// SendGrid key — `SG.` + 22 + `.` + 43 URL-safe chars.
pub fn sendgrid(seed: u64) -> String {
    let mut r = Rng::new(seed);
    format!(
        "SG.{}.{}",
        r.pick(alphabet::ALNUM_URL, 22),
        r.pick(alphabet::ALNUM_URL, 43)
    )
}

/// Twilio API key — `SK` + 32 lowercase hex.
///
/// Note the real rule additionally discards secrets with entropy ≤ 3.0, so a
/// value from here may legitimately go undetected.
pub fn twilio(seed: u64) -> String {
    format!("SK{}", Rng::new(seed).pick(alphabet::HEX_LOWER, 32))
}

/// A structurally valid three-segment JWT (header.payload.signature), each
/// segment URL-safe base64 of real JSON.
pub fn jwt(seed: u64) -> String {
    let mut r = Rng::new(seed);
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(
        format!(
            r#"{{"sub":"{}","name":"test","iat":1600000000}}"#,
            r.pick("0123456789", 10)
        )
        .as_bytes(),
    );
    format!("{header}.{payload}.{}", r.pick(alphabet::ALNUM_URL, 43))
}

/// A PEM private-key block with a body long enough for the real rule (which
/// needs the header **plus** ≥64 chars of body **plus** a footer).
pub fn private_key_pem(seed: u64) -> String {
    let mut r = Rng::new(seed);
    let body: Vec<String> = (0..4).map(|_| r.pick(alphabet::ALNUM, 64)).collect();
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
        body.join("\n")
    )
}

// ── exact reconstruction ────────────────────────────────────────────────────

/// Byte mask applied before hex encoding.
///
/// This is **not** secrecy and is not pretending to be — the mask is right here in
/// the source. Its only job is to stop the stored form being something a scanner
/// recognises. Base64 alone is not enough: GitHub's secret scanning **decodes
/// base64 and matches through it**, which was discovered the direct way, by a push
/// being refused for tokens that were already base64-encoded in the fixture.
const MASK: &[u8] = b"betterleaks-testkeys";

/// Reconstructs an exact recorded value from its masked-hex form.
///
/// Used for fixtures whose precise bytes are load-bearing. Storing them encoded
/// keeps the literal out of the source while leaving the value byte-identical, so
/// a measured baseline computed over the originals still means what it meant.
///
/// # Panics
/// On malformed input — a corrupt fixture must fail loudly at the point of use,
/// not silently degrade into a string that matches nothing and a green test.
pub fn reveal(encoded: &str) -> String {
    let raw = unhex(encoded).expect("testkeys: malformed fixture encoding");
    String::from_utf8(xor_mask(&raw)).expect("testkeys: fixture is not valid UTF-8")
}

/// Encodes a value into the form [`reveal`] accepts.
pub fn conceal(plain: &str) -> String {
    hex(&xor_mask(plain.as_bytes()))
}

/// XOR with the repeating [`MASK`]. Its own inverse.
fn xor_mask(b: &[u8]) -> Vec<u8> {
    b.iter()
        .enumerate()
        .map(|(i, x)| x ^ MASK[i % MASK.len()])
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// URL-safe, unpadded base64 — the encoding JWT segments use.
fn b64url(input: &[u8]) -> String {
    b64_encode(input)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    };

    let raw: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=').collect();
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    for chunk in raw.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic() {
        assert_eq!(aws(1), aws(1));
        assert_eq!(github_pat(7), github_pat(7));
        assert_ne!(aws(1), aws(2), "different seeds must differ");
    }

    #[test]
    fn shapes_match_their_documented_formats() {
        let k = aws(1);
        assert!(k.starts_with("AKIA") && k.len() == 20, "{k}");
        assert!(k[4..].chars().all(|c| alphabet::BASE32.contains(c)), "{k} not base32");

        assert_eq!(github_pat(1).len(), 40);
        assert_eq!(npm(1).len(), 40);
        assert_eq!(google_api(1).len(), 39);
        assert_eq!(openrouter(1).len(), 73);
        assert!(stripe_secret(1).starts_with("sk_live_"));
        assert!(slack_bot(1).starts_with("xoxb-"));
    }

    /// The non-base32 variant must be guaranteed-invalid, not luckily invalid.
    #[test]
    fn aws_non_base32_always_contains_an_out_of_set_char() {
        for seed in 0..64 {
            let k = aws_non_base32(seed);
            assert!(
                k[4..].chars().any(|c| !alphabet::BASE32.contains(c)),
                "{k} happens to be valid base32; the rejection test would silently pass"
            );
        }
    }

    #[test]
    fn jwt_has_three_segments_and_decodable_header() {
        let t = jwt(3);
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3, "{t}");
        let header = String::from_utf8(b64_decode(parts[0]).expect("header b64")).expect("utf8");
        assert!(header.contains("HS256"), "{header}");
    }

    #[test]
    fn conceal_reveal_round_trips() {
        for s in ["", "a", "ab", "abc", "abcd", "AKIA-not-a-real-key", "üñíçø∂é"] {
            assert_eq!(reveal(&conceal(s)), s, "round-trip failed for {s:?}");
        }
    }

    #[test]
    fn b64url_matches_known_rfc4648_vectors() {
        // Proves the JWT segment encoder against the spec, not just itself.
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
    }

    /// The property the encoding exists for: the stored form must not contain the
    /// plaintext, or a scanner would match it right there in the fixture.
    #[test]
    fn the_concealed_form_does_not_contain_the_plaintext() {
        let plain = "AKIA_not_a_real_key_0123456789";
        let enc = conceal(plain);
        assert!(!enc.contains(plain));
        assert!(!enc.contains("AKIA"), "not even the prefix survives: {enc}");
        assert!(enc.chars().all(|c| c.is_ascii_hexdigit()), "hex only: {enc}");
        assert_eq!(reveal(&enc), plain);
    }

    #[test]
    fn malformed_encodings_are_rejected_loudly() {
        assert!(unhex("abc").is_none(), "odd length");
        assert!(unhex("zz").is_none(), "not hex");
    }
}
