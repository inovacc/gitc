use super::*;

/// Generated at runtime — no literal provider token is committed (see `testkeys`).
fn aws_key() -> String {
    testkeys::aws(1)
}

/// Always perturbs, and always picks pool index 0 — so every result is
/// predictable and the CLASS behaviour is what is being asserted, not the
/// randomness.
struct AlwaysFirst;
impl RandomSource for AlwaysFirst {
    fn below(&self, _n: u64) -> u64 {
        0
    }
}

/// Never perturbs: `should_perturb` compares `below(DENOM)/DENOM < 0.7`, so a
/// source returning the maximum always fails that test.
struct NeverPerturb;
impl RandomSource for NeverPerturb {
    fn below(&self, n: u64) -> u64 {
        n.saturating_sub(1)
    }
}

/// A fixed cycle, for asserting that different draws give different results.
struct Cycle(std::cell::Cell<u64>);
impl RandomSource for Cycle {
    fn below(&self, n: u64) -> u64 {
        let v = self.0.get();
        self.0.set(v.wrapping_add(1));
        v % n.max(1)
    }
}

#[test]
fn an_empty_secret_stays_empty() {
    assert_eq!(obfuscate("", &AlwaysFirst), "");
}

/// The rate gate is honoured: a source that never clears it returns the secret
/// untouched.
#[test]
fn nothing_changes_when_the_rate_gate_never_opens() {
    let s = "github_pat_11ABCDEFG0abcdefghijklmn";
    assert_eq!(obfuscate(s, &NeverPerturb), s);
}

/// The invariant that makes the output usable: SAME LENGTH, and every rune
/// stays in its own character class.
#[test]
fn length_and_character_classes_are_preserved() {
    for secret in [
        &aws_key(),
        "github_pat_11ABCDEFG0abcdefghijklmnop",
        &testkeys::slack_bot(2),
        &testkeys::stripe_secret(3),
    ] {
        let out = obfuscate(secret, &Cycle(std::cell::Cell::new(3)));
        assert_eq!(
            out.chars().count(),
            secret.chars().count(),
            "{secret} -> {out}"
        );
        for (a, b) in secret.chars().zip(out.chars()) {
            let same_class = (a.is_ascii_lowercase() && b.is_ascii_lowercase())
                || (a.is_ascii_uppercase() && b.is_ascii_uppercase())
                || (a.is_ascii_digit() && b.is_ascii_digit())
                || (is_symbol(a) && is_symbol(b))
                || a == b;
            assert!(same_class, "{a:?} became {b:?} in {secret} -> {out}");
        }
    }
}

/// A perturbed rune must actually DIFFER — a "perturbation" that returns the
/// same character would leak the secret verbatim while claiming not to.
#[test]
fn every_perturbed_rune_is_different() {
    // AlwaysFirst picks pool index 0 unless that equals the current rune, in
    // which case pick_different draws again — and with this source the retry
    // returns index 0 forever, so the fallback path must supply a different
    // member.
    let out = obfuscate("abcdef", &AlwaysFirst);
    assert_eq!(out.chars().count(), 6);
    for (a, b) in "abcdef".chars().zip(out.chars()) {
        assert_ne!(a, b, "{a} was not perturbed in {out}");
    }
}

/// Below the threshold, nothing is preserved — a short secret has no prefix
/// worth keeping and every character is fair game.
#[test]
fn a_short_secret_keeps_no_prefix() {
    let short = "abcdefghij"; // 10, well under 20
    let (prefix, body) = split_prefix(short);
    assert_eq!(prefix, "");
    assert_eq!(body, short);

    // Exactly at the boundary is still "short": Go's test is `<=`.
    let exactly = "a".repeat(PREFIX_MIN_LEN);
    assert_eq!(split_prefix(&exactly).0, "");
}

/// Above the threshold the prefix runs to the first separator within the first
/// 8 characters — which is what keeps a `github_pat_` recognisable.
#[test]
fn a_long_secret_keeps_its_identifying_prefix() {
    let (prefix, body) = split_prefix("github_pat_11ABCDEFG0abcdefghijklmn");
    assert_eq!(prefix, "github_", "up to and INCLUDING the separator");
    assert_eq!(body, "pat_11ABCDEFG0abcdefghijklmn");

    // And the whole prefix survives obfuscation.
    let out = obfuscate("github_pat_11ABCDEFG0abcdefghijklmn", &Cycle(std::cell::Cell::new(1)));
    assert!(out.starts_with("github_"), "{out}");
}

/// With no separator in the first 8 characters, a fixed 6 are kept.
#[test]
fn without_a_separator_a_fixed_prefix_is_kept() {
    // An AWS id has no separator in its first 8 characters, so the split falls to
    // the fixed-6 rule. The expectation is derived from the input rather than
    // spelled out, because the key itself is generated — but the ASSERTION is the
    // same one: exactly six characters are kept, and nothing is lost.
    let full = format!("{}EXTRA", aws_key());
    let (prefix, body) = split_prefix(&full);
    assert_eq!(prefix.len(), 6, "a fixed six characters are kept: {prefix}");
    assert_eq!(prefix, &full[..6]);
    assert_eq!(body, &full[6..]);
}

/// Single-case hex is perturbed WITHIN the hex alphabet, so the result is still
/// hex. Mixed case falls through to generic alphanumeric, because narrowing it
/// would change the string's apparent shape.
#[test]
fn hex_secrets_stay_hex_unless_they_are_mixed_case() {
    assert_eq!(hex_pool("deadbeef0123"), Some(CLASS_HEX_LOWER));
    assert_eq!(hex_pool("DEADBEEF0123"), Some(CLASS_HEX_UPPER));
    assert_eq!(hex_pool("DeadBeef0123"), None, "mixed case is not a hex pool");
    assert_eq!(hex_pool("0123456789"), None, "digits alone are not hex");
    assert_eq!(hex_pool("nothex"), None);

    let out = obfuscate("deadbeefcafebabe", &Cycle(std::cell::Cell::new(5)));
    assert!(
        out.chars().all(|c| CLASS_HEX_LOWER.contains(c)),
        "a lower-hex secret must stay lower-hex: {out}"
    );
}

/// A symbol is swapped for another symbol PRESENT IN THE SECRET, so the result
/// cannot acquire punctuation the original never had.
#[test]
fn symbols_are_swapped_only_for_symbols_the_secret_already_had() {
    assert_eq!(collect_symbols("a-b_c-d"), vec!['-', '_']);
    assert_eq!(collect_symbols("abc"), Vec::<char>::new());

    let out = obfuscate("aa-bb_cc-dd_ee", &Cycle(std::cell::Cell::new(2)));
    for c in out.chars().filter(|c| is_symbol(*c)) {
        assert!(c == '-' || c == '_', "{c:?} appeared in {out}");
    }
}

/// With only ONE distinct symbol there is nothing different to pick, and it is
/// left alone rather than looping forever — Go's guard.
#[test]
fn a_lone_symbol_is_left_alone() {
    let out = obfuscate("a-b-c-d", &AlwaysFirst);
    assert_eq!(out.matches('-').count(), 3, "{out}");
}

/// Non-ASCII passes through: there is no meaningful same-class replacement.
#[test]
fn non_ascii_passes_through() {
    let out = obfuscate("clé—π", &AlwaysFirst);
    assert!(out.contains('é') && out.contains('—') && out.contains('π'), "{out}");
}

/// The whole point: the output is NOT the input.
#[test]
fn the_secret_does_not_survive() {
    let secret = aws_key();
    let out = obfuscate(&secret, &AlwaysFirst);
    assert_ne!(out, secret);
}

