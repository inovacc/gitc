//! Port of Go `bindings_strings.go`'s `obfuscate` — a same-length,
//! class-preserving perturbation of a secret.
//!
//! ## What it is for
//!
//! A validation expression sometimes needs to send something SHAPED like the
//! secret without sending the secret: to see whether a provider rejects a
//! malformed key differently from a revoked one, or to probe an endpoint
//! without putting a live credential on the wire. `obfuscate` produces a string
//! the provider will parse and reject, of the same length, in the same
//! character classes.
//!
//! ## Why the prefix survives
//!
//! Above 20 characters an identifying PREFIX is kept verbatim — up to the first
//! separator within the first 8 characters, or 6 characters otherwise. That is
//! what keeps `github_pat_…` recognisable as a GitHub PAT rather than becoming
//! noise the provider rejects for the wrong reason.
//!
//! ## Randomness is a parameter
//!
//! Go reaches a package-level `obfuscateRand` its own tests swap out. Here the
//! source is passed down explicitly. It is a handful of extra parameters and it
//! buys the absence of `unsafe` and of shared mutable state in a tool whose
//! whole job is handling other people's secrets — worth it. The properties that
//! matter (same length, same classes, preserved prefix, every perturbed rune
//! genuinely DIFFERENT) are only checkable against a known stream.

/// Go `obfuscateRate` — the probability each rune is replaced.
const OBFUSCATE_RATE: f64 = 0.7;
/// Go `prefixMinLen` — at or below this, nothing is preserved.
const PREFIX_MIN_LEN: usize = 20;
const PREFIX_FALLBACK_LEN: usize = 6;
const PREFIX_SCAN_LEN: usize = 8;
const PREFIX_SEPARATORS: &str = "_-.";
const CLASS_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const CLASS_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CLASS_DIGIT: &str = "0123456789";
const CLASS_HEX_LOWER: &str = "0123456789abcdef";
const CLASS_HEX_UPPER: &str = "0123456789ABCDEF";

/// The randomness `obfuscate` draws on — Go's `obfuscateRand`.
pub trait RandomSource {
    /// A uniform integer in `[0, n)`. Go's `rand.Int` returns 0 on error and
    /// its callers accept that, so this cannot fail either.
    fn below(&self, n: u64) -> u64;
}

/// The default source.
///
/// **Not cryptographic, and it does not need to be.** The output is a decoy
/// sent to a provider that will reject it — never a key, a nonce, or an
/// identifier anything trusts. Said plainly here so it is not later mistaken
/// for one.
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn below(&self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
        let mut x = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        x ^= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        // splitmix64.
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        x % n
    }
}

/// Go `obfuscate`.
pub fn obfuscate(secret: &str, rng: &dyn RandomSource) -> String {
    if secret.is_empty() {
        return String::new();
    }
    let (prefix, body) = split_prefix(secret);
    if body.is_empty() {
        return secret.to_string();
    }
    let symbols = collect_symbols(&body);
    let hex = hex_pool(&body);

    let mut runes: Vec<char> = body.chars().collect();
    for r in runes.iter_mut() {
        if !should_perturb(rng) {
            continue;
        }
        *r = perturb_rune(*r, &symbols, hex, rng);
    }
    format!("{prefix}{}", runes.into_iter().collect::<String>())
}

/// Go `splitPrefix`.
fn split_prefix(secret: &str) -> (String, String) {
    let runes: Vec<char> = secret.chars().collect();
    if runes.len() <= PREFIX_MIN_LEN {
        return (String::new(), secret.to_string());
    }
    let scan = PREFIX_SCAN_LEN.min(runes.len());
    for i in 0..scan {
        if PREFIX_SEPARATORS.contains(runes[i]) {
            return (runes[..=i].iter().collect(), runes[i + 1..].iter().collect());
        }
    }
    (
        runes[..PREFIX_FALLBACK_LEN].iter().collect(),
        runes[PREFIX_FALLBACK_LEN..].iter().collect(),
    )
}

/// Go `hexPool` — the hex alphabet to use, or none.
///
/// MIXED-case hex falls through to generic alphanumeric: perturbing a
/// mixed-case string within one hex case would change its apparent shape.
fn hex_pool(secret: &str) -> Option<&'static str> {
    let mut has_lower = false;
    let mut has_upper = false;
    for c in secret.chars() {
        match c {
            '0'..='9' => {}
            'a'..='f' => has_lower = true,
            'A'..='F' => has_upper = true,
            _ => return None,
        }
    }
    match (has_lower, has_upper) {
        (true, true) | (false, false) => None,
        (true, false) => Some(CLASS_HEX_LOWER),
        (false, true) => Some(CLASS_HEX_UPPER),
    }
}

/// Go `collectSymbols` — the distinct symbols present, in order of appearance.
fn collect_symbols(secret: &str) -> Vec<char> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for c in secret.chars() {
        if !is_symbol(c) || !seen.insert(c) {
            continue;
        }
        out.push(c);
    }
    out
}

/// Go `perturbRune`.
fn perturb_rune(
    r: char,
    symbols: &[char],
    hex: Option<&'static str>,
    rng: &dyn RandomSource,
) -> char {
    if let Some(pool) = hex {
        if r.is_ascii_hexdigit() {
            return pick_different(pool, r, rng);
        }
    }
    match r {
        'a'..='z' => pick_different(CLASS_LOWER, r, rng),
        'A'..='Z' => pick_different(CLASS_UPPER, r, rng),
        '0'..='9' => pick_different(CLASS_DIGIT, r, rng),
        c if is_symbol(c) => {
            // With one distinct symbol there is nothing DIFFERENT to pick, and
            // Go returns it unchanged rather than looping forever.
            if symbols.len() <= 1 {
                return c;
            }
            let pool: String = symbols.iter().collect();
            pick_different(&pool, c, rng)
        }
        // Non-ASCII passes through: there is no meaningful "same class".
        other => other,
    }
}

/// Go `isSymbol` — printable ASCII that is not alphanumeric.
fn is_symbol(r: char) -> bool {
    let c = r as u32;
    (0x21..=0x7e).contains(&c) && !r.is_ascii_alphanumeric()
}

/// Go `pickDifferent` — draw until the result differs from the current rune.
///
/// Go loops unbounded; with a pool of two or more distinct members that
/// terminates with probability 1, but a SCANNER must not be able to spin on a
/// pathological source, so the loop is bounded and falls back to a deterministic
/// choice. The observable result is the same.
fn pick_different(pool: &str, current: char, rng: &dyn RandomSource) -> char {
    let runes: Vec<char> = pool.chars().collect();
    if runes.len() < 2 {
        return current;
    }
    for _ in 0..64 {
        let c = runes[rng.below(runes.len() as u64) as usize];
        if c != current {
            return c;
        }
    }
    runes.into_iter().find(|c| *c != current).unwrap_or(current)
}

/// Go `shouldPerturb` — true with probability `obfuscateRate`.
fn should_perturb(rng: &dyn RandomSource) -> bool {
    const DENOM: u64 = 1 << 53;
    (rng.below(DENOM) as f64) / (DENOM as f64) < OBFUSCATE_RATE
}

#[cfg(test)]
mod tests;
