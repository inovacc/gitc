//! Port of Go `internal/exprruntime/bindings_filter.go` — the six functions the
//! filter namespace exposes, plus the two caches that keep them off the hot
//! path.

use ahocorasick::Matcher;
use regexp::Regexp;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Go `regexCache sync.Map // string -> *blregexp.Regexp`.
fn regex_cache() -> &'static Mutex<HashMap<String, Option<std::sync::Arc<Regexp>>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<std::sync::Arc<Regexp>>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Go `acTrieCache sync.Map // string -> *ahocorasick.Matcher`.
fn trie_cache() -> &'static Mutex<HashMap<String, std::sync::Arc<Matcher>>> {
    static C: OnceLock<Mutex<HashMap<String, std::sync::Arc<Matcher>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Go `orderedKey` — patterns joined by NUL, order-sensitive.
fn ordered_key(ss: &[String]) -> String {
    ss.join("\u{0}")
}

/// Go `sortedKey` — a COPY is sorted, so the caller's slice is untouched.
fn sorted_key(ss: &[String]) -> String {
    let mut cp = ss.to_vec();
    cp.sort();
    cp.join("\u{0}")
}

/// Go `getOrCompileJoinedRegex` — wrap each pattern in `(?:…)` and alternate
/// them into ONE regex, cached by the ordered key.
///
/// A compile failure yields `None` (Go returns a nil `*Regexp`) and — matching
/// Go's `sync.Map` behaviour of only storing successes — the failure is cached
/// as `None` here so a bad pattern is not recompiled on every call.
pub fn get_or_compile_joined_regex(patterns: &[String]) -> Option<std::sync::Arc<Regexp>> {
    if patterns.is_empty() {
        return None;
    }
    let key = ordered_key(patterns);
    if let Some(hit) = regex_cache().lock().expect("regex cache").get(&key) {
        return hit.clone();
    }
    let joined = patterns
        .iter()
        .map(|p| format!("(?:{p})"))
        .collect::<Vec<_>>()
        .join("|");
    let compiled = regexp::compile(&joined).ok().map(std::sync::Arc::new);
    regex_cache()
        .lock()
        .expect("regex cache")
        .insert(key, compiled.clone());
    compiled
}

/// Go `getOrBuildTrie` — terms are lower-cased, then cached by SORTED key so two
/// call sites listing the same terms in different orders share one trie.
fn get_or_build_trie(terms: &[String]) -> Option<std::sync::Arc<Matcher>> {
    if terms.is_empty() {
        return None;
    }
    let normalized: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    let key = sorted_key(&normalized);
    if let Some(hit) = trie_cache().lock().expect("trie cache").get(&key) {
        return Some(hit.clone());
    }
    let refs: Vec<&str> = normalized.iter().map(|s| s.as_str()).collect();
    // `fold_ascii = false`: Go lower-cases both the terms and the haystack
    // itself, so the matcher does no folding of its own.
    let m = std::sync::Arc::new(Matcher::compile(&refs, false));
    trie_cache()
        .lock()
        .expect("trie cache")
        .insert(key, m.clone());
    Some(m)
}

/// Go `matchesAny(s, patterns) bool`.
pub fn matches_any(s: &str, patterns: &[String]) -> bool {
    match get_or_compile_joined_regex(patterns) {
        Some(re) => re.is_match(s),
        None => false,
    }
}

/// Go `findMatch(s, pattern) string`.
pub fn find_match(s: &str, pattern: &str) -> String {
    match get_or_compile_joined_regex(std::slice::from_ref(&pattern.to_string())) {
        Some(re) => re.find(s),
        None => String::new(),
    }
}

/// Go `containsAny(s, terms) bool`.
///
/// **Substitution (flagged):** Go calls the EXTERNAL `github.com/rrethy/
/// ahocorasick` here (`CompileStrings` + `FindAllString`), while `detect` uses
/// the bespoke `internal/ahocorasick`. This port uses the ported internal
/// matcher for both. The contract `containsAny` needs is "does any term occur",
/// and both matchers answer that identically — so one fewer dependency, at the
/// cost of not being the same package. Early-aborts on the first hit rather
/// than collecting every match, since only emptiness is inspected.
pub fn contains_any(s: &str, terms: &[String]) -> bool {
    let Some(trie) = get_or_build_trie(terms) else {
        return false;
    };
    let haystack = s.to_lowercase();
    let mut found = false;
    trie.visit(&haystack, |_, _, _| {
        found = true;
        false // stop at the first match
    });
    found
}

/// Go `shannonEntropy(s) float64`.
///
/// **Byte-based, deliberately.** Go indexes `s[i]` over a `[256]float64`
/// frequency table — that is BYTES, not runes, so a multi-byte character
/// contributes several distinct symbols. Reproducing that exactly matters: the
/// catalogue compares the result against thresholds on 363 rules, so a
/// rune-based version would silently shift every one of them.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let mut freq = [0f64; 256];
    for &b in bytes {
        freq[b as usize] += 1.0;
    }
    let n = bytes.len() as f64;
    let mut h = 0f64;
    for f in freq {
        if f > 0.0 {
            let p = f / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Supplies BPE tokenization. Go's `tokenizerProvider` may be nil, in which case
/// `tokenRatio` returns 0 and `failsTokenEfficiency` returns false — so this is
/// an injection seam, and the tokenizer itself lands with M13.
pub trait Tokenizer: Send + Sync {
    /// Go `tiktoken.Encode(text, nil, nil)` — the token count is all that is used.
    fn encode_len(&self, text: &str) -> usize;
}

/// Go `newlineReplacer = strings.NewReplacer("\n", "", "\r", "")`.
fn strip_newlines(s: &str) -> String {
    s.chars().filter(|c| *c != '\n' && *c != '\r').collect()
}

/// Go `calculateTokenRatio` — returns `(analyzed, ratio, ok)`.
///
/// The `< 20` length guard is on BYTES (Go `len`), and strips newlines only for
/// short secrets.
pub fn calculate_token_ratio(tk: &dyn Tokenizer, secret: &str) -> (String, f64, bool) {
    let mut analyzed = secret.to_string();
    if analyzed.len() < 20 && analyzed.chars().any(|c| c == '\n' || c == '\r') {
        analyzed = strip_newlines(&analyzed);
    }
    let n = tk.encode_len(&analyzed);
    if n == 0 {
        return (analyzed, 0.0, false);
    }
    let ratio = analyzed.len() as f64 / n as f64;
    (analyzed, ratio, true)
}

/// Go `failsTokenEfficiency(tke, secret) bool`.
///
/// The threshold ladder is subtle and ported verbatim: the default is 2.5; a
/// secret shorter than 12 bytes drops to 2.1, but goes BACK to 2.5 when no
/// 4-letter dictionary word is present.
pub fn fails_token_efficiency(tk: &dyn Tokenizer, secret: &str) -> bool {
    let (analyzed, ratio, ok) = calculate_token_ratio(tk, secret);
    if !ok {
        return false;
    }
    if !words::has_match_in_list(&analyzed, 5).is_empty() {
        return true;
    }
    let mut threshold = 2.5;
    if analyzed.len() < 12 {
        threshold = 2.1;
        if words::has_match_in_list(&analyzed, 4).is_empty() {
            threshold = 2.5;
        }
    }
    ratio >= threshold
}

/// Go `(*runtimeBindings).setConfidence` — validates and writes the confidence
/// attribute, returning the value it stored.
pub fn set_confidence(
    attrs: &mut std::collections::BTreeMap<String, String>,
    value: &str,
) -> Result<String, String> {
    if !confidence::valid(value) {
        return Err(format!(
            "filter.setConfidence: invalid confidence \"{value}\" (expected low, medium, or high)"
        ));
    }
    attrs.insert(confidence::ATTRIBUTE.to_string(), value.to_string());
    Ok(value.to_string())
}

#[cfg(test)]
pub(crate) fn clear_caches_for_test() {
    regex_cache().lock().expect("regex cache").clear();
    trie_cache().lock().expect("trie cache").clear();
}
