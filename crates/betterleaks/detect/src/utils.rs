//! Port of the parts of Go `detect/utils.go` the core detection path uses.

use report::Finding;

/// Go `detect.shannonEntropy`.
///
/// **⚠ THIS IS NOT THE SAME FUNCTION AS `exprruntime::shannon_entropy`, and the
/// difference is deliberate — it is Go's.**
///
/// ```go
/// charCounts := make(map[rune]int)          // counts RUNES
/// for _, char := range data { charCounts[char]++ }
/// invLength := 1.0 / float64(len(data))     // divides by BYTES
/// ```
///
/// So frequencies are rune counts over a BYTE length. For ASCII the two agree;
/// for multi-byte input the "probabilities" do not sum to 1 and the result is
/// lower than a true rune entropy. Meanwhile `bindings_filter.go` computes a
/// pure BYTE entropy over a `[256]float64` table.
///
/// Two different entropies coexist in the source: this one populates
/// `Finding.Entropy` (what reports show), the other backs the `entropy()`
/// filter function (what 363 rules threshold on). A port that "cleaned this up"
/// into one function would silently change both. Ported quirk-for-quirk.
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for ch in data.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    // Go: 1.0 / float64(len(data)) — len() is BYTES.
    let inv_length = 1.0 / data.len() as f64;
    let mut entropy = 0.0;
    for count in counts.values() {
        let freq = *count as f64 * inv_length;
        entropy -= freq * freq.log2();
    }
    entropy
}

/// Go `findNewlineIndices` — `[start, start+1]` pairs for each `\n`.
pub fn find_newline_indices(s: &str) -> Vec<[usize; 2]> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    for (i, &c) in b.iter().enumerate() {
        if c == b'\n' {
            out.push([i, i + 1]);
        }
    }
    out
}

/// Go `detect.allowSignatures` — comment tags that suppress a finding.
///
/// Order matters and is Go's: `betterleaks:allow` is checked first (preferred),
/// `gitleaks:allow` second for backwards compatibility.
pub const ALLOW_SIGNATURES: [&str; 2] = ["betterleaks:allow", "gitleaks:allow"];

/// Go `containsAllowSignature`.
pub fn contains_allow_signature(line: &str) -> bool {
    ALLOW_SIGNATURES.iter().any(|sig| line.contains(sig))
}

/// Go `samePath` — compares two paths for the self-scan guard.
pub fn same_path(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let norm = |p: &str| p.replace('\\', "/");
    norm(a) == norm(b)
}

/// Go `isSuppressedByHigherSpecificityFinding`.
///
/// A finding is dropped when another finding on the SAME line, from a DIFFERENT
/// rule with HIGHER specificity, contains this one's secret. That is how the
/// generic catch-all yields to a specific provider rule.
pub fn is_suppressed_by_higher_specificity_finding(f: &Finding, findings: &[Finding]) -> bool {
    for other in findings {
        if f.start_line == other.start_line
            && f.attributes.get(sources::ATTR_GIT_SHA)
                == other.attributes.get(sources::ATTR_GIT_SHA)
            && f.rule_id != other.rule_id
            && other.secret.contains(&f.secret)
            && other.rule_specificity > f.rule_specificity
        {
            return true;
        }
        for set in &other.component_sets {
            for comp in &set.components {
                if f.start_line == comp.start_line
                    && f.rule_id != comp.rule_id
                    && comp.secret.contains(&f.secret)
                    && comp.rule_specificity > f.rule_specificity
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Go `filter(findings)` — dedupe.
///
/// Two passes, in Go's order: a finding already surfaced as a COMPONENT of a
/// composite finding is dropped, then specificity suppression is applied.
pub fn filter(findings: Vec<Finding>) -> Vec<Finding> {
    let mut component_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &findings {
        for set in &f.component_sets {
            for comp in &set.components {
                component_set.insert(format!("{}:{}", comp.start_line, comp.secret));
            }
        }
    }

    let mut out = Vec::with_capacity(findings.len());
    for f in &findings {
        let key = format!("{}:{}", f.start_line, f.secret);
        if component_set.contains(&key) {
            continue;
        }
        if is_suppressed_by_higher_specificity_finding(f, &findings) {
            continue;
        }
        out.push(f.clone());
    }
    out
}

/// Mask a secret for display — the lensr gate reports findings this way.
///
/// **lensr-local extension, not upstream.** Keeps the first 4 characters and
/// replaces the rest with `*`, so a report is actionable without carrying the
/// credential. Retained from the pre-M13 engine because the gate's output format
/// and its audit journal both depend on it.
pub fn mask_secret(secret: &str) -> String {
    let keep = 4.min(secret.chars().count());
    let head: String = secret.chars().take(keep).collect();
    let stars = "*".repeat(secret.chars().count().saturating_sub(keep));
    format!("{head}{stars}")
}

/// [`mask_secret`] applied to a finding's secret.
pub fn masked(f: &Finding) -> String {
    mask_secret(&f.secret)
}
