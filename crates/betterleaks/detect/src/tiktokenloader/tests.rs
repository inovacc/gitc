//! Token counts PRINTED BY GO, from a program driving the real
//! `tiktoken.GetEncoding("cl100k_base")` through betterleaks' own loader.
//!
//! These are the numbers that decide 121 filter expressions. If the vocabulary
//! or the split pattern drifted, the counts would move, the ratios would move,
//! and findings would appear or vanish with no other visible cause — so they
//! are pinned against Go rather than against this implementation's own output.

use super::*;
use exprruntime::Tokenizer;

fn tk() -> &'static Cl100kTokenizer {
    Cl100kTokenizer::shared().expect("the embedded cl100k_base asset must load")
}

#[test]
fn token_counts_match_go() {
    // These three are token-count fixtures: the counts below were measured
    // against THESE exact strings, so they are reconstructed byte for byte
    // rather than regenerated (see the `testkeys` crate).
    let aws = testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37");
    let slack = testkeys::reveal("1a0a0c1648435e56555e451a4c5c43595a574a475753434c5c425d575246124f170116120c0d10190909191a0a021d17121f065b031d");
    let ghp = testkeys::reveal("050d042b54442f52045f416b465c41175d5c484127524345551154565958471a3500424353274d12");
    let cases: &[(usize, &str)] = &[
        (0, ""),
        (1, "hello"),
        (2, "hello world"),
        // The point of the whole mechanism: a high-entropy secret costs many
        // tokens for few characters...
        (16, aws.as_str()),
        (19, slack.as_str()),
        (25, ghp.as_str()),
        (15, "aB3$xY9!zQ7#mN2%"),
        (11, "deadbeefcafebabe0123456789abcdef"),
        // ...while ordinary English is cheap, which is what separates them.
        (9, "the quick brown fox jumps over the lazy dog"),
        (1, "password"),
        (4, "correct horse battery staple"),
        (4, "clé—π"),
        (5, "a\nb\r\nc"),
    ];
    for (want, text) in cases {
        assert_eq!(tk().encode_len(text), *want, "encode_len({text:?})");
    }
}

/// The vocabulary is the thing that must not drift. cl100k_base has 100,256
/// ranks; a short read or a skipped line would change token counts everywhere
/// and look like nothing at all.
#[test]
fn the_whole_vocabulary_loads() {
    let ranks = load_tiktoken_bpe().expect("the asset must decode");
    assert_eq!(ranks.len(), 100_256, "cl100k_base rank count");
    // Spot-check the two ends of the table.
    assert_eq!(ranks.get(b"!".as_slice()), Some(&0));
    assert!(ranks.contains_key(b" the".as_slice()));
}

/// The ratio is what the filters actually read. A secret must come out BELOW
/// the efficiency threshold and prose above it — if that inverted, every filter
/// using it would flip.
#[test]
fn the_ratio_separates_secrets_from_prose() {
    let t = tk();
    let (_, secret_ratio, ok) =
        exprruntime::calculate_token_ratio(t, &testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37"));
    assert!(ok);
    let (_, prose_ratio, ok) =
        exprruntime::calculate_token_ratio(t, "the quick brown fox jumps over the lazy dog");
    assert!(ok);
    assert!(
        secret_ratio < prose_ratio,
        "a secret must tokenize WORSE than prose: {secret_ratio} vs {prose_ratio}"
    );
    // 20 bytes over 16 tokens.
    assert!((secret_ratio - 1.25).abs() < 1e-9, "{secret_ratio}");
}

/// An empty string yields no tokens, and the ratio helper reports "not ok"
/// rather than dividing by zero.
#[test]
fn an_empty_secret_has_no_ratio() {
    let (analyzed, ratio, ok) = exprruntime::calculate_token_ratio(tk(), "");
    assert_eq!(analyzed, "");
    assert_eq!(ratio, 0.0);
    assert!(!ok);
}

/// `shared()` is built once — the asset is 775 KB compressed and roughly 100k
/// entries expanded, so rebuilding it per fragment would dominate a scan.
#[test]
fn the_tokenizer_is_built_once() {
    let a = Cl100kTokenizer::shared().unwrap() as *const _;
    let b = Cl100kTokenizer::shared().unwrap() as *const _;
    assert_eq!(a, b);
}


