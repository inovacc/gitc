//! Tests for the filter expression runtime.
//!
//! The decisive one is `every_catalogue_filter_compiles`: if the grammar was
//! derived correctly from the corpus, all 367 shipped expressions parse. If it
//! was derived from a sample, this fails — which is exactly why PORT-PLAN
//! demanded the whole corpus.

use super::*;
use crate::bindings_filter as bf;
use crate::parser::parse;

// ── lexer / parser ──────────────────────────────────────────────────────────

#[test]
fn parses_the_canonical_entropy_filter() {
    let ast = parse(r#"entropy(finding["secret"]) < 3.5"#).expect("parse");
    match ast {
        Ast::Cmp(lhs, CmpOp::Lt, rhs) => {
            assert!(matches!(*lhs, Ast::Call(ref n, _) if n == "entropy"));
            assert_eq!(*rhs, Ast::Num(3.5));
        }
        other => panic!("unexpected AST: {other:?}"),
    }
}

#[test]
fn parses_the_namespaced_spelling() {
    // The catalogue uses BOTH `entropy(…)` and `filter.entropy(…)`.
    let a = parse(r#"entropy(finding["secret"]) <= 4.0"#).expect("bare");
    let b = parse(r#"filter.entropy(finding["secret"]) <= 4.0"#).expect("namespaced");
    assert_ne!(a, b, "the dotted path is preserved in the AST");
    let mut ctx = Context::with_secret("aaaa");
    assert_eq!(
        eval::eval(&a, &mut ctx).unwrap(),
        eval::eval(&b, &mut ctx).unwrap(),
        "…but they evaluate identically"
    );
}

/// Backtick raw strings are how the catalogue writes regexes — no escaping.
#[test]
fn lexes_backtick_raw_strings() {
    let ast = parse(r#"matchesAny(finding["secret"], [`\d+\.\d+`])"#).expect("parse");
    match ast {
        Ast::Call(name, args) => {
            assert_eq!(name, "matchesAny");
            assert_eq!(args[1], Ast::Array(vec![Ast::Str(r"\d+\.\d+".to_string())]));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn double_quoted_strings_process_escapes() {
    let ast = parse(r#"containsAny(finding["secret"], ["a\nb"])"#).expect("parse");
    match ast {
        Ast::Call(_, args) => assert_eq!(args[1], Ast::Array(vec![Ast::Str("a\nb".to_string())])),
        other => panic!("unexpected: {other:?}"),
    }
}

/// Multi-line arrays with a trailing comma — the prefilter's shape.
#[test]
fn parses_multiline_array_with_trailing_comma() {
    let ast = parse(
        r#"matchesAny(attributes["path"], [
  `a`,
  `b`,
])"#,
    )
    .expect("parse");
    match ast {
        Ast::Call(_, args) => match &args[1] {
            Ast::Array(items) => assert_eq!(items.len(), 2),
            other => panic!("unexpected: {other:?}"),
        },
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn or_is_left_associative_and_binds_looser_than_comparison() {
    let ast = parse("1 < 2 || 3 < 4").expect("parse");
    assert!(matches!(ast, Ast::Or(_, _)), "|| must be the root");
}

#[test]
fn comparison_does_not_chain() {
    assert!(parse("1 < 2 < 3").is_err(), "expr does not allow chained comparison");
}

#[test]
fn rejects_garbage() {
    assert!(parse("entropy(").is_err());
    assert!(parse("&& true").is_err());
    assert!(parse("`unterminated").is_err());
    assert!(parse("1 = 2").is_err(), "single '=' is not an operator");
}

// ── entropy ─────────────────────────────────────────────────────────────────

/// Exact, mathematically-checkable values. Go computes over BYTES with a
/// [256]float64 table, so these hold for both.
#[test]
fn shannon_entropy_exact_values() {
    assert_eq!(bf::shannon_entropy(""), 0.0);
    assert_eq!(bf::shannon_entropy("aaaa"), 0.0, "one symbol → 0 bits");
    assert_eq!(bf::shannon_entropy("ab"), 1.0, "two equally likely → 1 bit");
    assert_eq!(bf::shannon_entropy("abcd"), 2.0, "four equally likely → 2 bits");
    assert_eq!(bf::shannon_entropy("aabb"), 1.0);
}

/// The byte-vs-rune distinction is load-bearing: 363 rules compare entropy
/// against a threshold, so a rune-based version would shift every one of them.
/// "é" is ONE char but TWO bytes, so byte-entropy is 1.0 and rune-entropy would
/// be 0.0.
#[test]
fn shannon_entropy_is_byte_based_like_go() {
    assert_eq!("é".chars().count(), 1);
    assert_eq!("é".len(), 2);
    assert_eq!(
        bf::shannon_entropy("é"),
        1.0,
        "two DISTINCT bytes → 1 bit; a rune-based impl would say 0"
    );
}

// ── matchesAny / containsAny / findMatch ────────────────────────────────────

#[test]
fn matches_any_joins_patterns_with_alternation() {
    let pats = vec![r"^\d+$".to_string(), r"^[a-f]+$".to_string()];
    assert!(bf::matches_any("12345", &pats));
    assert!(bf::matches_any("abcdef", &pats));
    assert!(!bf::matches_any("hello!", &pats));
    assert!(!bf::matches_any("anything", &[]), "no patterns → false");
}

/// Each pattern is wrapped in `(?:…)` before joining, so a top-level `|` inside
/// one pattern cannot leak across the alternation boundary.
#[test]
fn matches_any_isolates_each_pattern() {
    let pats = vec!["^a|b$".to_string(), "^c$".to_string()];
    // Wrapped: (?:^a|b$)|(?:^c$) — "c" matches only via the third branch.
    assert!(bf::matches_any("c", &pats));
    assert!(bf::matches_any("a", &pats));
}

#[test]
fn contains_any_is_case_insensitive_both_ways() {
    let terms = vec!["EXAMPLE".to_string()];
    assert!(bf::contains_any("this is an example value", &terms), "term upper, haystack lower");
    assert!(bf::contains_any("THIS IS AN EXAMPLE", &terms));
    assert!(!bf::contains_any("nothing here", &terms));
    assert!(!bf::contains_any("anything", &[]), "no terms → false");
}

#[test]
fn find_match_returns_the_match_or_empty() {
    assert_eq!(bf::find_match("abc123def", r"\d+"), "123");
    assert_eq!(bf::find_match("abcdef", r"\d+"), "");
}

// ── caches ──────────────────────────────────────────────────────────────────

/// The trie cache is keyed by the SORTED term list, so two call sites listing
/// the same terms in different orders share one trie. Behaviour must be
/// identical either way.
#[test]
fn trie_cache_is_order_insensitive() {
    let a = vec!["alpha".to_string(), "beta".to_string()];
    let b = vec!["beta".to_string(), "alpha".to_string()];
    assert_eq!(bf::contains_any("xx beta xx", &a), bf::contains_any("xx beta xx", &b));
    assert!(bf::contains_any("xx alpha xx", &b));
}

/// The regex cache is keyed by the ORDERED list — order changes the joined
/// pattern, so it must not be shared.
#[test]
fn regex_cache_distinguishes_order() {
    let a = vec!["^a".to_string(), "b$".to_string()];
    let b = vec!["b$".to_string(), "^a".to_string()];
    let ra = bf::get_or_compile_joined_regex(&a).expect("compiled");
    let rb = bf::get_or_compile_joined_regex(&b).expect("compiled");
    assert_ne!(ra.as_str(), rb.as_str(), "different join order → different regex");
}

/// A pattern the engine rejects yields None rather than panicking, and the
/// failure is cached so it is not recompiled on every call.
#[test]
fn bad_pattern_is_none_not_panic() {
    let bad = vec!["(unclosed".to_string()];
    assert!(bf::get_or_compile_joined_regex(&bad).is_none());
    assert!(bf::get_or_compile_joined_regex(&bad).is_none(), "cached failure");
    assert!(!bf::matches_any("x", &bad));
}

// ── tokenizer seam ──────────────────────────────────────────────────────────

struct FakeTokenizer(usize);
impl Tokenizer for FakeTokenizer {
    fn encode_len(&self, _text: &str) -> usize {
        self.0
    }
}

/// Go's `tokenizerProvider` may be nil: `tokenRatio` → 0, `failsTokenEfficiency`
/// → false. That seam is what lets M10 land without a BPE dependency.
#[test]
fn absent_tokenizer_yields_zero_and_false() {
    let p = compile(r#"filter.tokenRatio(finding["secret"]) >= 2.5"#)
        .unwrap()
        .unwrap();
    let mut ctx = Context::with_secret("some-secret-value");
    assert!(ctx.tokenizer.is_none());
    assert!(!eval_bool(&p, &mut ctx).unwrap(), "ratio 0 is not >= 2.5");
}

#[test]
fn token_ratio_is_bytes_over_tokens() {
    let tk = FakeTokenizer(4);
    let (analyzed, ratio, ok) = bf::calculate_token_ratio(&tk, "abcdefgh");
    assert!(ok);
    assert_eq!(analyzed, "abcdefgh");
    assert_eq!(ratio, 2.0, "8 bytes / 4 tokens");
}

/// Newlines are stripped ONLY for secrets under 20 bytes — the guard is on
/// bytes, and it changes the ratio's numerator.
#[test]
fn short_secrets_have_newlines_stripped() {
    let tk = FakeTokenizer(2);
    let (analyzed, _, _) = bf::calculate_token_ratio(&tk, "ab\ncd");
    assert_eq!(analyzed, "abcd", "short → stripped");

    let long = "a".repeat(19) + "\n" + &"b".repeat(5);
    assert!(long.len() >= 20);
    let (analyzed, _, _) = bf::calculate_token_ratio(&tk, &long);
    assert!(analyzed.contains('\n'), "long → newline kept");
}

#[test]
fn zero_tokens_reports_not_ok() {
    let tk = FakeTokenizer(0);
    let (_, ratio, ok) = bf::calculate_token_ratio(&tk, "abc");
    assert!(!ok);
    assert_eq!(ratio, 0.0);
}

// ── evaluation ──────────────────────────────────────────────────────────────

fn eval_str(src: &str, secret: &str) -> bool {
    let p = compile(src).expect("compile").expect("non-empty");
    let mut ctx = Context::with_secret(secret);
    eval_bool(&p, &mut ctx).expect("eval")
}

#[test]
fn evaluates_a_real_catalogue_filter() {
    // 1password-secret-key's actual filter.
    let src = r#"entropy(finding["secret"]) <= 3.8"#;
    assert!(eval_str(src, "aaaaaaaa"), "low entropy → filtered");
    assert!(!eval_str(src, "A3-ZQ7X2M-K9WERT4YU-PL3NB-VC8XZ-QW2ER"), "high entropy → kept");
}

#[test]
fn or_short_circuits() {
    let src = r#"entropy(finding["secret"]) < 99.0 || matchesAny(finding["secret"], [`(unclosed`])"#;
    // The left side is true, so the invalid regex on the right is never reached.
    assert!(eval_str(src, "anything"));
}

#[test]
fn missing_finding_key_is_the_empty_string() {
    let p = compile(r#"entropy(finding["nope"]) == 0.0"#).unwrap().unwrap();
    let mut ctx = Context::with_secret("x");
    assert!(eval_bool(&p, &mut ctx).unwrap(), "absent key behaves like Go's zero value");
}

#[test]
fn empty_expression_compiles_to_none() {
    assert!(compile("").unwrap().is_none());
    assert!(compile("   \n  ").unwrap().is_none());
}

#[test]
fn non_boolean_result_is_an_error() {
    let p = compile(r#"entropy(finding["secret"])"#).unwrap().unwrap();
    let mut ctx = Context::with_secret("abc");
    assert!(matches!(eval_bool(&p, &mut ctx), Err(EvalError::NotBoolean(_))));
}

#[test]
fn unknown_function_is_an_error() {
    let p = compile("bogusFn(1)").unwrap().unwrap();
    let mut ctx = Context::new();
    assert!(matches!(
        eval::eval(p.ast(), &mut ctx),
        Err(EvalError::UnknownFunction(_))
    ));
}

#[test]
fn wrong_arity_is_an_error() {
    let p = compile("entropy()").unwrap().unwrap();
    let mut ctx = Context::new();
    assert!(matches!(eval::eval(p.ast(), &mut ctx), Err(EvalError::Arity { .. })));
}

/// `filter.setConfidence` writes into the attributes map and rejects an unknown
/// level, matching `bindings_filter.go`.
#[test]
fn set_confidence_writes_and_validates() {
    let mut attrs = std::collections::BTreeMap::new();
    assert_eq!(bf::set_confidence(&mut attrs, "high").unwrap(), "high");
    assert_eq!(attrs.get(confidence::ATTRIBUTE).map(String::as_str), Some("high"));
    let err = bf::set_confidence(&mut attrs, "certain").unwrap_err();
    assert!(err.contains("invalid confidence"), "got {err}");
}

// ── THE decisive test ───────────────────────────────────────────────────────

/// Every filter and prefilter expression in the shipped catalogue must COMPILE.
///
/// This is the test the grammar was derived for. 367 expressions, parsed from
/// the real 491 KB catalogue — not a sample.
#[test]
fn every_catalogue_filter_compiles() {
    let c = config::default_config().expect("catalogue parses");

    let mut sources: Vec<(String, String)> = Vec::new();
    if !c.prefilter.trim().is_empty() {
        sources.push(("<global prefilter>".to_string(), c.prefilter.clone()));
    }
    if !c.filter.trim().is_empty() {
        sources.push(("<global filter>".to_string(), c.filter.clone()));
    }
    for id in &c.ordered_rules {
        let f = &c.rules[id].filter;
        if !f.trim().is_empty() {
            sources.push((id.clone(), f.clone()));
        }
    }

    let mut failures: Vec<String> = Vec::new();
    for (id, src) in &sources {
        if let Err(e) = compile(src) {
            failures.push(format!("{id}: {} | {}", e.0, src.replace('\n', " ")));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} catalogue expressions failed to parse:\n{}",
        failures.len(),
        sources.len(),
        failures
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(sources.len(), 367, "expected the full corpus");
}

/// Compiling is not enough — the expressions must also RUN. Evaluate every one
/// against a representative secret and require a boolean out, with no unknown
/// function or arity error anywhere in the catalogue.
#[test]
fn every_catalogue_filter_evaluates_to_a_bool() {
    let c = config::default_config().expect("catalogue parses");
    let mut failures: Vec<String> = Vec::new();
    let mut evaluated = 0usize;

    for id in &c.ordered_rules {
        let src = &c.rules[id].filter;
        if src.trim().is_empty() {
            continue;
        }
        let Some(p) = compile(src).expect("already proven to parse") else {
            continue;
        };
        let mut ctx = Context::with_secret(&testkeys::aws(1));
        ctx.attributes.insert("path".to_string(), "src/main.rs".to_string());
        match eval_bool(&p, &mut ctx) {
            Ok(_) => evaluated += 1,
            Err(e) => failures.push(format!("{id}: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} filters failed to evaluate:\n{}",
        failures.len(),
        failures.iter().take(15).cloned().collect::<Vec<_>>().join("\n")
    );
    assert_eq!(evaluated, 365, "every rule filter evaluated");
}

/// The global prefilter is the one expression using `attributes`, and it decides
/// whether a whole fragment is skipped — so check it actually discriminates.
#[test]
fn global_prefilter_skips_known_noise_paths() {
    let c = config::default_config().expect("catalogue parses");
    let p = compile(&c.prefilter).expect("compile").expect("non-empty");

    let mut skip = |path: &str| -> bool {
        let mut ctx = Context::new();
        ctx.attributes.insert("path".to_string(), path.to_string());
        eval_bool(&p, &mut ctx).expect("eval")
    };

    assert!(skip("node_modules/left-pad/index.js"), "vendored js must be skipped");
    assert!(skip("go.sum"), "go.sum must be skipped");
    assert!(skip("assets/logo.png"), "images must be skipped");
    assert!(skip("package-lock.json"), "lockfiles must be skipped");
    assert!(!skip("src/main.rs"), "real source must NOT be skipped");
    assert!(!skip("internal/auth/token.go"), "real source must NOT be skipped");
}

