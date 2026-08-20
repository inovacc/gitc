//! Every expectation was PRINTED BY GO, from a program calling the real
//! `exprruntime.RewriteCELCompat` and `NeedsCELCompat`.
//!
//! Two of them corrected this port's first draft:
//!
//! * `x.?a.orValue(y.?b.orValue("z"))` → `x?.a.orValue((y?.b ?? "z"))` — the
//!   INNER call is rewritten and the outer is left in CEL spelling, because
//!   Go's pattern refuses an argument containing parentheses. A first-match-only
//!   implementation rewrote neither.
//! * `r.json.?data[0].?name` — the base scan must stop before the `.` that
//!   begins `.?`, which Go's regex reaches by backtracking.

use super::*;

fn go(input: &str) -> String {
    rewrite_cel_compat(input).unwrap_or_else(|e| panic!("{input:?}: {e}"))
}

#[test]
fn cel_bind_becomes_a_let() {
    assert_eq!(
        go(r#"cel.bind(r, http.get("https://x", {}), r.status == 200)"#),
        r#"let r = http.get("https://x", {}); r.status == 200"#
    );
}

/// Nested binds: the OUTER wrapper is stripped, the inner one keeps its
/// parentheses. That asymmetry is Go's and it matters — the inner `(let …)` is
/// an expression in a larger one.
#[test]
fn nested_binds_keep_the_inner_parentheses() {
    assert_eq!(
        go("cel.bind(a, 1, cel.bind(b, 2, a + b))"),
        "let a = 1; (let b = 2; a + b)"
    );
}

/// A comma inside a string or a map literal is not an argument separator.
#[test]
fn bind_argument_splitting_is_quote_and_bracket_aware() {
    assert_eq!(
        go(r#"cel.bind(r, http.get("a,b", {"k": "v,w"}), r.status)"#),
        r#"let r = http.get("a,b", {"k": "v,w"}); r.status"#
    );
}

#[test]
fn optional_field_and_or_value_become_coalesce() {
    assert_eq!(go(r#"finding.?secret.orValue("")"#), r#"(finding?.secret ?? "")"#);
}

/// The array form spans an index, which the general `.?` rule would leave in
/// the CEL spelling.
#[test]
fn the_optional_array_form_is_rewritten_whole() {
    assert_eq!(
        go(r#"r.json.?data[0].?name.orValue("none")"#),
        r#"(r.json?.data?.[0]?.name ?? "none")"#
    );
}

/// Go's `[^()]*` refuses an argument with parentheses, so a nested `orValue`
/// leaves the outer call in CEL spelling. Preserved rather than "improved":
/// rewriting it would change what the expression means relative to Go.
#[test]
fn a_nested_or_value_rewrites_only_the_inner_call() {
    assert_eq!(
        go(r#"x.?a.orValue(y.?b.orValue("z"))"#),
        r#"x?.a.orValue((y?.b ?? "z"))"#
    );
}

#[test]
fn optional_index_loses_its_question_mark() {
    assert_eq!(
        go(r#"components[?"aws-id"].secret"#),
        r#"components["aws-id"].secret"#
    );
}

/// A CEL raw string becomes a backtick string, which is the spelling the lexer
/// treats as escape-free.
#[test]
fn raw_strings_become_backticks() {
    assert_eq!(go(r#"r"""a\b\c""""#), "`a\\b\\c`");
}

/// `contains` becomes the OPERATOR; the other three become ordinary calls with
/// the receiver moved to the first argument.
#[test]
fn method_calls_move_the_receiver() {
    assert_eq!(
        go(r#"finding["secret"].contains("AKIA")"#),
        r#"(finding["secret"] contains "AKIA")"#
    );
    assert_eq!(go(r#"s.replace("a", "b")"#), r#"replace(s, "a", "b")"#);
    assert_eq!(go("s.substring(0, 5)"), "substring(s, 0, 5)");
    assert_eq!(go(r#"s.lastIndexOf(":")"#), r#"lastIndexOf(s, ":")"#);
}

#[test]
fn every_method_call_in_an_expression_is_rewritten() {
    assert_eq!(
        go(r#"finding["secret"].contains("a") && finding["match"].contains("b")"#),
        r#"(finding["secret"] contains "a") && (finding["match"] contains "b")"#
    );
}

/// `env(` is a WORD-BOUNDARY match, so `myenv(` is left alone. Getting that
/// wrong would rewrite an unrelated user function into an env read.
#[test]
fn the_env_alias_respects_word_boundaries() {
    assert_eq!(go(r#"env("GITHUB_TOKEN")"#), r#"env.get("GITHUB_TOKEN")"#);
    assert_eq!(go(r#"myenv("X")"#), r#"myenv("X")"#);
    assert!(!needs_cel_compat(r#"myenv("X")"#));
    assert!(needs_cel_compat(r#"env("X")"#));
}

#[test]
fn the_redundant_string_cast_is_dropped() {
    assert_eq!(go("string(time.now_unix())"), "time.now_unix()");
}

/// A whole-expression `(let …)` loses its wrapper — including when nothing else
/// needed rewriting, which is why `needs_cel_compat` is false here and the
/// output still differs.
#[test]
fn a_top_level_let_loses_its_parentheses() {
    assert_eq!(go("(let x = 1; x)"), "let x = 1; x");
    assert!(!needs_cel_compat("(let x = 1; x)"));
}

/// Plain expr syntax is left completely alone, and `needs_cel_compat` says so
/// first — the rewrite is never attempted on an expression that does not need
/// it.
#[test]
fn plain_expr_syntax_is_untouched() {
    let plain = r#"r.status == 200 ? "valid" : "invalid""#;
    assert!(!needs_cel_compat(plain));
    assert_eq!(go(plain), plain);
}

/// The rewritten forms must actually COMPILE — a rewrite that produces
/// something the parser rejects is worse than no rewrite.
#[test]
fn the_rewritten_expressions_compile() {
    for src in [
        r#"cel.bind(r, http.get("https://x", {}), r.status == 200 ? {"result": "valid"} : validate.unknown(r))"#,
        r#"finding.?secret.orValue("")"#,
        r#"finding["secret"].contains("AKIA")"#,
        r#"components[?"aws-id"].secret"#,
        r#"s.replace("a", "b")"#,
    ] {
        let rewritten = go(src);
        crate::compile(&rewritten)
            .unwrap_or_else(|e| panic!("{src:?} rewrote to {rewritten:?} which will not parse: {e:?}"));
    }
}

/// A malformed bind is an ERROR naming the problem, not a silent passthrough
/// that fails later with a confusing parse error.
#[test]
fn a_malformed_bind_is_refused_by_name() {
    let err = rewrite_cel_compat("cel.bind(a, 1)").unwrap_err();
    assert!(err.contains("expected 3 args, got 2"), "{err}");

    let err = rewrite_cel_compat("cel.bind( , 1, 2)").unwrap_err();
    assert!(err.contains("empty binding name"), "{err}");

    let err = rewrite_cel_compat("cel.bind(a, 1, 2").unwrap_err();
    assert!(err.contains("unmatched parenthesis"), "{err}");
}
