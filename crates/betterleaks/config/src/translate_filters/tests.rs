//! Tests for allowlist → filter-expression translation.
//!
//! The generated expression IS the suppression. Getting it wrong in one
//! direction hides live secrets; in the other it buries them in noise. The
//! prefilter/filter split gets particular attention because putting a
//! finding-level check into the prefilter would evaluate it before any finding
//! exists.

use super::*;

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_allowlist_that_checks_nothing_is_rejected() {
    assert!(Allowlist::default().validate().is_err());
    let a = Allowlist {
        paths: v(&["testdata"]),
        ..Default::default()
    };
    assert!(a.validate().is_ok());
}

/// Paths are ATTRIBUTE-level, so they land in the prefilter and can suppress a
/// fragment before any regex runs.
#[test]
fn paths_become_a_prefilter_expression() {
    let a = Allowlist {
        paths: v(&["(^|/)cmd/generate/config/rules", r".*test\.go", "testdata"]),
        ..Default::default()
    };
    let (pre, fil) = translate_allowlist(&a);
    assert!(fil.is_empty(), "a path check needs no finding");
    assert_eq!(pre.len(), 1);
    let e = &pre[0];
    assert!(e.starts_with("matchesAny(attributes[\"path\"], ["), "got {e}");
    assert!(e.contains("`(^|/)cmd/generate/config/rules`"));
    assert!(e.contains(r"`.*test\.go`"), "a regex keeps its backslashes verbatim");
    assert!(e.contains("`testdata`"));
}

#[test]
fn commits_become_a_prefilter_membership_test() {
    let a = Allowlist {
        commits: v(&["ABC123", "def456"]),
        ..Default::default()
    };
    let (pre, fil) = translate_allowlist(&a);
    assert!(fil.is_empty());
    assert_eq!(pre.len(), 1);
    assert!(pre[0].starts_with("attributes[\"git.sha\"] in ["), "got {}", pre[0]);
    assert!(
        pre[0].contains("\"abc123\""),
        "commits are lower-cased — they are compared case-insensitively: {}",
        pre[0]
    );
}

/// Regexes and stopwords need a FINDING, so they must not reach the prefilter.
#[test]
fn regexes_and_stopwords_become_filter_expressions() {
    let a = Allowlist {
        regexes: v(&["^AKIA[0-9A-Z]{16}$"]),
        stopwords: v(&["EXAMPLE", "dummy"]),
        ..Default::default()
    };
    let (pre, fil) = translate_allowlist(&a);
    assert!(pre.is_empty(), "a finding-level check must never be a prefilter");
    assert_eq!(fil.len(), 1);
    assert!(fil[0].contains("matchesAny(finding[\"secret\"]"));
    assert!(fil[0].contains("containsAny(finding[\"secret\"]"));
    assert!(fil[0].contains("\"example\""), "stopwords are lower-cased");
    assert!(fil[0].starts_with('(') && fil[0].contains(" || "), "OR-ed: {}", fil[0]);
}

#[test]
fn regex_target_selects_the_field() {
    let a = Allowlist {
        regexes: v(&["foo"]),
        regex_target: "line".to_string(),
        ..Default::default()
    };
    let (_, fil) = translate_allowlist(&a);
    assert!(fil[0].contains("finding[\"line\"]"), "got {}", fil[0]);
}

/// **The AND split is the subtle one.** With AND semantics every condition must
/// hold, so the path half cannot be promoted to the prefilter — doing so would
/// suppress fragments whose OTHER conditions never matched.
#[test]
fn an_and_allowlist_stays_entirely_in_the_filter() {
    let a = Allowlist {
        match_condition: MatchCondition::And,
        paths: v(&["testdata"]),
        stopwords: v(&["example"]),
        ..Default::default()
    };
    let (pre, fil) = translate_allowlist(&a);
    assert!(pre.is_empty(), "an AND allowlist must NOT split into the prefilter");
    assert_eq!(fil.len(), 1);
    assert!(fil[0].contains(" && "), "conditions are AND-ed: {}", fil[0]);
    assert!(fil[0].contains("attributes[\"path\"]"));
    assert!(fil[0].contains("containsAny"));

    // The same allowlist with OR semantics DOES split — the contrast is the point.
    let or = Allowlist { match_condition: MatchCondition::Or, ..a };
    let (pre2, fil2) = translate_allowlist(&or);
    assert_eq!(pre2.len(), 1);
    assert_eq!(fil2.len(), 1);
}

#[test]
fn compose_ors_the_skip_predicates_with_the_user_expression() {
    assert_eq!(compose_filters(&[], ""), "");
    assert_eq!(compose_filters(&v(&["a"]), ""), "a");
    assert_eq!(compose_filters(&[], "user"), "user");
    assert_eq!(compose_filters(&v(&["a", "b"]), "user"), "a\n|| b\n|| user");
}

/// A `let`-bound user expression is parenthesised so the OR cannot capture the
/// binding. Only when there is something to OR with — Go does not add stray
/// parentheses otherwise.
#[test]
fn a_let_expression_is_parenthesised_only_when_needed() {
    let user = "let x = 1;\nx > 0";
    assert_eq!(
        compose_filters(&v(&["skip"]), user),
        format!("skip\n|| ({user})")
    );
    assert_eq!(compose_filters(&[], user), user, "nothing to OR with, no parens");

    // Leading comments do not hide a `let`.
    let commented = "// why\nlet x = 1;\nx > 0";
    assert!(compose_filters(&v(&["skip"]), commented).contains("|| (// why"));
    // ...and a non-let expression is never parenthesised.
    assert_eq!(compose_filters(&v(&["skip"]), "a > 1"), "skip\n|| a > 1");
}

#[test]
fn regex_literals_prefer_backticks_but_fall_back_when_they_cannot() {
    let a = Allowlist {
        paths: v(&["has`backtick"]),
        ..Default::default()
    };
    let (pre, _) = translate_allowlist(&a);
    assert!(pre[0].contains("\"has`backtick\""), "quoted instead: {}", pre[0]);
}

#[test]
fn a_single_element_list_stays_inline_and_several_go_one_per_line() {
    let one = Allowlist { paths: v(&["a"]), ..Default::default() };
    assert!(translate_allowlist(&one).0[0].contains("[`a`]"));

    let many = Allowlist { paths: v(&["a", "b"]), ..Default::default() };
    let e = &translate_allowlist(&many).0[0];
    assert!(e.contains("[\n  `a`,\n  `b`\n]"), "got {e}");
}

#[test]
fn duplicate_commits_and_stopwords_are_collapsed() {
    let a = Allowlist {
        commits: v(&["ABC", "abc", " abc "]),
        stopwords: v(&["Example", "EXAMPLE"]),
        ..Default::default()
    };
    let n = a.normalized();
    assert_eq!(n.commits, v(&["abc"]));
    assert_eq!(n.stopwords, v(&["example"]));
}

/// The exact config that betterleaks' own repository ships, and the reason this
/// module exists. Its translation must produce a prefilter that suppresses the
/// generator, test files and testdata.
#[test]
fn the_real_betterleaks_dev_config_translates_as_expected() {
    let a = Allowlist {
        paths: v(&["(^|/)cmd/generate/config/rules", r".*test\.go", "testdata"]),
        ..Default::default()
    };
    let (pre, fil) = translate_allowlist(&a);
    assert!(fil.is_empty());
    let expr = compose_filters(&pre, "");
    assert_eq!(
        expr,
        "matchesAny(attributes[\"path\"], [\n  `(^|/)cmd/generate/config/rules`,\n  `.*test\\.go`,\n  `testdata`\n])"
    );
}
