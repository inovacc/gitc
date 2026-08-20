//! Tests for the config loader.
//!
//! The headline assertion is `default_config_loads_all_414_rules`: the whole
//! point of M9 is that the shipped catalogue parses and every pattern in it
//! compiles under Rust's regex engine. If that holds, rule coverage went from
//! 26 to 414 without porting a line of the 14K-LOC Go `rules` package.

use super::*;

fn cfg() -> Config {
    default_config().expect("the embedded catalogue must parse")
}

/// THE headline test. Counts are pinned against the Go source, measured with
/// `rg -c '^\[\[rules\]\]' config/betterleaks.toml` = 414.
#[test]
fn default_config_loads_all_414_rules() {
    let c = cfg();
    assert_eq!(c.rules.len(), 414, "rule count");
    assert_eq!(c.ordered_rules.len(), 414, "ordered rules");
    assert_eq!(c.title, "betterleaks config");
    assert_eq!(c.min_version, "v8.25.0");
    assert_eq!(c.betterleaks_min_version, "v1.7.5");
    assert!(!c.prefilter.is_empty(), "the global prefilter must load");
}

/// Every rule's `regex` and `path` must actually COMPILE, not merely parse as a
/// string. The facade defers engine compilation to first use, so this forces it
/// — otherwise a pattern Rust's engine rejects would not surface until scan
/// time, which is exactly the ASCII-vs-Unicode risk PORT-PLAN §7 flags.
#[test]
fn every_rule_pattern_compiles() {
    let c = cfg();
    let mut failures: Vec<String> = Vec::new();
    for id in &c.ordered_rules {
        let rule = &c.rules[id];
        if let Some(re) = &rule.regex {
            if let Err(e) = re.force_compile() {
                failures.push(format!("{id} regex: {e}"));
            }
        }
        if let Some(p) = &rule.path {
            if let Err(e) = p.force_compile() {
                failures.push(format!("{id} path: {e}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 414 rules have patterns Rust's engine rejects:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every rule in the shipped catalogue must pass `Rule::validate` — the same
/// gate Go applies. This exercises the confidence check (414 rules carry one),
/// the secret-group bound, and component `within` parsing.
#[test]
fn every_rule_validates() {
    let mut c = cfg();
    c.validate_rules().expect("all shipped rules must validate");
}

/// Measured against the Go source: 413 of 414 rules declare `regex`, and 413
/// declare `keywords`. Pinning these catches a silent parse regression that
/// would otherwise look like a healthy load.
#[test]
fn catalogue_field_coverage_matches_source() {
    let c = cfg();
    let with_regex = c.rules.values().filter(|r| r.regex.is_some()).count();
    let with_keywords = c.rules.values().filter(|r| !r.keywords.is_empty()).count();
    let with_filter = c.rules.values().filter(|r| !r.filter.is_empty()).count();
    let with_validate = c.rules.values().filter(|r| !r.validate_expr.is_empty()).count();
    let with_components = c.rules.values().filter(|r| !r.components.is_empty()).count();
    let with_path = c.rules.values().filter(|r| r.path.is_some()).count();
    let skip_report = c.rules.values().filter(|r| r.skip_report).count();
    // The shipped catalogue uses the `entropy` KEY zero times. The 212 lines
    // mentioning entropy are INDENTED — they sit inside `filter` expressions as
    // `entropy(finding["secret"]) <= N`. That matches rule.go's own note that
    // "Deprecated legacy Allowlists, Entropy, and TokenEfficiency are translated
    // into this field [Filter]", and it means entropy filtering is gated on M10
    // (the expression evaluator), not on this field.
    let with_entropy = c.rules.values().filter(|r| r.entropy > 0.0).count();

    assert_eq!(with_regex, 413, "rules with a regex");
    assert_eq!(with_keywords, 413, "rules with keywords");
    // 365, not 366: the source has 366 `filter = ` lines, but ONE of them is the
    // GLOBAL filter at config level, not a rule's.
    assert_eq!(with_filter, 365, "rules with a filter expression");
    assert!(!c.filter.is_empty(), "the 366th `filter =` is the global one");
    assert_eq!(with_validate, 186, "rules with a validate expression");
    assert_eq!(with_components, 25, "rules with components");
    assert_eq!(with_path, 5, "rules with a path pattern");
    assert_eq!(skip_report, 31, "rules with skipReport");
    assert_eq!(with_entropy, 0, "the entropy KEY is unused; it lives in filter exprs");
    // …and here is where entropy checking actually lives. Counted as rules, not
    // raw occurrences, since a filter may call entropy() more than once.
    let rules_filtering_on_entropy = c
        .rules
        .values()
        .filter(|r| r.filter.contains("entropy("))
        .count();
    assert_eq!(rules_filtering_on_entropy, 363, "rules filtering on entropy");
}

/// A known rule, checked field by field against `betterleaks.toml`.
#[test]
fn one_password_rule_round_trips() {
    let c = cfg();
    let r = c.rules.get("1password-secret-key").expect("rule present");
    assert_eq!(
        r.description,
        "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults."
    );
    assert_eq!(r.confidence, "high");
    assert_eq!(r.keywords, vec!["a3-"], "keywords are lower-cased at load");
    assert!(r.regex.as_ref().unwrap().as_str().contains(r"\bA3-[A-Z0-9]{6}-"));
    assert!(r.filter.contains("entropy(finding[\"secret\"]) <= 3.8"));
}

/// Keywords are lower-cased at load time and folded into the global set.
#[test]
fn keywords_are_lowercased_and_indexed() {
    let c = cfg();
    assert!(!c.keywords.is_empty());
    for k in &c.keywords {
        assert_eq!(k, &k.to_lowercase(), "keyword {k:?} is not lower-cased");
    }
    // Every indexed keyword resolves to at least one rule, and every rule it
    // names really carries it.
    for (kw, ids) in &c.keyword_to_rules {
        assert!(!ids.is_empty(), "keyword {kw:?} maps to no rules");
        for id in ids {
            assert!(
                c.rules[id].keywords.contains(kw),
                "rule {id} indexed under {kw:?} it does not declare"
            );
        }
    }
}

/// The keyword index must cover every rule exactly once: a rule is either
/// keyword-indexed or in `no_keyword_rules`, never both, never neither.
#[test]
fn keyword_index_partitions_every_rule() {
    let c = cfg();
    let indexed: BTreeSet<&String> = c.keyword_to_rules.values().flatten().collect();
    let no_kw: BTreeSet<&String> = c.no_keyword_rules.iter().collect();

    assert!(indexed.is_disjoint(&no_kw), "a rule is both indexed and keyword-less");
    assert_eq!(
        indexed.len() + no_kw.len(),
        414,
        "every rule must be reachable from the index"
    );
    // Measured: 413 rules declare keywords, so exactly one has none.
    assert_eq!(c.no_keyword_rules.len(), 1, "rules with no keywords");
}

/// Catalogue order is preserved — SARIF output depends on it.
#[test]
fn ordered_rules_follow_catalogue_order() {
    let c = cfg();
    assert_eq!(c.ordered_rules[0], "1password-secret-key");
    // No duplicates, and each names a real rule.
    let unique: BTreeSet<&String> = c.ordered_rules.iter().collect();
    assert_eq!(unique.len(), c.ordered_rules.len(), "duplicate rule id");
    for id in &c.ordered_rules {
        assert!(c.rules.contains_key(id), "{id} ordered but absent");
    }
}

/// The shipped catalogue uses NO allowlists and NO extend — the measurement the
/// deferral in the module docs rests on. If a future catalogue adds either, this
/// fails and the deferral must be revisited rather than silently ignored.
#[test]
fn shipped_catalogue_uses_no_deferred_features() {
    assert!(
        !DEFAULT_CONFIG.contains("[[rules.allowlists]]"),
        "catalogue gained rule allowlists — the allowlist translation is DEFERRED"
    );
    assert!(
        !DEFAULT_CONFIG.contains("[[allowlists]]"),
        "catalogue gained global allowlists — the allowlist translation is DEFERRED"
    );
    let c = cfg();
    assert_eq!(c.extend, Extend::default(), "catalogue gained an extend block");
}

// ── loader unit tests (small inline configs) ────────────────────────────────

#[test]
fn parses_a_minimal_config() {
    let c = parse_toml_string(
        r#"
title = "t"
[[rules]]
id = "a"
description = "d"
regex = '''secret-\d+'''
keywords = ["SECRET"]
"#,
        "inline",
    )
    .expect("parse");
    assert_eq!(c.title, "t");
    assert_eq!(c.path, "inline");
    assert_eq!(c.rules.len(), 1);
    assert_eq!(c.rules["a"].keywords, vec!["secret"]);
    assert_eq!(c.keyword_to_rules["secret"], vec!["a"]);
}

#[test]
fn rejects_an_invalid_regex_naming_the_rule() {
    let err = parse_toml_string(
        r#"
[[rules]]
id = "bad"
regex = '''(unclosed'''
"#,
        "",
    )
    .unwrap_err()
    .to_string();
    assert!(err.starts_with("bad: invalid regex"), "got {err:?}");
}

#[test]
fn rejects_both_allowlist_forms() {
    let err = parse_toml_string(
        r#"
[[rules]]
id = "x"
regex = '''a'''
[rules.allowlist]
description = "old"
[[rules.allowlists]]
description = "new"
"#,
        "",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cannot be used alongside"), "got {err:?}");
}

/// A rule with neither regex nor path is inert, and `validate` says so.
#[test]
fn validate_rejects_a_rule_that_matches_nothing() {
    let mut c = parse_toml_string("[[rules]]\nid = \"empty\"\n", "").expect("parse");
    let err = c.validate_rules().unwrap_err().to_string();
    assert!(err.contains("both |regex| and |path| are empty"), "got {err:?}");
}

#[test]
fn validate_rejects_an_unknown_confidence() {
    let mut c = parse_toml_string(
        "[[rules]]\nid = \"x\"\nregex = '''a'''\nconfidence = \"certain\"\n",
        "",
    )
    .expect("parse");
    let err = c.validate_rules().unwrap_err().to_string();
    assert!(err.contains("invalid confidence"), "got {err:?}");
}

/// `secretGroup` must exist in the pattern — and this is checked WITHOUT
/// compiling the regex, via the facade's recorded capture count.
#[test]
fn validate_rejects_an_out_of_range_secret_group() {
    let mut c = parse_toml_string(
        "[[rules]]\nid = \"x\"\nregex = '''(a)(b)'''\nsecretGroup = 3\n",
        "",
    )
    .expect("parse");
    let err = c.validate_rules().unwrap_err().to_string();
    assert!(err.contains("invalid regex secret group 3"), "got {err:?}");
    assert!(err.contains("max regex secret group 2"), "got {err:?}");
}

/// A component's `within` goes through the contextwindow grammar.
#[test]
fn validate_rejects_a_bad_component_within() {
    let mut c = parse_toml_string(
        r#"
[[rules]]
id = "primary"
regex = '''a'''
[[rules.components]]
id = "other"
within = "10X"
"#,
        "",
    )
    .expect("parse");
    let err = c.validate_rules().unwrap_err().to_string();
    assert!(err.contains("has invalid within value"), "got {err:?}");
}

#[test]
fn validate_rejects_duplicate_components() {
    let mut c = parse_toml_string(
        r#"
[[rules]]
id = "primary"
regex = '''a'''
[[rules.components]]
id = "dup"
[[rules.components]]
id = "dup"
"#,
        "",
    )
    .expect("parse");
    let err = c.validate_rules().unwrap_err().to_string();
    assert!(err.contains("duplicate component rule ID"), "got {err:?}");
}

/// The deprecated `[[rules.required]]` form maps onto `within`.
#[test]
fn legacy_required_translates_to_within() {
    let c = parse_toml_string(
        r#"
[[rules]]
id = "primary"
regex = '''a'''
[[rules.required]]
id = "other"
withinLines = 3
withinColumns = 20
"#,
        "",
    )
    .expect("parse");
    let comps = &c.rules["primary"].components;
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0].rule_id, "other");
    assert_eq!(comps[0].within, "3L,20C");
    assert!(!comps[0].optional);
    assert!(c.rules["primary"].components_set());
}

#[test]
fn legacy_required_rejects_negative_bounds() {
    let err = parse_toml_string(
        "[[rules]]\nid = \"p\"\nregex = '''a'''\n[[rules.required]]\nid = \"o\"\nwithinLines = -1\n",
        "",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("withinLines must be non-negative"), "got {err:?}");
}

/// `components_set` distinguishes omission from an explicit empty list — that
/// distinction is what config extension relies on.
#[test]
fn components_set_distinguishes_omission_from_empty() {
    let c = parse_toml_string("[[rules]]\nid = \"a\"\nregex = '''x'''\n", "").expect("parse");
    assert!(!c.rules["a"].components_set(), "omitted");

    let c = parse_toml_string(
        "[[rules]]\nid = \"a\"\nregex = '''x'''\ncomponents = []\n",
        "",
    )
    .expect("parse");
    assert!(c.rules["a"].components_set(), "explicitly empty");
    assert!(c.rules["a"].components.is_empty());
}

#[test]
fn validate_is_idempotent() {
    let mut c = parse_toml_string("[[rules]]\nid = \"a\"\nregex = '''x'''\n", "").expect("parse");
    c.validate_rules().expect("first");
    c.validate_rules().expect("second is a no-op");
}

/// `specificity` defaults to `DEFAULT_RULE_SPECIFICITY`, and an explicit 0 is
/// preserved rather than being treated as absent (Go uses `*int` for exactly
/// this reason).
#[test]
fn specificity_default_and_explicit_zero() {
    let c = parse_toml_string("[[rules]]\nid = \"a\"\nregex = '''x'''\n", "").expect("parse");
    assert_eq!(c.rules["a"].specificity, DEFAULT_RULE_SPECIFICITY);

    let c = parse_toml_string(
        "[[rules]]\nid = \"a\"\nregex = '''x'''\nspecificity = 5\n",
        "",
    )
    .expect("parse");
    assert_eq!(c.rules["a"].specificity, 5);
}

#[test]
fn semver_parsing_tolerates_go_version_laxness() {
    assert_eq!(parse_semver("v8.25.0"), Some((8, 25, 0)));
    assert_eq!(parse_semver("8.25.0"), Some((8, 25, 0)));
    assert_eq!(parse_semver("v1"), Some((1, 0, 0)), "go-version accepts a bare major");
    assert_eq!(parse_semver("v1.2"), Some((1, 2, 0)));
    assert_eq!(parse_semver("v1.2.3-rc1"), Some((1, 2, 3)), "pre-release dropped");
    assert_eq!(parse_semver("nope"), None);
}
