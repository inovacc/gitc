//! The two rendered documents below were PRINTED BY THE GO BINARY, from a
//! program calling `report.NewTemplateReporter` on `testdata/report/*.tmpl`
//! with these exact findings.
//!
//! Details that came from that run rather than from reading the source:
//! `Entropy` renders as `0` (not `0.0`) and `3.5`, because Go prints a float32
//! with `%v`; an empty `Tags` renders as `[]`, because `sub (len .Tags) 1` is
//! -1 and the range body never runs; and the parse error is worded
//! `error parsing file: template: custom:1: function "env" not defined`.

use super::*;

/// `testdata/report/markdown.tmpl`, verbatim.
const MARKDOWN_TMPL: &str = "| File | Line | Secret |\n|:-----|-----:|--------|\n{{ range . -}}\n| {{ .File }} | {{ .StartLine }} | {{ quote .Secret }} |\n{{ end -}}\n";

/// `testdata/report/jsonextra.tmpl`, verbatim.
const JSONEXTRA_TMPL: &str = r#"[{{ $lastFinding := (sub (len . ) 1) }}
{{- range $i, $finding := . }}{{with $finding}}
    {
        "Description": {{ quote .Description }},
        "StartLine": {{ .StartLine }},
        "EndLine": {{ .EndLine }},
        "StartColumn": {{ .StartColumn }},
        "EndColumn": {{ .EndColumn }},
        "Line": {{ quote .Line }},
        "Match": {{ quote .Match }},
        "Secret": {{ quote .Secret }},
        "File": "{{ .File }}",
        "SymlinkFile": {{ quote .SymlinkFile }},
        "Commit": {{ quote .Commit }},
        "Entropy": {{ .Entropy }},
        "Author": {{ quote .Author }},
        "Email": {{ quote .Email }},
        "Date": {{ quote .Date }},
        "Message": {{ quote .Message }},
        "Tags": [{{ $lastTag := (sub (len .Tags ) 1) }}{{ range $j, $tag := .Tags }}{{ quote . }}{{ if ne $j $lastTag }},{{ end }}{{ end }}],
        "RuleID": {{ quote .RuleID }},
        "Fingerprint": {{ quote .Fingerprint }}
    }{{ if ne $i $lastFinding }},{{ end }}
{{- end}}{{ end }}
]
"#;

fn fixture() -> Vec<Finding> {
    vec![
        Finding {
            rule_id: "test-rule".into(),
            description: "A test rule".into(),
            line: "whole line containing secret".into(),
            r#match: "line containing secret".into(),
            secret: "a secret".into(),
            start_line: 1,
            end_line: 2,
            start_column: 1,
            end_column: 2,
            message: "opps".into(),
            file: "auth.py".into(),
            commit: "0000000000000000".into(),
            author: "John Doe".into(),
            email: "johndoe@gmail.com".into(),
            date: "10-19-2003".into(),
            tags: vec!["tag1".into(), "tag2".into(), "tag3".into()],
            ..Default::default()
        },
        Finding {
            rule_id: "second-rule".into(),
            description: "has a \" quote and a \\ backslash".into(),
            line: "second line".into(),
            r#match: "m2".into(),
            secret: "s\"2".into(),
            start_line: 7,
            end_line: 7,
            start_column: 3,
            end_column: 9,
            file: "b.go".into(),
            entropy: 3.5,
            tags: Vec::new(),
            ..Default::default()
        },
    ]
}

fn render(tmpl: &str) -> String {
    let r = TemplateReporter::from_text(tmpl).expect("the fixture template must parse");
    let mut out = Vec::new();
    r.write(&mut out, &fixture()).expect("render");
    String::from_utf8(out).unwrap()
}

const GO_MARKDOWN: &str = "\
| File | Line | Secret |
|:-----|-----:|--------|
| auth.py | 1 | \"a secret\" |
| b.go | 7 | \"s\\\"2\" |
";

const GO_JSONEXTRA: &str = r#"[
    {
        "Description": "A test rule",
        "StartLine": 1,
        "EndLine": 2,
        "StartColumn": 1,
        "EndColumn": 2,
        "Line": "whole line containing secret",
        "Match": "line containing secret",
        "Secret": "a secret",
        "File": "auth.py",
        "SymlinkFile": "",
        "Commit": "0000000000000000",
        "Entropy": 0,
        "Author": "John Doe",
        "Email": "johndoe@gmail.com",
        "Date": "10-19-2003",
        "Message": "opps",
        "Tags": ["tag1","tag2","tag3"],
        "RuleID": "test-rule",
        "Fingerprint": ""
    },
    {
        "Description": "has a \" quote and a \\ backslash",
        "StartLine": 7,
        "EndLine": 7,
        "StartColumn": 3,
        "EndColumn": 9,
        "Line": "second line",
        "Match": "m2",
        "Secret": "s\"2",
        "File": "b.go",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 3.5,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": [],
        "RuleID": "second-rule",
        "Fingerprint": ""
    }
]
"#;

#[test]
fn markdown_fixture_matches_go() {
    assert_eq!(render(MARKDOWN_TMPL), GO_MARKDOWN);
}

/// The demanding one: variables, nested `range` with two indices, `with`,
/// `sub`, `len`, `ne`, `quote`, and both trim markers.
#[test]
fn jsonextra_fixture_matches_go() {
    let got = render(JSONEXTRA_TMPL);
    assert_eq!(got, GO_JSONEXTRA);
    // And it is real JSON — which is the whole point of a template that emits
    // JSON, and a check the byte comparison alone would not make.
    let parsed: serde_json::Value = serde_json::from_str(&got).expect("must be valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 2);
}

/// Go deletes these three from the func map. Their absence is the security
/// property: a template supplied by whoever controls CI config must not be able
/// to read the environment or make a DNS request.
#[test]
fn the_three_dangerous_functions_are_refused_by_name() {
    for (src, name) in [
        (r#"{{ env "S" }}"#, "env"),
        (r#"{{ expandenv "$S" }}"#, "expandenv"),
        (r#"{{ getHostByName "h" }}"#, "getHostByName"),
    ] {
        let err = TemplateReporter::from_text(src)
            .err()
            .unwrap_or_else(|| panic!("{name} must not be callable"));
        assert!(
            err.contains(&format!("function \"{name}\" not defined")),
            "Go's wording, quoted; got {err:?}"
        );
    }
}

/// Belt and braces: the func map itself must not carry them, whatever a future
/// richer sprig port might add.
#[test]
fn assert_dangerous_funcs_absent() {
    let r = TemplateReporter::from_text("hello").unwrap();
    for name in DANGEROUS_FUNCS {
        assert!(
            !r.template.funcs.contains_key(*name),
            "{name} must not be in the func map"
        );
    }
}

/// Go parses this one fine, so the port must too — `now` and `date` both have
/// to exist.
#[test]
fn now_piped_into_date_parses_as_it_does_in_go() {
    TemplateReporter::from_text(r#"{{ now | date "2006-01-02" }}"#)
        .expect("now | date must parse, as it does in Go");
}

/// An unsupported function fails at LOAD time, naming itself — the property
/// that makes a partial sprig port safe.
#[test]
fn an_unsupported_function_fails_loudly_at_parse() {
    let err = TemplateReporter::from_text(r#"{{ semverCompare "1.0" "2.0" }}"#).unwrap_err();
    assert!(
        err.contains("function \"semverCompare\" not defined"),
        "got {err:?}"
    );
}

#[test]
fn an_empty_path_is_rejected_as_in_go() {
    assert_eq!(
        TemplateReporter::new("").unwrap_err(),
        "template path cannot be empty"
    );
}

#[test]
fn a_missing_file_says_so() {
    let err = TemplateReporter::new("C:\\nope\\missing.tmpl").unwrap_err();
    assert!(err.starts_with("error reading file:"), "got {err:?}");
}

/// `sub a b` is a difference, not a fold. Reversed, every `sub (len .) 1`
/// index in a template would be wrong.
#[test]
fn sub_is_a_difference_not_a_fold() {
    assert_eq!(sub(&[Value::from(10), Value::from(3)]).unwrap(), Value::from(7));
    assert!(sub(&[Value::from(1)]).is_err(), "sub takes exactly two");
}

/// `quote` uses Go's `%q` escaping — a template emitting JSON depends on it.
#[test]
fn quote_escapes_the_way_go_does() {
    let q = |s: &str| match quote(&[Value::from(s)]).unwrap() {
        Value::String(s) => s,
        other => panic!("{other:?}"),
    };
    assert_eq!(q("plain"), "\"plain\"");
    assert_eq!(q("a\"b"), "\"a\\\"b\"");
    assert_eq!(q("a\\b"), "\"a\\\\b\"");
    assert_eq!(q("a\nb"), "\"a\\nb\"");
    assert_eq!(q("a\tb"), "\"a\\tb\"");
    assert_eq!(q("a\u{1}b"), "\"a\\x01b\"");
}

/// The Go reference layout, on a date whose every component is distinguishable.
/// 2003-10-19T04:05:06Z was a Sunday.
#[test]
fn date_formats_the_go_reference_layout() {
    // days from 1970-01-01 to 2003-10-19 = 12344; plus 04:05:06.
    let secs = 12_344 * 86_400 + 4 * 3600 + 5 * 60 + 6;
    let f = |layout: &str| format_go_layout(layout, secs);
    assert_eq!(f("2006-01-02"), "2003-10-19");
    assert_eq!(f("2006-01-02T15:04:05Z07:00"), "2003-10-19T04:05:06Z");
    assert_eq!(f("Mon Jan 2 15:04:05 MST 2006"), "Sun Oct 19 04:05:06 UTC 2003");
    assert_eq!(f("Monday, January 2, 2006"), "Sunday, October 19, 2003");
    assert_eq!(f("03:04 PM"), "04:05 AM");
    assert_eq!(f("06"), "03");
    // Literal text between tokens is copied through.
    assert_eq!(f("on 2006 at 15h"), "on 2003 at 04h");
}

/// `2006` must be tried before `2`, or a year renders as a day-of-month.
#[test]
fn the_year_token_wins_over_the_day_token() {
    assert_eq!(format_go_layout("2006", 0), "1970");
    assert_eq!(format_go_layout("2", 0), "1");
}

/// The civil-date maths, against dates chosen to break naive implementations.
#[test]
fn civil_from_days_handles_leap_years_and_the_epoch() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(-1), (1969, 12, 31));
    // 2000 is a leap year (divisible by 400); 1900 is not.
    assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    assert_eq!(civil_from_days(-25_508), (1900, 3, 1));
}

/// `date` takes sprig's `now` map as well as a bare Unix integer.
#[test]
fn date_accepts_both_a_now_map_and_a_bare_integer() {
    let mut m = std::collections::HashMap::new();
    m.insert("Unix".to_string(), Value::from(0));
    assert_eq!(
        date(&[Value::from("2006-01-02"), Value::Object(m)]).unwrap(),
        Value::from("1970-01-01")
    );
    assert_eq!(
        date(&[Value::from("2006-01-02"), Value::from(86_400)]).unwrap(),
        Value::from("1970-01-02")
    );
}

/// An empty findings list must still render — a report of nothing is a valid
/// report, and erroring here would fail every clean scan using this format.
#[test]
fn no_findings_still_renders() {
    let r = TemplateReporter::from_text(MARKDOWN_TMPL).unwrap();
    let mut out = Vec::new();
    r.write(&mut out, &[]).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "| File | Line | Secret |\n|:-----|-----:|--------|\n"
    );
}
