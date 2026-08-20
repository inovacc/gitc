//! The two report bodies below were PRINTED BY THE GO BINARY, from a program
//! calling `detect.WriteRuleTimingsHuman` / `WriteRuleTimingsCSV` on this exact
//! timing set. They are pasted verbatim.
//!
//! Three details came from that run rather than from reading the source:
//! Go's `csv.Writer` ends records with a bare `\n` (the first draft used
//! `\r\n`); the averages truncate, so `1.5s / 9` renders `166.666666ms`; and
//! two rules with the SAME total are ordered by hits descending, which is why
//! `aws-access-token` precedes `generic-api-key`.

use super::*;

fn fixture() -> Vec<RuleTiming> {
    vec![
        RuleTiming {
            rule_id: "generic-api-key".into(),
            total: 1_500_000_000,
            hits: 4,
        },
        RuleTiming {
            rule_id: "aws-access-token".into(),
            total: 1_500_000_000,
            hits: 9,
        },
        RuleTiming {
            rule_id: "a-very-long-rule-id-that-widens-the-column".into(),
            total: 2_000_000_000,
            hits: 3,
        },
        RuleTiming {
            rule_id: "zero-hits".into(),
            total: 0,
            hits: 0,
        },
        RuleTiming {
            rule_id: "tiny".into(),
            total: 1_234,
            hits: 7,
        },
        RuleTiming {
            rule_id: "comma,in,id".into(),
            total: 5_000,
            hits: 1,
        },
    ]
}

const GO_HUMAN: &str = "\
Rule Timings

Rules timed: 6

Rule ID                                              Total      Hits         Average
a-very-long-rule-id-that-widens-the-column              2s         3    666.666666ms
aws-access-token                                      1.5s         9    166.666666ms
generic-api-key                                       1.5s         4           375ms
comma,in,id                                            5\u{b5}s         1             5\u{b5}s
tiny                                               1.234\u{b5}s         7           176ns
zero-hits                                               0s         0              0s
";

const GO_CSV: &str = "\
rule_id,total_duration_ns,total_duration,hits,avg_duration_ns,avg_duration
a-very-long-rule-id-that-widens-the-column,2000000000,2s,3,666666666,666.666666ms
aws-access-token,1500000000,1.5s,9,166666666,166.666666ms
generic-api-key,1500000000,1.5s,4,375000000,375ms
\"comma,in,id\",5000,5\u{b5}s,1,5000,5\u{b5}s
tiny,1234,1.234\u{b5}s,7,176,176ns
zero-hits,0,0s,0,0,0s
";

#[test]
fn human_report_is_byte_identical_to_go() {
    let mut out = Vec::new();
    write_rule_timings_human(&mut out, &fixture()).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), GO_HUMAN);
}

#[test]
fn csv_report_is_byte_identical_to_go() {
    let mut out = Vec::new();
    write_rule_timings_csv(&mut out, &fixture()).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), GO_CSV);
}

/// The column is as wide as the widest rule id — and never narrower than the
/// header, which is what a fixture of only short ids would fail to prove.
#[test]
fn the_id_column_never_shrinks_below_the_header() {
    let mut out = Vec::new();
    write_rule_timings_human(
        &mut out,
        &[RuleTiming {
            rule_id: "ab".into(),
            total: 1,
            hits: 1,
        }],
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let header = text.lines().nth(4).unwrap();
    assert!(
        header.starts_with("Rule ID  "),
        "header must keep its own width, got {header:?}"
    );
    assert!(text.contains("ab       "), "row padded to the header width");
}

/// Go's `Average` is integer division, and 0 hits is 0 rather than a panic.
#[test]
fn average_truncates_and_survives_zero_hits() {
    assert_eq!(
        RuleTiming {
            rule_id: "x".into(),
            total: 1_500_000_000,
            hits: 9
        }
        .average(),
        166_666_666
    );
    assert_eq!(
        RuleTiming {
            rule_id: "x".into(),
            total: 5,
            hits: 0
        }
        .average(),
        0
    );
}

/// Ordering: total desc, then hits desc, then id asc. The id tiebreak is what
/// makes the report reproducible — the collector is a hash map.
#[test]
fn ordering_is_total_then_hits_then_id() {
    let mut t = vec![
        RuleTiming {
            rule_id: "b".into(),
            total: 10,
            hits: 1,
        },
        RuleTiming {
            rule_id: "a".into(),
            total: 10,
            hits: 1,
        },
        RuleTiming {
            rule_id: "c".into(),
            total: 10,
            hits: 5,
        },
        RuleTiming {
            rule_id: "d".into(),
            total: 99,
            hits: 1,
        },
    ];
    sort_rule_timings(&mut t);
    let ids: Vec<&str> = t.iter().map(|x| x.rule_id.as_str()).collect();
    assert_eq!(ids, ["d", "c", "a", "b"]);
}

/// The collector accumulates rather than replacing, and ignores an empty id.
#[test]
fn collector_accumulates_and_ignores_an_empty_rule_id() {
    let c = RuleTimingCollector::new();
    c.record("r", 100);
    c.record("r", 250);
    c.record("", 999);
    let snap = c.snapshot();
    assert_eq!(snap.len(), 1, "the empty id must not create a row");
    assert_eq!(snap[0].total, 350);
    assert_eq!(snap[0].hits, 2);
}

/// Only the fields Go quotes get quoted, and a quote is doubled.
#[test]
fn csv_quoting_follows_go() {
    assert_eq!(csv_field("plain-id"), "plain-id");
    assert_eq!(csv_field(""), "");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field(" leading"), "\" leading\"");
    // The Postgres end-of-data marker, which Go special-cases.
    assert_eq!(csv_field(r"\."), "\"\\.\"");
}
