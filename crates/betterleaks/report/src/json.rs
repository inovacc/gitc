//! JSON report emitter (faithful port of Go `report/json.go`).
//!
//! Go's `JsonReporter.Write` is `json.NewEncoder(w).SetIndent("", " ").Encode`.
//! Rust std has no JSON, so this uses `serde_json` (the pack's sanctioned JSON
//! dep) with a single-space `PrettyFormatter` and a trailing newline, matching
//! Go's `Encode` byte output.

use std::io::{self, Write};

use serde::Serialize;

use crate::Finding;

/// Emits findings as an indented JSON array (Go `JsonReporter`).
pub struct JsonReporter;

impl JsonReporter {
    /// Write `findings` as JSON to `w` (Go `(*JsonReporter).Write`).
    pub fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        // Single-space indent = Go `SetIndent("", " ")`.
        let mut ser = serde_json::Serializer::with_formatter(
            &mut *w,
            serde_json::ser::PrettyFormatter::with_indent(b" "),
        );
        findings
            .serialize(&mut ser)
            .map_err(io::Error::other)?;
        // `Encode` appends a trailing newline.
        w.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ComponentFinding, ComponentSet, Finding, ValidationStatus};
    use serde_json::Value;

    // Golden captured verbatim from the Go source's fixture
    // `testdata/expected/report/json_simple.json`.
    const GOLDEN_SIMPLE: &str = r#"[
 {
  "RuleID": "test-rule",
  "Description": "",
  "StartLine": 1,
  "EndLine": 2,
  "StartColumn": 1,
  "EndColumn": 2,
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
  "Tags": [],
  "Fingerprint": ""
 }
]"#;

    /// Ports the Go test's `simpleFinding`.
    fn simple_finding() -> Finding {
        Finding {
            rule_id: "test-rule".to_string(),
            r#match: "line containing secret".to_string(),
            secret: "a secret".to_string(),
            start_line: 1,
            end_line: 2,
            start_column: 1,
            end_column: 2,
            message: "opps".to_string(),
            file: "auth.py".to_string(),
            commit: "0000000000000000".to_string(),
            author: "John Doe".to_string(),
            email: "johndoe@gmail.com".to_string(),
            date: "10-19-2003".to_string(),
            tags: Vec::new(),
            ..Default::default()
        }
    }

    /// Coerce every JSON number to `f64`, recursively. This replicates the Go
    /// test's comparison, which `json.Unmarshal`s both sides into `interface{}`
    /// (all numbers become `float64`). Without it, Go's `"Entropy": 0` (int) and
    /// serde's `0.0` (float) would be unequal `serde_json::Value`s even though
    /// they are the same number — a real Go-vs-serde number-representation
    /// difference, masked (as in Go) by float64-coercing before comparison.
    fn normalize_numbers(v: &Value) -> Value {
        match v {
            Value::Number(n) => Value::from(n.as_f64().unwrap_or(0.0)),
            Value::Array(a) => Value::Array(a.iter().map(normalize_numbers).collect()),
            Value::Object(o) => {
                Value::Object(o.iter().map(|(k, v)| (k.clone(), normalize_numbers(v))).collect())
            }
            other => other.clone(),
        }
    }

    #[test]
    fn write_json_simple() {
        let mut buf = Vec::new();
        JsonReporter
            .write(&mut buf, std::slice::from_ref(&simple_finding()))
            .unwrap();

        let got = normalize_numbers(&serde_json::from_slice(&buf).unwrap());
        let want = normalize_numbers(&serde_json::from_str(GOLDEN_SIMPLE).unwrap());
        assert_eq!(got, want);
    }

    #[test]
    fn write_json_empty() {
        let mut buf = Vec::new();
        JsonReporter.write(&mut buf, &[]).unwrap();
        let got: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(got, serde_json::json!([]));
    }

    // Ports Go `report_test.go` TestWriteStdout: JsonReporter writes non-empty
    // output for a finding.
    #[test]
    fn write_stdout_produces_output() {
        let finding = Finding {
            rule_id: "test-rule".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        JsonReporter
            .write(&mut buf, std::slice::from_ref(&finding))
            .unwrap();
        assert!(!buf.is_empty());
    }

    // Differential golden captured from the Go source (`json.Marshal`) for a RICH
    // finding — populating the omitempty + nested fields the Go test leaves empty:
    // MatchContext, CaptureGroups, Attributes, non-empty Tags, ComponentSets (with a
    // component + per-set validationStatus), ValidationStatus/Reason, and
    // ValidationMeta with heterogeneous `any` values (int 403, bool false). Pins the
    // omitempty behavior and the nested serialization shape byte-for-byte.
    //
    // RE-CAPTURED 2026-08-14 against source `6cf4f1a2` after upstream renamed the
    // `Required*` vocabulary to `Component*`. This is a WIRE change — the key is
    // now `ComponentSets` — and the new `Optional` field is emitted even when
    // false (Go declares it with no tag, so no omitempty) in second position.
    // Regenerated by marshalling the equivalent Finding through the Go source,
    // NOT by hand-editing the previous golden.
    const GOLDEN_RICH: &str = r#"[{"RuleID":"aws-key","Description":"AWS access key","StartLine":10,"EndLine":10,"StartColumn":5,"EndColumn":40,"Match":"AKIAIOSFODNN7EXAMPLE","Secret":"AKIAsecret","MatchContext":"ctx line here","CaptureGroups":{"key":"val"},"Attributes":{"path":"a.go"},"Tags":["t1","t2"],"ComponentSets":[{"components":[{"RuleID":"c1","Optional":false,"StartLine":1,"EndLine":1,"StartColumn":0,"EndColumn":0,"Match":"m1","Secret":"s1"}],"validationStatus":"valid"}],"ValidationStatus":"invalid","ValidationReason":"nope","ValidationMeta":{"code":403,"ok":false},"Fingerprint":"fp1","File":"a.go","SymlinkFile":"","Commit":"abc123","Entropy":3.5,"Author":"","Email":"","Date":"","Message":""}]"#;

    fn rich_finding() -> Finding {
        let mut capture_groups = std::collections::HashMap::new();
        capture_groups.insert("key".to_string(), "val".to_string());
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("path".to_string(), "a.go".to_string());
        let mut validation_meta = std::collections::HashMap::new();
        validation_meta.insert("code".to_string(), serde_json::json!(403));
        validation_meta.insert("ok".to_string(), serde_json::json!(false));

        Finding {
            rule_id: "aws-key".to_string(),
            description: "AWS access key".to_string(),
            start_line: 10,
            end_line: 10,
            start_column: 5,
            end_column: 40,
            r#match: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret: "AKIAsecret".to_string(),
            match_context: "ctx line here".to_string(),
            capture_groups,
            attributes,
            tags: vec!["t1".to_string(), "t2".to_string()],
            component_sets: vec![ComponentSet {
                components: vec![ComponentFinding {
                    rule_id: "c1".to_string(),
                    r#match: "m1".to_string(),
                    secret: "s1".to_string(),
                    start_line: 1,
                    end_line: 1,
                    ..Default::default()
                }],
                validation_status: ValidationStatus::VALID,
                ..Default::default()
            }],
            validation_status: ValidationStatus::INVALID,
            validation_reason: "nope".to_string(),
            validation_meta,
            fingerprint: "fp1".to_string(),
            file: "a.go".to_string(),
            commit: "abc123".to_string(),
            entropy: 3.5,
            ..Default::default()
        }
    }

    #[test]
    fn diff_rich_finding_matches_go() {
        let mut buf = Vec::new();
        JsonReporter
            .write(&mut buf, std::slice::from_ref(&rich_finding()))
            .unwrap();
        let got = normalize_numbers(&serde_json::from_slice(&buf).unwrap());
        let want = normalize_numbers(&serde_json::from_str(GOLDEN_RICH).unwrap());
        assert_eq!(got, want);
    }
}
