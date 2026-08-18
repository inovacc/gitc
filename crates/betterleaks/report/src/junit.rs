//! JUnit XML report emitter (faithful port of Go `report/junit.go`).
//!
//! Go uses `encoding/xml`; Rust std has no XML, so this uses `quick-xml` (a
//! sanctioned serialization-format lib). Each `<failure>`'s character data is the
//! JSON-marshaled `Finding` (tab-indented) — reusing the crate's `Finding` serde
//! serialization, exactly as Go's `getData` calls `json.MarshalIndent`.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::Finding;

/// `<testsuites>` root (Go `TestSuites`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "testsuites")]
pub struct TestSuites {
    #[serde(rename = "testsuite", default)]
    pub testsuites: Vec<TestSuite>,
}

/// `<testsuite>` (Go `TestSuite`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TestSuite {
    #[serde(rename = "@failures")]
    pub failures: String,
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@tests")]
    pub tests: String,
    #[serde(rename = "@time")]
    pub time: String,
    #[serde(rename = "testcase", default)]
    pub testcases: Vec<TestCase>,
}

/// `<testcase>` (Go `TestCase`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TestCase {
    #[serde(rename = "@classname")]
    pub classname: String,
    #[serde(rename = "@file")]
    pub file: String,
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@time")]
    pub time: String,
    pub failure: Failure,
}

/// `<failure>` (Go `Failure`); `data` is the `,chardata` JSON payload.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Failure {
    #[serde(rename = "@message")]
    pub message: String,
    #[serde(rename = "@type")]
    pub r#type: String,
    #[serde(rename = "$text", default)]
    pub data: String,
}

/// Emits findings as JUnit XML (Go `JunitReporter`).
pub struct JunitReporter;

impl JunitReporter {
    /// Write `findings` as JUnit XML to `w` (Go `(*JunitReporter).Write`).
    pub fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        let suites = TestSuites {
            testsuites: get_test_suites(findings),
        };
        // `xml.Header`
        w.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
        let mut xml = String::new();
        let mut ser = quick_xml::se::Serializer::new(&mut xml);
        ser.indent('\t', 1);
        suites.serialize(ser).map_err(io::Error::other)?;
        w.write_all(xml.as_bytes())
    }
}

fn get_test_suites(findings: &[Finding]) -> Vec<TestSuite> {
    vec![TestSuite {
        failures: findings.len().to_string(),
        name: "betterleaks".to_string(),
        tests: findings.len().to_string(),
        testcases: get_test_cases(findings),
        time: String::new(),
    }]
}

fn get_test_cases(findings: &[Finding]) -> Vec<TestCase> {
    findings
        .iter()
        .map(|f| TestCase {
            classname: f.description.clone(),
            failure: get_failure(f),
            file: f.file.clone(),
            name: get_message(f),
            time: String::new(),
        })
        .collect()
}

fn get_failure(f: &Finding) -> Failure {
    Failure {
        data: get_data(f),
        message: get_message(f),
        r#type: f.description.clone(),
    }
}

/// `json.MarshalIndent(f, "", "\t")` — reuses the `Finding` serde serialization.
fn get_data(f: &Finding) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut buf,
        serde_json::ser::PrettyFormatter::with_indent(b"\t"),
    );
    // Go's getData logs + returns "" on error; serialization here does not error.
    if f.serialize(&mut ser).is_err() {
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

fn get_message(f: &Finding) -> String {
    if f.commit.is_empty() {
        format!(
            "{} has detected a secret in file {}, line {}.",
            f.rule_id, f.file, f.start_line
        )
    } else {
        format!(
            "{} has detected a secret in file {}, line {}, at commit {}.",
            f.rule_id, f.file, f.start_line, f.commit
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;
    use serde_json::Value;

    // Goldens captured verbatim from the Go fixtures
    // `testdata/expected/report/junit_{simple,empty}.xml`.
    const GOLDEN_SIMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
	<testsuite failures="2" name="betterleaks" tests="2" time="">
		<testcase classname="Test Rule" file="auth.py" name="test-rule has detected a secret in file auth.py, line 1, at commit 0000000000000000." time="">
			<failure message="test-rule has detected a secret in file auth.py, line 1, at commit 0000000000000000." type="Test Rule">{&#xA;&#x9;&#34;RuleID&#34;: &#34;test-rule&#34;,&#xA;&#x9;&#34;Description&#34;: &#34;Test Rule&#34;,&#xA;&#x9;&#34;StartLine&#34;: 1,&#xA;&#x9;&#34;EndLine&#34;: 2,&#xA;&#x9;&#34;StartColumn&#34;: 1,&#xA;&#x9;&#34;EndColumn&#34;: 2,&#xA;&#x9;&#34;Match&#34;: &#34;line containing secret&#34;,&#xA;&#x9;&#34;Secret&#34;: &#34;a secret&#34;,&#xA;&#x9;&#34;File&#34;: &#34;auth.py&#34;,&#xA;&#x9;&#34;SymlinkFile&#34;: &#34;&#34;,&#xA;&#x9;&#34;Commit&#34;: &#34;0000000000000000&#34;,&#xA;&#x9;&#34;Entropy&#34;: 0,&#xA;&#x9;&#34;Author&#34;: &#34;John Doe&#34;,&#xA;&#x9;&#34;Email&#34;: &#34;johndoe@gmail.com&#34;,&#xA;&#x9;&#34;Date&#34;: &#34;10-19-2003&#34;,&#xA;&#x9;&#34;Message&#34;: &#34;opps&#34;,&#xA;&#x9;&#34;Tags&#34;: [],&#xA;&#x9;&#34;Fingerprint&#34;: &#34;&#34;&#xA;}</failure>
		</testcase>
		<testcase classname="Test Rule" file="auth.py" name="test-rule has detected a secret in file auth.py, line 2." time="">
			<failure message="test-rule has detected a secret in file auth.py, line 2." type="Test Rule">{&#xA;&#x9;&#34;RuleID&#34;: &#34;test-rule&#34;,&#xA;&#x9;&#34;Description&#34;: &#34;Test Rule&#34;,&#xA;&#x9;&#34;StartLine&#34;: 2,&#xA;&#x9;&#34;EndLine&#34;: 3,&#xA;&#x9;&#34;StartColumn&#34;: 1,&#xA;&#x9;&#34;EndColumn&#34;: 2,&#xA;&#x9;&#34;Match&#34;: &#34;line containing secret&#34;,&#xA;&#x9;&#34;Secret&#34;: &#34;a secret&#34;,&#xA;&#x9;&#34;File&#34;: &#34;auth.py&#34;,&#xA;&#x9;&#34;SymlinkFile&#34;: &#34;&#34;,&#xA;&#x9;&#34;Commit&#34;: &#34;&#34;,&#xA;&#x9;&#34;Entropy&#34;: 0,&#xA;&#x9;&#34;Author&#34;: &#34;&#34;,&#xA;&#x9;&#34;Email&#34;: &#34;&#34;,&#xA;&#x9;&#34;Date&#34;: &#34;&#34;,&#xA;&#x9;&#34;Message&#34;: &#34;&#34;,&#xA;&#x9;&#34;Tags&#34;: [],&#xA;&#x9;&#34;Fingerprint&#34;: &#34;&#34;&#xA;}</failure>
		</testcase>
	</testsuite>
</testsuites>"#;

    const GOLDEN_EMPTY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
	<testsuite failures="0" name="betterleaks" tests="0" time=""></testsuite>
</testsuites>"#;

    /// Coerce every JSON number to `f64`, recursively (as the Go JSON tests do).
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

    /// Canonicalize each `Failure.data` JSON payload in place, mirroring the Go
    /// test's `normalizeJunitJSONPayloads` — so an int `0` and float `0.0` compare
    /// equal (Go coerces to float64 on `Unmarshal`).
    fn canonicalize(suites: &mut TestSuites) {
        for suite in &mut suites.testsuites {
            for tc in &mut suite.testcases {
                if tc.failure.data.is_empty() {
                    continue;
                }
                let v: Value = serde_json::from_str(&tc.failure.data).unwrap();
                tc.failure.data = serde_json::to_string(&normalize_numbers(&v)).unwrap();
            }
        }
    }

    fn findings() -> Vec<Finding> {
        vec![
            Finding {
                description: "Test Rule".to_string(),
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
            },
            Finding {
                description: "Test Rule".to_string(),
                rule_id: "test-rule".to_string(),
                r#match: "line containing secret".to_string(),
                secret: "a secret".to_string(),
                start_line: 2,
                end_line: 3,
                start_column: 1,
                end_column: 2,
                file: "auth.py".to_string(),
                tags: Vec::new(),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn write_junit_simple() {
        let mut buf = Vec::new();
        JunitReporter.write(&mut buf, &findings()).unwrap();

        let mut got: TestSuites = quick_xml::de::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let mut want: TestSuites = quick_xml::de::from_str(GOLDEN_SIMPLE).unwrap();
        canonicalize(&mut got);
        canonicalize(&mut want);
        assert_eq!(got, want);
    }

    #[test]
    fn write_junit_empty() {
        let mut buf = Vec::new();
        JunitReporter.write(&mut buf, &[]).unwrap();

        let got: TestSuites = quick_xml::de::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let want: TestSuites = quick_xml::de::from_str(GOLDEN_EMPTY).unwrap();
        assert_eq!(got, want);
    }
}
