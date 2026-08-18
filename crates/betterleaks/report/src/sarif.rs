//! SARIF report emitter (faithful port of Go `report/sarif.go`).
//!
//! Go uses `encoding/json` with `SetIndent("", " ")`. The Go test compares the
//! output BYTE-FOR-BYTE (string equality, after line-ending normalization), so the
//! structs are declared in Go's exact field order and serde produces the same
//! single-space-indented JSON (serde serializes struct fields in declaration
//! order, matching Go). Trailing newline added to match `Encode`.

use std::io::{self, Write};

use serde::Serialize;

use crate::Finding;

const DRIVER: &str = "betterleaks";
const VERSION: &str = "v8.0.0";

/// Emits findings as SARIF 2.1.0 (Go `SarifReporter`).
pub struct SarifReporter {
    /// Rules to advertise in the SARIF driver (Go `[]config.Rule`).
    pub ordered_rules: Vec<config::Rule>,
}

impl SarifReporter {
    /// Write `findings` as SARIF JSON to `w` (Go `(*SarifReporter).Write`).
    pub fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        let sarif = Sarif {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: self.get_runs(findings),
        };
        let mut ser = serde_json::Serializer::with_formatter(
            &mut *w,
            serde_json::ser::PrettyFormatter::with_indent(b" "),
        );
        sarif.serialize(&mut ser).map_err(io::Error::other)?;
        w.write_all(b"\n") // `Encode` appends a trailing newline.
    }

    fn get_runs(&self, findings: &[Finding]) -> Vec<Runs> {
        vec![Runs {
            tool: self.get_tool(),
            results: get_results(findings),
        }]
    }

    fn get_tool(&self) -> Tool {
        // Empty rules serialize as `[]` (Rust Vec is never null), which is exactly
        // what Go's `hasEmptyRules` workaround forces.
        Tool {
            driver: Driver {
                name: DRIVER.to_string(),
                semantic_version: VERSION.to_string(),
                information_uri: "https://github.com/gitleaks/gitleaks".to_string(),
                rules: self.get_rules(),
            },
        }
    }

    fn get_rules(&self) -> Vec<Rules> {
        self.ordered_rules
            .iter()
            .map(|rule| Rules {
                id: rule.rule_id.clone(),
                description: ShortDescription {
                    text: rule.description.clone(),
                },
            })
            .collect()
    }
}

fn message_text(f: &Finding) -> String {
    if f.commit.is_empty() {
        format!("{} has detected secret for file {}.", f.rule_id, f.file)
    } else {
        format!(
            "{} has detected secret for file {} at commit {}.",
            f.rule_id, f.file, f.commit
        )
    }
}

fn get_results(findings: &[Finding]) -> Vec<Results> {
    findings
        .iter()
        .map(|f| Results {
            message: Message {
                text: message_text(f),
            },
            rule_id: f.rule_id.clone(),
            locations: get_location(f),
            partial_finger_prints: PartialFingerPrints {
                commit_sha: f.commit.clone(),
                email: f.email.clone(),
                author: f.author.clone(),
                date: f.date.clone(),
                commit_message: f.message.clone(),
            },
            properties: Properties {
                tags: f.tags.clone(),
            },
        })
        .collect()
}

fn get_location(f: &Finding) -> Vec<Locations> {
    let uri = if f.symlink_file.is_empty() {
        f.file.clone()
    } else {
        f.symlink_file.clone()
    };
    let context_region = if f.match_context.is_empty() {
        None
    } else {
        Some(ContextRegion {
            snippet: Snippet {
                text: f.match_context.clone(),
            },
        })
    };
    vec![Locations {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation { uri },
            region: Region {
                start_line: f.start_line,
                start_column: f.start_column,
                end_line: f.end_line,
                end_column: f.end_column,
                snippet: Snippet {
                    text: f.secret.clone(),
                },
            },
            context_region,
        },
    }]
}

// ---- SARIF wire types (field order = Go struct order = JSON key order) ----

#[derive(Serialize)]
struct Sarif {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<Runs>,
}

#[derive(Serialize)]
struct Runs {
    tool: Tool,
    results: Vec<Results>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: String,
    #[serde(rename = "semanticVersion")]
    semantic_version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<Rules>,
}

#[derive(Serialize)]
struct Rules {
    id: String,
    #[serde(rename = "shortDescription")]
    description: ShortDescription,
}

#[derive(Serialize)]
struct ShortDescription {
    text: String,
}

#[derive(Serialize)]
struct Results {
    message: Message,
    #[serde(rename = "ruleId")]
    rule_id: String,
    locations: Vec<Locations>,
    #[serde(rename = "partialFingerprints")]
    partial_finger_prints: PartialFingerPrints,
    properties: Properties,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Locations {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
    #[serde(rename = "contextRegion", skip_serializing_if = "Option::is_none")]
    context_region: Option<ContextRegion>,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: i64,
    #[serde(rename = "startColumn")]
    start_column: i64,
    #[serde(rename = "endLine")]
    end_line: i64,
    #[serde(rename = "endColumn")]
    end_column: i64,
    snippet: Snippet,
}

#[derive(Serialize)]
struct Snippet {
    text: String,
}

#[derive(Serialize)]
struct ContextRegion {
    snippet: Snippet,
}

#[derive(Serialize)]
struct PartialFingerPrints {
    #[serde(rename = "commitSha")]
    commit_sha: String,
    email: String,
    author: String,
    date: String,
    #[serde(rename = "commitMessage")]
    commit_message: String,
}

#[derive(Serialize)]
struct Properties {
    tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;

    // Golden captured verbatim from the Go fixture
    // `testdata/expected/report/sarif_simple.sarif`.
    const GOLDEN_SIMPLE: &str = r#"{
 "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
 "version": "2.1.0",
 "runs": [
  {
   "tool": {
    "driver": {
     "name": "betterleaks",
     "semanticVersion": "v8.0.0",
     "informationUri": "https://github.com/gitleaks/gitleaks",
     "rules": [
      {
       "id": "aws-access-key",
       "shortDescription": {
        "text": "AWS Access Key"
       }
      },
      {
       "id": "pypi",
       "shortDescription": {
        "text": "PyPI upload token"
       }
      }
     ]
    }
   },
   "results": [
    {
     "message": {
      "text": "test-rule has detected secret for file auth.py at commit 0000000000000000."
     },
     "ruleId": "test-rule",
     "locations": [
      {
       "physicalLocation": {
        "artifactLocation": {
         "uri": "auth.py"
        },
        "region": {
         "startLine": 1,
         "startColumn": 1,
         "endLine": 2,
         "endColumn": 2,
         "snippet": {
          "text": "a secret"
         }
        }
       }
      }
     ],
     "partialFingerprints": {
      "commitSha": "0000000000000000",
      "email": "johndoe@gmail.com",
      "author": "John Doe",
      "date": "10-19-2003",
      "commitMessage": "opps"
     },
     "properties": {
      "tags": [
       "tag1",
       "tag2",
       "tag3"
      ]
     }
    }
   ]
  }
 ]
}
"#;

    fn norm(s: &str) -> String {
        s.replace("\r\n", "\n").replace('\r', "\n")
    }

    #[test]
    fn write_sarif_simple() {
        let reporter = SarifReporter {
            ordered_rules: vec![
                config::Rule::new("aws-access-key", "AWS Access Key"),
                config::Rule::new("pypi", "PyPI upload token"),
            ],
        };
        let finding = Finding {
            rule_id: "test-rule".to_string(),
            description: "A test rule".to_string(),
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
            tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        reporter.write(&mut buf, std::slice::from_ref(&finding)).unwrap();
        let got = norm(&String::from_utf8(buf).unwrap());
        assert_eq!(got, norm(GOLDEN_SIMPLE));
    }

    // Differential golden captured from the Go source for the paths the simple test
    // misses: EMPTY ordered rules (`"rules": []`), a SymlinkFile (uri = symlink),
    // MatchContext (`contextRegion` present), and an empty Commit (the no-commit
    // message branch + empty partial-fingerprint fields). Byte-for-byte.
    const GOLDEN_PATHS: &str = r#"{
 "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
 "version": "2.1.0",
 "runs": [
  {
   "tool": {
    "driver": {
     "name": "betterleaks",
     "semanticVersion": "v8.0.0",
     "informationUri": "https://github.com/gitleaks/gitleaks",
     "rules": []
    }
   },
   "results": [
    {
     "message": {
      "text": "r has detected secret for file f.py."
     },
     "ruleId": "r",
     "locations": [
      {
       "physicalLocation": {
        "artifactLocation": {
         "uri": "link.py"
        },
        "region": {
         "startLine": 3,
         "startColumn": 5,
         "endLine": 4,
         "endColumn": 6,
         "snippet": {
          "text": "s"
         }
        },
        "contextRegion": {
         "snippet": {
          "text": "ctx"
         }
        }
       }
      }
     ],
     "partialFingerprints": {
      "commitSha": "",
      "email": "",
      "author": "",
      "date": "",
      "commitMessage": ""
     },
     "properties": {
      "tags": [
       "x"
      ]
     }
    }
   ]
  }
 ]
}
"#;

    #[test]
    fn diff_sarif_paths_match_go() {
        let reporter = SarifReporter {
            ordered_rules: Vec::new(),
        };
        let finding = Finding {
            rule_id: "r".to_string(),
            description: "d".to_string(),
            file: "f.py".to_string(),
            symlink_file: "link.py".to_string(),
            match_context: "ctx".to_string(),
            secret: "s".to_string(),
            start_line: 3,
            end_line: 4,
            start_column: 5,
            end_column: 6,
            tags: vec!["x".to_string()],
            ..Default::default()
        };
        let mut buf = Vec::new();
        reporter.write(&mut buf, std::slice::from_ref(&finding)).unwrap();
        let got = norm(&String::from_utf8(buf).unwrap());
        assert_eq!(got, norm(GOLDEN_PATHS));
    }
}
