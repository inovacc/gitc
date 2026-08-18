//! `Finding` and its report-serialization shape (partial port of Go
//! `report/finding.go`).
//!
//! SCOPE: the STRUCT + its JSON serialization contract, PLUS the methods
//! `mask_secret` (package fn), `Finding::redact`, `Finding::build_component_sets`
//! (+ helper `cartesian_findings`), and `Finding::attr`. Still DEFERRED (not
//! ported): `SetFingerprint`, `ToExprMap`, `locateMatch`, `sortedMapKeys`,
//! `printPretty`, `SetAttr`/`SetAttributes`/`SyncDeprecatedSourceFields`/
//! `Attribute`. `Fragment` is a STUB — the full `sources.Fragment` is not ported;
//! the field is `omitempty` and always `None` in the current scope.
//!
//! JSON field-name fidelity: Go `encoding/json` uses the exact (PascalCase) struct
//! field name as the key when there is no tag, so every field carries an explicit
//! `#[serde(rename = "...")]`. `omitempty` → `skip_serializing_if`; `json:"-"` and
//! unexported fields → `#[serde(skip)]`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ValidationStatus;

/// `skip_serializing_if` for `ValidationStatus` fields tagged `omitempty`
/// (Go omits the zero value `""`).
fn is_status_none(s: &ValidationStatus) -> bool {
    s.as_str().is_empty()
}

/// Partial STUB for Go `sources.Fragment` — the full `sources` package is not
/// ported. Present only so `Finding.fragment` stays faithful; it is `omitempty`
/// and always `None`/omitted in the currently-ported scope (the JSON emitter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {}

/// A subset of `Finding` fields, used only for reporting (Go `ComponentFinding`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ComponentFinding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    /// Optional components are attached when found but do not gate the primary
    /// finding. Go declares `Optional bool` with NO tag, so it is always emitted
    /// (not `omitempty`) and sits second in the marshal order.
    #[serde(rename = "Optional")]
    pub optional: bool,
    #[serde(rename = "StartLine")]
    pub start_line: i64,
    #[serde(rename = "EndLine")]
    pub end_line: i64,
    #[serde(rename = "StartColumn")]
    pub start_column: i64,
    #[serde(rename = "EndColumn")]
    pub end_column: i64,
    /// Go `json:"-"`.
    #[serde(skip)]
    pub line: String,
    #[serde(rename = "Match")]
    pub r#match: String,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "CaptureGroups", skip_serializing_if = "HashMap::is_empty")]
    pub capture_groups: HashMap<String, String>,
    /// Go `json:"-"`.
    #[serde(skip)]
    pub rule_specificity: i64,
}

/// One combination of component findings (Go `ComponentSet`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ComponentSet {
    #[serde(rename = "components")]
    pub components: Vec<ComponentFinding>,
    #[serde(rename = "validationStatus", skip_serializing_if = "is_status_none")]
    pub validation_status: ValidationStatus,
    #[serde(rename = "validationReason", skip_serializing_if = "String::is_empty")]
    pub validation_reason: String,
}

/// A secret finding (Go `report.Finding`). Field order mirrors the Go struct; the
/// JSON key for each field is pinned to Go's exact serialized name.
// Deserialize so a previous JSON report can be read back as a BASELINE.
// serde(default) throughout, because a baseline written by an older version
// may lack a field this one knows about, and a baseline that fails to parse is
// a build that suddenly fails on findings it had already accepted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "StartLine")]
    pub start_line: i64,
    #[serde(rename = "EndLine")]
    pub end_line: i64,
    #[serde(rename = "StartColumn")]
    pub start_column: i64,
    #[serde(rename = "EndColumn")]
    pub end_column: i64,

    #[serde(rename = "Match")]
    pub r#match: String,
    #[serde(rename = "Secret")]
    pub secret: String,

    #[serde(rename = "MatchContext", skip_serializing_if = "String::is_empty")]
    pub match_context: String,

    /// Go `json:"-"`.
    #[serde(skip)]
    pub line: String,

    #[serde(rename = "CaptureGroups", skip_serializing_if = "HashMap::is_empty")]
    pub capture_groups: HashMap<String, String>,

    #[serde(rename = "Fragment", skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Fragment>,

    #[serde(rename = "Attributes", skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,

    #[serde(rename = "Tags")]
    pub tags: Vec<String>,

    /// Go `json:"-"`.
    #[serde(skip)]
    pub rule_specificity: i64,

    #[serde(rename = "ComponentSets", skip_serializing_if = "Vec::is_empty")]
    pub component_sets: Vec<ComponentSet>,

    #[serde(rename = "ValidationStatus", skip_serializing_if = "is_status_none")]
    pub validation_status: ValidationStatus,
    #[serde(rename = "ValidationReason", skip_serializing_if = "String::is_empty")]
    pub validation_reason: String,
    /// Go `map[string]any` → `serde_json::Value` (JSON-native `any` model).
    #[serde(rename = "ValidationMeta", skip_serializing_if = "HashMap::is_empty")]
    pub validation_meta: HashMap<String, serde_json::Value>,

    #[serde(rename = "Fingerprint")]
    pub fingerprint: String,

    /// Go unexported `exprContext` — never serialized.
    #[serde(skip)]
    pub expr_context: String,

    // Deprecated source fields (still serialized by Go).
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "SymlinkFile")]
    pub symlink_file: String,
    #[serde(rename = "Commit")]
    pub commit: String,
    #[serde(rename = "Link", skip_serializing_if = "String::is_empty")]
    pub link: String,

    /// Go `float32`.
    #[serde(rename = "Entropy")]
    pub entropy: f32,

    #[serde(rename = "Author")]
    pub author: String,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Date")]
    pub date: String,
    #[serde(rename = "Message")]
    pub message: String,
}

/// Applies partial masking to a secret string based on the given percentage
/// (port of Go package fn `report.MaskSecret`). At 100% the caller should use
/// `"REDACTED"` instead.
///
/// Operates on CHARS (Go runes), not bytes: slicing a multi-byte UTF-8 secret by
/// byte offset can split a rune and skews the mask ratio. `f64::round_ties_even`
/// reproduces Go's `math.RoundToEven` (banker's rounding) exactly — a plain
/// `.round()` would diverge on the `.5` boundary cases (e.g. `"secret"` 75%).
pub fn mask_secret(secret: &str, percent: u32) -> String {
    let percent = if percent > 100 { 100 } else { percent };
    let chars: Vec<char> = secret.chars().collect();
    let total = chars.len() as f64;
    if total <= 0.0 {
        return secret.to_string();
    }
    let prc = (100 - percent) as f64;
    let keep = (total * prc / 100.0).round_ties_even() as usize;
    chars[..keep].iter().collect::<String>() + "..."
}

/// Computes the Cartesian product over `ComponentFinding` slices keyed by
/// `rule_order`, stopping early once `max_component_sets` is reached (port of Go
/// unexported `cartesianFindings`).
///
/// Go operates on `[]*ComponentFinding` (shared pointers); here we work by VALUE
/// (`Vec<ComponentFinding>`) and clone into each product row — no aliasing.
fn cartesian_findings(
    rule_order: &[String],
    by_rule: &HashMap<String, Vec<ComponentFinding>>,
    max_component_sets: usize,
) -> Vec<Vec<ComponentFinding>> {
    if rule_order.is_empty() {
        return vec![Vec::new()];
    }

    let head = &rule_order[0];
    let rest = cartesian_findings(&rule_order[1..], by_rule, max_component_sets);

    let mut result: Vec<Vec<ComponentFinding>> = Vec::new();
    if let Some(findings) = by_rule.get(head) {
        for rf in findings {
            for tail in &rest {
                let mut row = Vec::with_capacity(tail.len() + 1);
                row.push(rf.clone());
                row.extend(tail.iter().cloned());
                result.push(row);
                if result.len() >= max_component_sets {
                    return result;
                }
            }
        }
    }
    result
}

impl Finding {
    /// Go `(*Finding).SetAttr`.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
    }

    /// Go `(*Finding).SetExprContext` — the hidden context text filter and
    /// validation expressions read as `finding["context"]`. Unexported in Go and
    /// `json:"-"`, so it never reaches a report.
    pub fn set_expr_context(&mut self, context: &str) {
        self.expr_context = context.to_string();
    }

    /// Go `(*Finding).SyncDeprecatedSourceFields` — mirror the attribute map
    /// into the deprecated flat fields for backwards compatibility.
    pub fn sync_deprecated_source_fields(&mut self) {
        self.file = self.attr(sources::ATTR_PATH).to_string();
        self.symlink_file = self.attr(sources::ATTR_FS_SYMLINK).to_string();
        self.commit = self.attr(sources::ATTR_GIT_SHA).to_string();
        self.author = self.attr(sources::ATTR_GIT_AUTHOR_NAME).to_string();
        self.email = self.attr(sources::ATTR_GIT_AUTHOR_EMAIL).to_string();
        self.date = self.attr(sources::ATTR_GIT_DATE).to_string();
        self.message = self.attr(sources::ATTR_GIT_MESSAGE).to_string();
    }

    /// Go `(*Finding).SetFingerprint`.
    ///
    /// Reads the ATTRIBUTE map directly rather than going through `attr` — so
    /// the deprecated-field fallback does NOT apply here. That asymmetry is
    /// Go's, and it means a finding whose path came from `File` rather than
    /// `Attributes` fingerprints with an empty path.
    pub fn set_fingerprint(&mut self) {
        let path = self.attributes.get(sources::ATTR_PATH).cloned().unwrap_or_default();
        let commit = self.attributes.get(sources::ATTR_GIT_SHA).cloned().unwrap_or_default();
        self.fingerprint = if commit.is_empty() {
            format!("{}:{}:{}", path, self.rule_id, self.start_line)
        } else {
            format!("{}:{}:{}:{}", commit, path, self.rule_id, self.start_line)
        };
    }

    /// Go `(*Finding).ToExprMap` — the fixed-shape `finding` variable filter and
    /// validation expressions see.
    pub fn to_expr_map(&self) -> Vec<(String, String)> {
        vec![
            ("secret".to_string(), self.secret.clone()),
            ("match".to_string(), self.r#match.clone()),
            ("line".to_string(), self.line.clone()),
            ("rule_id".to_string(), self.rule_id.clone()),
            ("description".to_string(), self.description.clone()),
            ("context".to_string(), self.expr_context.clone()),
        ]
    }

    /// Removes sensitive information from a finding (port of Go
    /// `(*Finding).Redact`).
    ///
    /// Shared-pointer reshape: Go dedups by `*ComponentFinding` pointer because the
    /// same finding can appear in multiple sets (Cartesian product) and partial
    /// masking must apply once. Here `components: Vec<ComponentFinding>` is BY
    /// VALUE — no aliasing — so each component is naturally masked exactly once
    /// and the dedup is unnecessary.
    pub fn redact(&mut self, percent: u32) {
        let secret = if percent >= 100 {
            "REDACTED".to_string()
        } else {
            mask_secret(&self.secret, percent)
        };

        // Replace ALL occurrences of the ORIGINAL secret before overwriting
        // `self.secret` (the original is still needed to match).
        let orig = self.secret.clone();
        self.line = self.line.replace(&orig, &secret);
        self.r#match = self.r#match.replace(&orig, &secret);
        self.match_context = self.match_context.replace(&orig, &secret);
        // Capture groups can contain the secret verbatim and are emitted in JSON,
        // JUnit, and template reports, so they must be redacted too.
        for v in self.capture_groups.values_mut() {
            *v = v.replace(&orig, &secret);
        }
        self.secret = secret;

        for set in &mut self.component_sets {
            for comp in &mut set.components {
                let comp_secret = if percent >= 100 {
                    "REDACTED".to_string()
                } else {
                    mask_secret(&comp.secret, percent)
                };
                comp.r#match = comp.r#match.replace(&comp.secret, &comp_secret);
                // Upstream drift (6cf4f1a2): a component's own line and capture
                // groups can carry the secret verbatim, so they are masked too.
                comp.line = comp.line.replace(&comp.secret, &comp_secret);
                for v in comp.capture_groups.values_mut() {
                    *v = v.replace(&comp.secret, &comp_secret);
                }
                comp.secret = comp_secret;
            }
        }
    }

    /// Generates the Cartesian product of the given component findings grouped by
    /// `rule_id` and populates `self.component_sets` (port of Go
    /// `(*Finding).BuildComponentSets`). `max_component_sets` caps the total number
    /// of combos. Go takes `[]*ComponentFinding`; here `&[ComponentFinding]`.
    pub fn build_component_sets(&mut self, component_findings: &[ComponentFinding], max_component_sets: usize) {
        if component_findings.is_empty() {
            // Go sets nil; an empty Vec is the faithful analog.
            self.component_sets = Vec::new();
            return;
        }

        // Group by rule_id, preserving first-occurrence order.
        let mut rule_order: Vec<String> = Vec::new();
        let mut by_rule: HashMap<String, Vec<ComponentFinding>> = HashMap::new();
        for rf in component_findings {
            if !by_rule.contains_key(&rf.rule_id) {
                rule_order.push(rf.rule_id.clone());
            }
            by_rule.entry(rf.rule_id.clone()).or_default().push(rf.clone());
        }

        let products = cartesian_findings(&rule_order, &by_rule, max_component_sets);
        self.component_sets = products
            .into_iter()
            .map(|components| ComponentSet {
                components,
                ..Default::default()
            })
            .collect();
    }

    /// Returns the value for `key`, falling back to the deprecated source fields
    /// (port of Go `(Finding).Attr`).
    pub fn attr(&self, key: &str) -> String {
        if let Some(value) = self.attributes.get(key) {
            if !value.is_empty() {
                return value.clone();
            }
        }

        match key {
            k if k == sources::ATTR_PATH => self.file.clone(),
            k if k == sources::ATTR_FS_SYMLINK => self.symlink_file.clone(),
            k if k == sources::ATTR_GIT_SHA => self.commit.clone(),
            k if k == sources::ATTR_GIT_AUTHOR_NAME => self.author.clone(),
            k if k == sources::ATTR_GIT_AUTHOR_EMAIL => self.email.clone(),
            k if k == sources::ATTR_GIT_DATE => self.date.clone(),
            k if k == sources::ATTR_GIT_MESSAGE => self.message.clone(),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TestRedact
    #[test]
    fn test_redact() {
        let mut f = Finding {
            r#match: "line containing secret".to_string(),
            secret: "secret".to_string(),
            ..Default::default()
        };
        f.redact(100);
        assert_eq!("REDACTED", f.secret);
        assert_eq!("line containing REDACTED", f.r#match);
    }

    // TestRedact_ComponentSets
    #[test]
    fn test_redact_component_sets() {
        let mut f = Finding {
            r#match: "line containing secret".to_string(),
            secret: "secret".to_string(),
            component_sets: vec![ComponentSet {
                components: vec![
                    ComponentFinding {
                        rule_id: "rule-a".to_string(),
                        secret: "comp-secret-1".to_string(),
                        line: "line comp-secret-1 here".to_string(),
                        r#match: "match comp-secret-1 here".to_string(),
                        capture_groups: HashMap::from([
                            ("token".to_string(), "comp-secret-1".to_string()),
                            ("label".to_string(), "safe".to_string()),
                        ]),
                        ..Default::default()
                    },
                    ComponentFinding {
                        rule_id: "rule-b".to_string(),
                        secret: "comp-secret-2".to_string(),
                        r#match: "match comp-secret-2 here".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        f.redact(100);
        assert_eq!("REDACTED", f.secret);
        assert_eq!("REDACTED", f.component_sets[0].components[0].secret);
        assert_eq!("match REDACTED here", f.component_sets[0].components[0].r#match);
        assert_eq!("REDACTED", f.component_sets[0].components[1].secret);
        assert_eq!("match REDACTED here", f.component_sets[0].components[1].r#match);

        // Drift 6cf4f1a2: a component's own `line` and capture-group VALUES are
        // masked too — while a group whose value never contained the secret is
        // left alone.
        let c0 = &f.component_sets[0].components[0];
        assert_eq!("line REDACTED here", c0.line);
        assert_eq!("REDACTED", c0.capture_groups["token"]);
        assert_eq!("safe", c0.capture_groups["label"]);
    }

    // TestRedact_SharedPointerDedup — reshaped for Rust ownership.
    //
    // Go dedups by `*ComponentFinding` pointer (same finding aliased into two
    // sets, masked once). Rust `components: Vec<ComponentFinding>` is by value, so
    // build TWO sets each holding an EQUIVALENT component and assert both are
    // masked exactly once (each is a separate owned value).
    #[test]
    fn test_redact_shared_pointer_dedup() {
        let comp = ComponentFinding {
            rule_id: "rule-a".to_string(),
            secret: "abcdefghij".to_string(),
            line: "line abcdefghij here".to_string(),
            r#match: "found abcdefghij here".to_string(),
            capture_groups: HashMap::from([("token".to_string(), "abcdefghij".to_string())]),
            ..Default::default()
        };
        let mut f = Finding {
            r#match: "primary".to_string(),
            secret: "primary".to_string(),
            component_sets: vec![
                ComponentSet {
                    components: vec![comp.clone()],
                    ..Default::default()
                },
                ComponentSet {
                    components: vec![comp.clone()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        f.redact(75);
        // 75% mask on 10-char secret: RoundToEven(10 * 25/100 = 2.5) = 2 chars kept → "ab..."
        assert_eq!("ab...", f.component_sets[0].components[0].secret);
        assert_eq!("found ab... here", f.component_sets[0].components[0].r#match);
        assert_eq!("ab...", f.component_sets[1].components[0].secret);
        assert_eq!("found ab... here", f.component_sets[1].components[0].r#match);

        // Drift 6cf4f1a2: PARTIAL masking reaches the component's line and
        // capture groups too, not just secret/match.
        let shared = &f.component_sets[0].components[0];
        assert_eq!("line ab... here", shared.line);
        assert_eq!("ab...", shared.capture_groups["token"]);
    }

    /// Drift 6cf4f1a2 — the rename is a WIRE change. The emitted JSON must carry
    /// `ComponentSets` and must NOT carry the retired `RequiredSets` key
    /// (Go: `assert.NotContains(t, parsed, "RequiredSets")`).
    #[test]
    fn component_sets_replaces_required_sets_on_the_wire() {
        let mut f = Finding {
            rule_id: "primary".to_string(),
            secret: "s".to_string(),
            ..Default::default()
        };
        f.build_component_sets(
            &[
                ComponentFinding {
                    rule_id: "aws-key".to_string(),
                    secret: "AKIA".to_string(),
                    start_line: 10,
                    ..Default::default()
                },
                // An OPTIONAL component — the field added by the drift.
                ComponentFinding {
                    rule_id: "aws-region".to_string(),
                    optional: true,
                    secret: "us-east-1".to_string(),
                    start_line: 11,
                    ..Default::default()
                },
            ],
            10,
        );
        let json = serde_json::to_string(&f).expect("serialize");
        assert!(json.contains("\"ComponentSets\""), "got {json}");
        assert!(!json.contains("RequiredSets"), "retired key still emitted: {json}");
        // `Optional` has no omitempty in Go, so BOTH values appear.
        assert!(json.contains("\"Optional\":true"), "got {json}");
        assert!(json.contains("\"Optional\":false"), "got {json}");
    }

    // TestMask
    #[test]
    fn test_mask() {
        struct Case {
            finding: Finding,
            percent: u32,
            expect_secret: String,
            expect_match: String,
        }
        let cases = vec![
            // "normal secret"
            Case {
                finding: Finding {
                    r#match: "line containing secret".to_string(),
                    secret: "secret".to_string(),
                    ..Default::default()
                },
                percent: 75,
                expect_match: "line containing se...".to_string(),
                expect_secret: "se...".to_string(),
            },
            // "empty secret"
            Case {
                finding: Finding {
                    r#match: "line containing".to_string(),
                    secret: String::new(),
                    ..Default::default()
                },
                percent: 75,
                expect_match: "line containing".to_string(),
                expect_secret: String::new(),
            },
            // "short secret"
            Case {
                finding: Finding {
                    r#match: "line containing".to_string(),
                    secret: "ss".to_string(),
                    ..Default::default()
                },
                percent: 75,
                expect_match: "line containing".to_string(),
                expect_secret: "...".to_string(),
            },
        ];
        for mut c in cases {
            c.finding.redact(c.percent);
            assert_eq!(c.expect_secret, c.finding.secret);
            assert_eq!(c.expect_match, c.finding.r#match);
        }
    }

    // TestMaskSecret
    #[test]
    fn test_mask_secret() {
        assert_eq!("se...", mask_secret("secret", 75)); // normal masking
        assert_eq!("s...", mask_secret("secret", 90)); // high masking
        assert_eq!("secre...", mask_secret("secret", 10)); // low masking
        assert_eq!("...", mask_secret("secret", 1000)); // invalid masking (capped at 100)
    }

    // TestBuildComponentSets_Empty
    #[test]
    fn test_build_component_sets_empty() {
        let mut f = Finding::default();
        f.build_component_sets(&[], 100);
        assert!(f.component_sets.is_empty());
    }

    // TestBuildComponentSets_SingleRuleSingleFinding
    #[test]
    fn test_build_component_sets_single_rule_single_finding() {
        let rf = ComponentFinding {
            rule_id: "rule-a".to_string(),
            secret: "secret-a".to_string(),
            start_line: 1,
            ..Default::default()
        };
        let mut f = Finding::default();
        f.build_component_sets(&[rf], 100);

        assert_eq!(1, f.component_sets.len());
        assert_eq!(1, f.component_sets[0].components.len());
        assert_eq!("rule-a", f.component_sets[0].components[0].rule_id);
        assert_eq!("secret-a", f.component_sets[0].components[0].secret);
    }

    // TestBuildComponentSets_MultiRuleMultiFinding
    #[test]
    fn test_build_component_sets_multi_rule_multi_finding() {
        let reqs = vec![
            ComponentFinding {
                rule_id: "rule-a".to_string(),
                secret: "a1".to_string(),
                start_line: 1,
                ..Default::default()
            },
            ComponentFinding {
                rule_id: "rule-a".to_string(),
                secret: "a2".to_string(),
                start_line: 2,
                ..Default::default()
            },
            ComponentFinding {
                rule_id: "rule-b".to_string(),
                secret: "b1".to_string(),
                start_line: 3,
                ..Default::default()
            },
        ];
        let mut f = Finding::default();
        f.build_component_sets(&reqs, 100);

        // 2 values for rule-a × 1 value for rule-b = 2 sets
        assert_eq!(2, f.component_sets.len());
        for set in &f.component_sets {
            assert_eq!(2, set.components.len(), "each set should have one component per rule");
            assert_eq!("rule-a", set.components[0].rule_id);
            assert_eq!("rule-b", set.components[1].rule_id);
        }
        // Verify distinct secrets in the rule-a position.
        let a = &f.component_sets[0].components[0].secret;
        let b = &f.component_sets[1].components[0].secret;
        assert!(a == "a1" || b == "a1");
        assert!(a == "a2" || b == "a2");
    }

    // TestBuildComponentSets_MaxCap
    #[test]
    fn test_build_component_sets_max_cap() {
        // 3 × 3 = 9 sets, cap at 5
        let reqs = vec![
            ComponentFinding { rule_id: "r1".to_string(), secret: "s1".to_string(), ..Default::default() },
            ComponentFinding { rule_id: "r1".to_string(), secret: "s2".to_string(), ..Default::default() },
            ComponentFinding { rule_id: "r1".to_string(), secret: "s3".to_string(), ..Default::default() },
            ComponentFinding { rule_id: "r2".to_string(), secret: "t1".to_string(), ..Default::default() },
            ComponentFinding { rule_id: "r2".to_string(), secret: "t2".to_string(), ..Default::default() },
            ComponentFinding { rule_id: "r2".to_string(), secret: "t3".to_string(), ..Default::default() },
        ];
        let mut f = Finding::default();
        f.build_component_sets(&reqs, 5);
        assert_eq!(5, f.component_sets.len());
    }

    // TestBuildComponentSets_JSONSerialization
    #[test]
    fn test_build_component_sets_json_serialization() {
        let reqs = vec![
            ComponentFinding {
                rule_id: "aws-secret".to_string(),
                secret: "wJalrXUtnFEMI".to_string(),
                start_line: 10,
                ..Default::default()
            },
            ComponentFinding {
                rule_id: "aws-region".to_string(),
                secret: "us-east-1".to_string(),
                start_line: 11,
                ..Default::default()
            },
        ];
        let mut f = Finding {
            rule_id: "aws-access-key".to_string(),
            secret: "AKIAIOSFODNN7EXAMPLE".to_string(),
            ..Default::default()
        };
        f.build_component_sets(&reqs, 100);

        let data = serde_json::to_string(&f).expect("marshal finding");
        let parsed: serde_json::Value = serde_json::from_str(&data).expect("unmarshal finding");

        let sets = parsed
            .get("ComponentSets")
            .expect("ComponentSets should be present in JSON");
        let set_slice = sets.as_array().expect("ComponentSets should be an array");
        assert_eq!(1, set_slice.len());

        let components = set_slice[0]
            .get("components")
            .and_then(|c| c.as_array())
            .expect("components should be an array");
        assert_eq!(2, components.len());
    }

    // TestFindingAttrFallsBackToDeprecatedFields
    #[test]
    fn test_finding_attr_falls_back_to_deprecated_fields() {
        let f = Finding {
            file: "fallback.txt".to_string(),
            commit: "abc123".to_string(),
            author: "alice".to_string(),
            email: "alice@example.com".to_string(),
            date: "2026-04-13".to_string(),
            ..Default::default()
        };

        assert_eq!("fallback.txt", f.attr(sources::ATTR_PATH));
        assert_eq!("abc123", f.attr(sources::ATTR_GIT_SHA));
        assert_eq!("alice", f.attr(sources::ATTR_GIT_AUTHOR_NAME));
        assert_eq!("alice@example.com", f.attr(sources::ATTR_GIT_AUTHOR_EMAIL));
        assert_eq!("2026-04-13", f.attr(sources::ATTR_GIT_DATE));
    }

    // TestRedactMasksCaptureGroups
    #[test]
    fn test_redact_masks_capture_groups() {
        let mut capture_groups = HashMap::new();
        capture_groups.insert("token".to_string(), "supersecret".to_string());
        capture_groups.insert("user".to_string(), "alice".to_string());
        let mut f = Finding {
            secret: "supersecret".to_string(),
            r#match: "key=supersecret".to_string(),
            line: "api key=supersecret here".to_string(),
            capture_groups,
            ..Default::default()
        };
        f.redact(100);

        assert_eq!(
            "REDACTED", f.capture_groups["token"],
            "capture group holding the secret must be redacted"
        );
        assert_eq!(
            "alice", f.capture_groups["user"],
            "non-secret capture group should be left intact"
        );
    }

    // TestRedactPartiallyMasksCaptureGroups
    #[test]
    fn test_redact_partially_masks_capture_groups() {
        let mut capture_groups = HashMap::new();
        capture_groups.insert("t".to_string(), "abcdefghij".to_string());
        let mut f = Finding {
            secret: "abcdefghij".to_string(),
            capture_groups,
            ..Default::default()
        };
        f.redact(50);
        let want = mask_secret("abcdefghij", 50);
        assert_eq!(want, f.capture_groups["t"], "capture group should be partially masked");
    }

    // TestMaskSecretMultibyteUTF8
    #[test]
    fn test_mask_secret_multibyte_utf8() {
        let secret = "日本語パスワード"; // 8 runes (chars), 24 bytes

        // At 70% a byte-based slice would cut at byte 7 (inside the 3rd rune),
        // producing invalid UTF-8. The char-based mask keeps whole chars. In Rust
        // a `String` is always valid UTF-8, so the byte-splitting bug the Go test
        // guards against cannot even be constructed — we assert the exact value.
        let got = mask_secret(secret, 70);
        let want = secret.chars().take(2).collect::<String>() + "...";
        assert_eq!(want, got);
    }
}
