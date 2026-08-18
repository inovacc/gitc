//! The TOML deserialization schema — a 1:1 port of Go's unexported `rawConfig`
//! / `rawRule` / `rawComponent` / `rawRequired` structs (`config/config.go:29-91`).
//!
//! Every `#[serde(rename)]` is Go's `toml:"…"` tag verbatim; these key names are
//! the user-facing config contract.
//!
//! `#[serde(default)]` throughout mirrors Go's zero-value-on-absent behaviour,
//! and `Option` is used ONLY where Go itself uses a pointer to distinguish
//! "absent" from "explicitly empty" — `Specificity`, `Components`, and the
//! allowlist shims. That distinction is load-bearing during config extension.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub extend: Extend,
    #[serde(default)]
    pub rules: Vec<RawRule>,

    /// Deprecated singular form, kept as a backwards-compatibility shim.
    #[serde(default)]
    pub allowlist: Option<RawGlobalAllowlist>,
    #[serde(default)]
    pub allowlists: Vec<RawGlobalAllowlist>,

    #[serde(rename = "minVersion", default)]
    pub min_version: String,
    #[serde(rename = "betterleaksMinVersion", default)]
    pub betterleaks_min_version: String,

    /// Global expression over attributes only, evaluated before any per-match
    /// work. True = skip this fragment entirely.
    #[serde(default)]
    pub prefilter: String,
    /// Global expression over attributes + finding, evaluated per match.
    /// True = skip (discard) this finding.
    #[serde(default)]
    pub filter: String,
}

/// Go `config.Extend`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Extend {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub url: String,
    #[serde(rename = "useDefault", default)]
    pub use_default: bool,
    #[serde(rename = "disabledRules", default)]
    pub disabled_rules: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub regex: String,
    #[serde(rename = "secretGroup", default)]
    pub secret_group: i64,
    #[serde(default)]
    pub entropy: f64,
    #[serde(default)]
    pub keywords: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Go uses `*int` so an explicit 0 is distinguishable from "absent".
    #[serde(default)]
    pub specificity: Option<i64>,
    #[serde(default)]
    pub confidence: String,

    /// Deprecated singular form (backwards-compatibility shim).
    #[serde(default)]
    pub allowlist: Option<RawRuleAllowlist>,
    #[serde(default)]
    pub allowlists: Vec<RawRuleAllowlist>,

    /// A pointer in Go so config extension can tell omission from
    /// `components = []`.
    #[serde(default)]
    pub components: Option<Vec<RawComponent>>,

    /// Deprecated: translated to components when `components` is absent.
    #[serde(default)]
    pub required: Option<Vec<RawRequired>>,

    #[serde(default)]
    pub validate: String,
    #[serde(rename = "skipReport", default)]
    pub skip_report: bool,
    #[serde(rename = "tokenEfficiency", default)]
    pub token_efficiency: bool,

    /// Per-match expression. True = skip (discard this finding).
    #[serde(default)]
    pub filter: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawComponent {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub within: String,
}

/// Deprecated shape, superseded by [`RawComponent`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRequired {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "withinLines", default)]
    pub within_lines: Option<i64>,
    #[serde(rename = "withinColumns", default)]
    pub within_columns: Option<i64>,
}

/// Rule-scoped allowlist.
///
/// **DEFERRED (see PORT-TRACK):** the shape is parsed so a user config carrying
/// allowlists is not REJECTED, but the translation to filter expressions
/// (`allowlist.go`, `translate_filters.go`) is not ported yet. The shipped
/// catalogue uses ZERO allowlists — measured, not assumed — so nothing in the
/// default path depends on it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRuleAllowlist {
    #[serde(default)]
    pub description: String,
    #[serde(rename = "regexTarget", default)]
    pub regex_target: String,
    #[serde(default)]
    pub condition: String,
    #[serde(default)]
    pub commits: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(rename = "stopwords", default)]
    pub stopwords: Vec<String>,
}

/// Config-scoped allowlist. Same deferral as [`RawRuleAllowlist`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGlobalAllowlist {
    #[serde(default)]
    pub description: String,
    #[serde(rename = "regexTarget", default)]
    pub regex_target: String,
    #[serde(default)]
    pub condition: String,
    #[serde(default)]
    pub commits: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(rename = "stopwords", default)]
    pub stopwords: Vec<String>,
    #[serde(rename = "targetRules", default)]
    pub target_rules: Vec<String>,
}
