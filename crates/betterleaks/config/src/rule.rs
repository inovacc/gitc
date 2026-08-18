//! Port of Go `config/rule.go` — the `Rule` and `Component` types and
//! `Rule.Validate`.

use crate::Program;
use regexp::Regexp;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Go `config.DefaultRuleSpecificity` (`config/config.go:27`) — **100**, not 0.
///
/// This was 0 here, and the consequence was not cosmetic. Specificity does two
/// jobs: it orders the rule loop so a specific provider rule runs before the
/// generic catch-all, and it drives the suppression that lets that specific
/// rule *displace* the catch-all's finding. With the default at 0, 413 of the
/// 414 shipped rules tied at 0 — the ordering collapsed to catalogue order and
/// nothing could out-rank anything.
///
/// The shipped catalogue only ever sets this DOWNWARD (`generic-api-key` is
/// `specificity = 0`), so a wrong default is invisible in any test that looks
/// at one rule at a time. It surfaced in a differential: Go emitted
/// `slack-bot-token` before `generic-api-key`, this port emitted them the other
/// way round.
pub const DEFAULT_RULE_SPECIFICITY: i64 = 100;

/// Go `config.Component` — another rule whose matches contribute to this one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    pub rule_id: String,
    /// Optional components are attached when found but do NOT gate the primary
    /// finding.
    pub optional: bool,
    /// Uses the same directional L/C grammar as `--match-context`, parsed by
    /// [`contextwindow::parse`].
    pub within: String,
}

/// Go `config.Rule` — how to detect one kind of secret.
///
/// **Pointer reshape:** Go holds `*regexp.Regexp` so copying a `Rule` is cheap.
/// `Arc<Regexp>` reproduces exactly that (shared, cheap to clone, and `Regexp`
/// itself is not `Clone` because it caches a lazily-compiled program).
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub rule_id: String,
    pub description: String,

    /// Minimum Shannon entropy a regex group must have to count as a secret.
    pub entropy: f64,

    /// Which regex group the secret is extracted from — and whose entropy is
    /// checked when `entropy` is set.
    pub secret_group: i64,

    pub regex: Option<Arc<Regexp>>,
    /// Filters secrets by path.
    pub path: Option<Arc<Regexp>>,

    pub tags: Vec<String>,

    /// Precedence when overlapping findings compete; higher suppresses lower.
    pub specificity: i64,

    /// How likely a match is to be a real secret (`low` | `medium` | `high`).
    pub confidence: String,

    /// Pre-regex filtering: a rule with keywords is only checked when one of
    /// them appears in the content. Lower-cased at load time.
    pub keywords: Vec<String>,

    /// Other rules whose matches contribute to this one.
    pub components: Vec<Component>,

    /// Whether a config explicitly supplied components — distinguishes omission
    /// from `components = []` while extending configs.
    pub(crate) components_set: bool,

    pub skip_report: bool,

    /// Enables the BPE token-efficiency filter for this rule.
    pub token_efficiency: bool,

    /// Raw expression used for secret validation.
    pub validate_expr: String,

    /// Expression evaluated against attributes + finding per regex match.
    /// True = skip (discard this finding).
    pub filter: String,

    /// Per-rule allowlists BEFORE translation. Emptied by
    /// [`crate::Config::translate_legacy_filters`], which folds them into
    /// `filter`. A rule has NO prefilter — Go folds even its path/commit checks
    /// into the single filter expression, because a rule is only reached once a
    /// fragment has already survived the global prefilter.
    pub allowlists: Vec<crate::Allowlist>,

    /// Tracks whether [`Rule::validate`] has run — Go's `validated` flag makes
    /// validation idempotent.
    pub(crate) validated: bool,

    // `pub(crate)` so `translate` can build a `Rule` literal; the public API is
    // the accessor pair below, mirroring Go's unexported field + getter/setter.
    pub(crate) validation_program: Program,
    pub(crate) filter_program: Program,
}

/// Go's `Rule.Validate` errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// `rule |id| is missing or empty` + whatever context could be gathered.
    MissingId(String),
    /// `<id>: both |regex| and |path| are empty, this rule will have no effect`
    NoRegexOrPath(String),
    /// `<id>: invalid confidence %q (expected low, medium, or high)`
    InvalidConfidence { rule_id: String, confidence: String },
    /// `<id>: invalid regex secret group N, max regex secret group M`
    InvalidSecretGroup { rule_id: String, got: i64, max: usize },
    /// `<id>: component rule ID is empty`
    EmptyComponentId(String),
    /// `<id>: duplicate component rule ID %q`
    DuplicateComponent { rule_id: String, component: String },
    /// `<id>: component %q has invalid within value %q: …`
    InvalidComponentWithin { rule_id: String, component: String, within: String, cause: String },
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::MissingId(ctx) => write!(f, "rule |id| is missing or empty{ctx}"),
            RuleError::NoRegexOrPath(id) => write!(
                f,
                "{id}: both |regex| and |path| are empty, this rule will have no effect"
            ),
            RuleError::InvalidConfidence { rule_id, confidence } => write!(
                f,
                "{rule_id}: invalid confidence \"{confidence}\" (expected low, medium, or high)"
            ),
            RuleError::InvalidSecretGroup { rule_id, got, max } => write!(
                f,
                "{rule_id}: invalid regex secret group {got}, max regex secret group {max}"
            ),
            RuleError::EmptyComponentId(id) => write!(f, "{id}: component rule ID is empty"),
            RuleError::DuplicateComponent { rule_id, component } => {
                write!(f, "{rule_id}: duplicate component rule ID \"{component}\"")
            }
            RuleError::InvalidComponentWithin { rule_id, component, within, cause } => write!(
                f,
                "{rule_id}: component \"{component}\" has invalid within value \"{within}\": {cause}"
            ),
        }
    }
}

impl Error for RuleError {}

impl Rule {
    /// Convenience constructor for the id + description pair.
    ///
    /// Kept from the earlier two-field subset crate: `report`'s SARIF emitter
    /// builds rules this way, and the emitters genuinely need nothing else.
    pub fn new(rule_id: &str, description: &str) -> Rule {
        Rule {
            rule_id: rule_id.to_string(),
            description: description.to_string(),
            ..Default::default()
        }
    }

    /// Go `(*Rule).Validate` — guards against common misconfigurations.
    ///
    /// Idempotent: Go short-circuits on its `validated` flag, so a second call
    /// is a no-op even if the rule was mutated in between. That quirk is
    /// preserved.
    ///
    /// **Not ported here:** the `Allowlists` loop. Allowlists are deferred (see
    /// `raw.rs`), and the shipped catalogue has none.
    pub fn validate(&mut self) -> Result<(), RuleError> {
        if self.validated {
            return Ok(());
        }

        // |id| must be present. Go assembles context from whatever it has,
        // precisely because the id — the thing you would name in the error — is
        // the missing field.
        if self.rule_id.trim().is_empty() {
            let mut sb = String::new();
            if !self.description.is_empty() {
                sb.push_str(&format!(", description: {}", self.description));
            }
            if let Some(re) = &self.regex {
                sb.push_str(&format!(", regex: {}", re.as_str()));
            }
            if let Some(p) = &self.path {
                sb.push_str(&format!(", path: {}", p.as_str()));
            }
            return Err(RuleError::MissingId(sb));
        }

        // The rule must actually match something.
        if self.regex.is_none() && self.path.is_none() {
            return Err(RuleError::NoRegexOrPath(self.rule_id.clone()));
        }

        if !self.confidence.is_empty() && !confidence::valid(&self.confidence) {
            return Err(RuleError::InvalidConfidence {
                rule_id: self.rule_id.clone(),
                confidence: self.confidence.clone(),
            });
        }

        // |secretGroup| must exist in the pattern. `num_subexp` is available
        // WITHOUT compiling the regex — that laziness is why the facade records
        // the capture count at parse time.
        if let Some(re) = &self.regex {
            let max = re.num_subexp();
            if self.secret_group > max as i64 {
                return Err(RuleError::InvalidSecretGroup {
                    rule_id: self.rule_id.clone(),
                    got: self.secret_group,
                    max,
                });
            }
        }

        let mut seen: Vec<&str> = Vec::with_capacity(self.components.len());
        for component in &self.components {
            if component.rule_id.trim().is_empty() {
                return Err(RuleError::EmptyComponentId(self.rule_id.clone()));
            }
            if seen.contains(&component.rule_id.as_str()) {
                return Err(RuleError::DuplicateComponent {
                    rule_id: self.rule_id.clone(),
                    component: component.rule_id.clone(),
                });
            }
            seen.push(&component.rule_id);
            if let Err(e) = contextwindow::parse(&component.within) {
                return Err(RuleError::InvalidComponentWithin {
                    rule_id: self.rule_id.clone(),
                    component: component.rule_id.clone(),
                    within: component.within.clone(),
                    cause: e.to_string(),
                });
            }
        }

        self.validated = true;
        Ok(())
    }

    /// Go `(*Rule).ValidationProgram`.
    pub fn validation_program(&self) -> &Program {
        &self.validation_program
    }

    /// Go `(*Rule).SetValidationProgram`.
    pub fn set_validation_program(&mut self, p: Program) {
        self.validation_program = p;
    }

    /// Go `(*Rule).FilterProgram`.
    pub fn filter_program(&self) -> &Program {
        &self.filter_program
    }

    /// Go `(*Rule).SetFilterProgram`.
    pub fn set_filter_program(&mut self, p: Program) {
        self.filter_program = p;
    }

    /// Whether a config explicitly supplied components (Go `componentsSet`).
    pub fn components_set(&self) -> bool {
        self.components_set
    }
}
