//! Port of Go `config` — the rule catalogue and its TOML loader (M9 in
//! `PORT-PLAN.md`).
//!
//! **This is the module that lifts rule coverage from 26 to 414**, and it does
//! so by porting the LOADER, not the rules: the shipped catalogue
//! `config/betterleaks.toml` is embedded byte-identical and parsed at load
//! time, exactly as Go's `//go:embed betterleaks.toml` does. Nothing in the
//! 14K-LOC Go `cmd/generate/config/rules` package needs porting — at runtime Go
//! reads the TOML too, never those functions.
//!
//! ## What is ported, and what is deferred
//!
//! Ported: the full raw TOML schema, `Rule`/`Component`, `Rule::validate`,
//! `translate`, the keyword index, and min-version checking.
//!
//! Also ported: `allowlist.go` + `translate_filters.go` (allowlists rewritten
//! into filter expressions) and `[extend]`.
//!
//! **These two were previously deferred on a reasoning error worth recording.**
//! The justification was that the shipped catalogue contains zero allowlists —
//! measured and true, and beside the point. Allowlists are what USER configs
//! are made of, and `[extend] useDefault` is how a user config reaches the
//! catalogue at all. betterleaks' own repository ships a `.betterleaks.toml`
//! that is nothing but those two features, and without them a scan of that tree
//! reports 559 findings where the Go binary reports 1. "Unused by the default
//! config" is not the same as "unused".

mod raw;
mod rule;
mod translate_filters;

pub use raw::Extend;
pub use rule::{Component, Rule, RuleError, DEFAULT_RULE_SPECIFICITY};
pub use translate_filters::{
    compose_filters, translate_allowlist, translate_allowlist_slice, Allowlist, MatchCondition,
};

use raw::RawConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// The shipped rule catalogue, embedded byte-identical from
/// `config/betterleaks.toml` (Go: `//go:embed betterleaks.toml`).
///
/// Signed as an M9 source file in `PORT-PROVENANCE.json`: drift here silently
/// changes detection, so it is hashed like code, not treated as an asset.
pub const DEFAULT_CONFIG: &str = include_str!("../assets/betterleaks.toml");

/// Opaque handle to a compiled expression program (Go `exprruntime.Program`).
///
/// `config` never compiles or evaluates one — M10 owns that. Keeping this a
/// ONE-WAY handle is what stops `config -> exprruntime` becoming a dependency
/// edge, and is how the near-cycle in PORT-PLAN §3 stays broken.
///
/// A newtype rather than a bare alias so `Rule`/`Config` can still derive
/// `Debug`: `dyn Any` has no `Debug` impl of its own.
#[derive(Clone, Default)]
pub struct Program(pub Option<Arc<dyn std::any::Any + Send + Sync>>);

impl Program {
    /// Go's nil check — whether a program has been compiled onto this slot.
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(_) => f.write_str("Program(<compiled>)"),
            None => f.write_str("Program(none)"),
        }
    }
}

/// Go `config.Config`.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub title: String,
    pub extend: Extend,
    pub path: String,
    pub description: String,

    pub rules: BTreeMap<String, Rule>,
    pub keywords: BTreeSet<String>,

    /// Maps each lower-cased keyword to the rule IDs that use it, so an
    /// Aho-Corasick hit is O(1) to resolve instead of a scan over all rules.
    pub keyword_to_rules: BTreeMap<String, Vec<String>>,

    /// Rules with NO keywords, which must therefore always be checked.
    pub no_keyword_rules: Vec<String>,

    /// Preserves catalogue order so SARIF output stays stable.
    pub ordered_rules: Vec<String>,

    pub min_version: String,
    pub betterleaks_min_version: String,

    /// Global expression over attributes only, evaluated before any per-match
    /// work. True = skip the fragment entirely.
    pub prefilter: String,
    /// Global expression over attributes + finding, evaluated per match.
    /// True = skip (discard) the finding.
    pub filter: String,

    /// Global allowlists, BEFORE translation. Emptied by
    /// [`Config::translate_legacy_filters`], which folds them into
    /// `prefilter`/`filter` — matching Go, which clears `c.Allowlists` for the
    /// same reason: one evaluator, not two.
    pub allowlists: Vec<Allowlist>,

    /// Targeted allowlists whose rule was not present yet. Resolved at depth 0
    /// after every extend, because the target may come from the extended config.
    pending_target_allowlists: Vec<(String, Allowlist)>,

    prefilter_program: Program,
    filter_program: Program,
}

/// Errors from loading a config.
#[derive(Debug)]
pub enum ConfigError {
    Toml(String),
    /// `<id>: invalid regex %q: …`
    InvalidRegex { rule_id: String, pattern: String, cause: String },
    /// `<id>: invalid path regex %q: …`
    InvalidPathRegex { rule_id: String, pattern: String, cause: String },
    /// `<id>: [[rules.required]] withinLines must be non-negative`
    NegativeWithinLines(String),
    /// `<id>: [[rules.required]] withinColumns must be non-negative`
    NegativeWithinColumns(String),
    /// `<id>: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]`
    BothAllowlistForms(String),
    /// `invalid minVersion '<v>': …`
    InvalidMinVersion(String),
    /// An allowlist that checks nothing, which would silently never fire.
    InvalidAllowlist { rule_id: String, cause: String },
    /// `[[allowlists]] target rule ID '<id>' does not exist` — checked only
    /// after extend, since the target may live in the extended config.
    UnknownTargetRule(String),
    Rule(RuleError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Toml(e) => write!(f, "{e}"),
            ConfigError::InvalidRegex { rule_id, pattern, cause } => {
                write!(f, "{rule_id}: invalid regex \"{pattern}\": {cause}")
            }
            ConfigError::InvalidPathRegex { rule_id, pattern, cause } => {
                write!(f, "{rule_id}: invalid path regex \"{pattern}\": {cause}")
            }
            ConfigError::NegativeWithinLines(id) => {
                write!(f, "{id}: [[rules.required]] withinLines must be non-negative")
            }
            ConfigError::NegativeWithinColumns(id) => {
                write!(f, "{id}: [[rules.required]] withinColumns must be non-negative")
            }
            ConfigError::BothAllowlistForms(id) => write!(
                f,
                "{id}: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]"
            ),
            ConfigError::InvalidMinVersion(v) => write!(f, "invalid minVersion '{v}'"),
            ConfigError::InvalidAllowlist { rule_id, cause } => {
                write!(f, "{rule_id}: {cause}")
            }
            ConfigError::UnknownTargetRule(id) => {
                write!(f, "[[allowlists]] target rule ID '{id}' does not exist")
            }
            ConfigError::Rule(e) => write!(f, "{e}"),
        }
    }
}

impl Error for ConfigError {}

impl From<RuleError> for ConfigError {
    fn from(e: RuleError) -> Self {
        ConfigError::Rule(e)
    }
}

/// Go `config.ParseTOMLString`.
pub fn parse_toml_string(content: &str, path: &str) -> Result<Config, ConfigError> {
    parse_toml_string_at_depth(content, path, 0)
}

/// The depth-carrying form. Depth 0 is the config the user asked for; each
/// `[extend]` hop increments it, and [`MAX_EXTEND_DEPTH`] stops the chain so a
/// cycle of configs extending each other cannot hang the loader.
fn parse_toml_string_at_depth(
    content: &str,
    path: &str,
    depth: usize,
) -> Result<Config, ConfigError> {
    let rc: RawConfig = toml::from_str(content).map_err(|e| ConfigError::Toml(e.to_string()))?;
    translate(rc, path, depth)
}

/// Go `config.LoadFile`.
pub fn load_file(path: &str) -> Result<Config, Box<dyn Error>> {
    let data = std::fs::read_to_string(path)?;
    Ok(parse_toml_string(&data, path)?)
}

/// Go `config.Default` — parse the embedded catalogue.
pub fn default_config() -> Result<Config, ConfigError> {
    parse_toml_string(DEFAULT_CONFIG, "")
}

/// Go `(*rawConfig).translate`.
fn translate(rc: RawConfig, path: &str, depth: usize) -> Result<Config, ConfigError> {
    let mut keywords: BTreeSet<String> = BTreeSet::new();
    let mut ordered_rules: Vec<String> = Vec::new();
    let mut rules_map: BTreeMap<String, Rule> = BTreeMap::new();

    for mut vr in rc.rules {
        // Go compiles path/regex eagerly HERE (not lazily), so a bad pattern is
        // a load-time error naming the rule — the facade's laziness applies to
        // the engine program, not to this syntax check.
        let path_pat = if vr.path.is_empty() {
            None
        } else {
            Some(Arc::new(regexp::compile(&vr.path).map_err(|e| {
                ConfigError::InvalidPathRegex {
                    rule_id: vr.id.clone(),
                    pattern: vr.path.clone(),
                    cause: e.to_string(),
                }
            })?))
        };
        let regex_pat = if vr.regex.is_empty() {
            None
        } else {
            Some(Arc::new(regexp::compile(&vr.regex).map_err(|e| {
                ConfigError::InvalidRegex {
                    rule_id: vr.id.clone(),
                    pattern: vr.regex.clone(),
                    cause: e.to_string(),
                }
            })?))
        };

        // Keywords are lower-cased in place and folded into the global set.
        let rule_keywords: Vec<String> = match vr.keywords.take() {
            None => Vec::new(),
            Some(ks) => ks
                .into_iter()
                .map(|k| {
                    let k = k.to_lowercase();
                    keywords.insert(k.clone());
                    k
                })
                .collect(),
        };

        let specificity = vr.specificity.unwrap_or(DEFAULT_RULE_SPECIFICITY);

        let mut cr = Rule {
            rule_id: vr.id.clone(),
            description: vr.description,
            regex: regex_pat,
            secret_group: vr.secret_group,
            entropy: vr.entropy,
            path: path_pat,
            keywords: rule_keywords,
            tags: vr.tags.unwrap_or_default(),
            specificity,
            confidence: vr.confidence,
            skip_report: vr.skip_report,
            token_efficiency: vr.token_efficiency,
            ..Default::default()
        };

        // Allowlists. The deprecated singular `[rules.allowlist]` cannot be
        // combined with the plural form — Go refuses rather than guessing which
        // the author meant.
        if vr.allowlist.is_some() && !vr.allowlists.is_empty() {
            return Err(ConfigError::BothAllowlistForms(cr.rule_id));
        }
        let mut rule_allowlist_sources: Vec<raw::RawRuleAllowlist> = Vec::new();
        if let Some(a) = vr.allowlist.take() {
            rule_allowlist_sources.push(a);
        }
        rule_allowlist_sources.append(&mut vr.allowlists);
        for ra in rule_allowlist_sources {
            let a = rule_allowlist_from_raw(&ra);
            a.validate()
                .map_err(|e| ConfigError::InvalidAllowlist { rule_id: cr.rule_id.clone(), cause: e })?;
            cr.allowlists.push(a);
        }

        if let Some(components) = vr.components {
            cr.components_set = true;
            for c in components {
                cr.components.push(Component {
                    rule_id: c.id,
                    optional: c.optional,
                    within: c.within,
                });
            }
        } else if let Some(required) = vr.required {
            cr.components_set = true;
            for r in required {
                if r.within_lines.is_some_and(|v| v < 0) {
                    return Err(ConfigError::NegativeWithinLines(cr.rule_id));
                }
                if r.within_columns.is_some_and(|v| v < 0) {
                    return Err(ConfigError::NegativeWithinColumns(cr.rule_id));
                }
                cr.components.push(Component {
                    rule_id: r.id,
                    optional: false,
                    within: legacy_component_within(r.within_lines, r.within_columns),
                });
            }
        }

        cr.validate_expr = vr.validate;
        cr.filter = vr.filter;

        ordered_rules.push(cr.rule_id.clone());
        rules_map.insert(cr.rule_id.clone(), cr);
    }

    let mut c = Config {
        title: rc.title,
        description: rc.description,
        extend: rc.extend,
        rules: rules_map,
        keywords,
        ordered_rules,
        min_version: rc.min_version,
        betterleaks_min_version: rc.betterleaks_min_version,
        prefilter: rc.prefilter,
        filter: rc.filter,
        path: path.to_string(),
        ..Default::default()
    };

    // ── global allowlists ───────────────────────────────────────────────────
    // An allowlist naming `targetRules` is NOT global: it attaches to those
    // rules instead, so a targeted suppression cannot leak onto every rule.
    let mut global_raw: Vec<raw::RawGlobalAllowlist> = Vec::new();
    if let Some(a) = rc.allowlist {
        global_raw.push(a);
    }
    global_raw.extend(rc.allowlists);
    for ga in &global_raw {
        let a = global_allowlist_from_raw(ga);
        a.validate().map_err(|e| ConfigError::InvalidAllowlist {
            rule_id: "[[allowlists]]".to_string(),
            cause: e,
        })?;
        if a.target_rules.is_empty() {
            c.allowlists.push(a);
        } else {
            for rule_id in &a.target_rules {
                match c.rules.get_mut(rule_id) {
                    Some(r) => r.allowlists.push(a.clone()),
                    // Go validates target rule IDs only at depth 0, AFTER
                    // extend — a targeted rule may come from the extended
                    // config. Deferred to the same place for the same reason.
                    None => c.pending_target_allowlists.push((rule_id.clone(), a.clone())),
                }
            }
        }
    }

    validate_min_version(&c.min_version, &c.betterleaks_min_version, &c.path)?;

    // ── extend ──────────────────────────────────────────────────────────────
    // Go: `if maxExtendDepth != depth`, with maxExtendDepth = 2. So a config may
    // extend, and the config it extends may extend once more, and there it
    // stops — a cycle cannot hang the loader.
    if depth != MAX_EXTEND_DEPTH {
        if !c.extend.path.is_empty() && c.extend.use_default {
            return Err(ConfigError::Toml(
                "unable to load config due to extend.path and extend.useDefault being set"
                    .to_string(),
            ));
        }
        if c.extend.use_default {
            c.extend_default(depth)?;
        } else if !c.extend.path.is_empty() {
            c.extend_path(depth)?;
        }
    }

    // Everything below runs only for the OUTERMOST config, after every extend
    // has landed — matching Go's `if depth == 0` guard.
    if depth == 0 {
        let pending = std::mem::take(&mut c.pending_target_allowlists);
        for (rule_id, a) in pending {
            match c.rules.get_mut(&rule_id) {
                Some(r) => r.allowlists.push(a),
                None => {
                    return Err(ConfigError::UnknownTargetRule(rule_id));
                }
            }
        }
        c.translate_legacy_filters();
    }

    c.build_keyword_index();
    Ok(c)
}

/// Go `const maxExtendDepth = 2`.
const MAX_EXTEND_DEPTH: usize = 2;

/// Go's `fmt.Sprintf("%g", f)` for the entropy thresholds this actually sees —
/// small positive decimals like `3.5`.
///
/// `%g` prints the shortest representation that round-trips, dropping trailing
/// zeros, which is what Rust's `{}` for `f64` also does. The exponent form
/// differs in spelling for extreme magnitudes; an entropy threshold is never in
/// that range (it is bounded by log2 of the alphabet size), so the divergence
/// is unreachable here rather than merely unlikely.
fn format_g(f: f64) -> String {
    format!("{f}")
}

fn match_condition_from_raw(condition: &str) -> MatchCondition {
    // Go compares case-insensitively and treats anything that is not "and" as
    // OR, which is also the zero value.
    if condition.trim().eq_ignore_ascii_case("and") {
        MatchCondition::And
    } else {
        MatchCondition::Or
    }
}

fn rule_allowlist_from_raw(r: &raw::RawRuleAllowlist) -> Allowlist {
    Allowlist {
        description: r.description.clone(),
        match_condition: match_condition_from_raw(&r.condition),
        commits: r.commits.clone(),
        paths: r.paths.clone(),
        regex_target: r.regex_target.clone(),
        regexes: r.regexes.clone(),
        stopwords: r.stopwords.clone(),
        target_rules: Vec::new(),
    }
}

fn global_allowlist_from_raw(r: &raw::RawGlobalAllowlist) -> Allowlist {
    Allowlist {
        description: r.description.clone(),
        match_condition: match_condition_from_raw(&r.condition),
        commits: r.commits.clone(),
        paths: r.paths.clone(),
        regex_target: r.regex_target.clone(),
        regexes: r.regexes.clone(),
        stopwords: r.stopwords.clone(),
        target_rules: r.target_rules.clone(),
    }
}

impl Config {
    /// Go `(*Config).translateLegacyFilters` — fold allowlists (and the
    /// deprecated `entropy` / `tokenEfficiency` rule fields) into expressions.
    ///
    /// Called once, on the OUTERMOST config, after every extend has landed —
    /// otherwise an inherited allowlist would be translated before the rule it
    /// targets exists.
    pub fn translate_legacy_filters(&mut self) {
        let (global_pre, global_fil) = translate_allowlist_slice(&self.allowlists);
        self.prefilter = compose_filters(&global_pre, &self.prefilter);
        self.filter = compose_filters(&global_fil, &self.filter);

        for rule in self.rules.values_mut() {
            let (rule_pre, rule_fil) = translate_allowlist_slice(&rule.allowlists);
            // A rule has no prefilter: the attribute-level parts are folded in
            // with the rest, FIRST, matching Go's `append(rulePre, ruleFil...)`.
            let mut parts = rule_pre;
            parts.extend(rule_fil);

            if rule.entropy != 0.0 {
                // Go: `%g`, then `.0` appended when the result has no `.` or
                // `e`, so the expression always reads as a float.
                let mut threshold = format_g(rule.entropy);
                if !threshold.contains('.') && !threshold.contains('e') {
                    threshold.push_str(".0");
                }
                parts.push(format!("entropy(finding[\"secret\"]) <= {threshold}"));
            }
            if rule.token_efficiency {
                parts.push("failsTokenEfficiency(finding[\"secret\"])".to_string());
            }

            rule.filter = compose_filters(&parts, &rule.filter);

            // Cleared once translated, exactly as Go does — leaving them set
            // would invite a second evaluator applying them again.
            rule.allowlists.clear();
            rule.entropy = 0.0;
            rule.token_efficiency = false;
        }

        self.allowlists.clear();
    }

    /// Go `(*Config).extendDefault` — extend with the EMBEDDED catalogue.
    ///
    /// This is what `[extend] useDefault = true` means, and it is the common
    /// case: a repository's own config adds its allowlists on top of the
    /// shipped rules rather than replacing them.
    fn extend_default(&mut self, depth: usize) -> Result<(), ConfigError> {
        let base = parse_toml_string_at_depth(DEFAULT_CONFIG, "", depth + 1)?;
        self.extend_with(base);
        Ok(())
    }

    /// Go `(*Config).extendPath`.
    fn extend_path(&mut self, depth: usize) -> Result<(), ConfigError> {
        let path = self.extend.path.clone();
        let data = std::fs::read_to_string(&path)
            .map_err(|e| ConfigError::Toml(format!("failed to load extended config, err: {e}")))?;
        let base = parse_toml_string_at_depth(&data, &path, depth + 1)?;
        self.extend_with(base);
        Ok(())
    }

    /// Go `(*Config).extend` — merge an extended config UNDER this one.
    ///
    /// Direction matters: the extended config is the BASE and this config's
    /// values win, because the local config exists to adjust the shared one.
    fn extend_with(&mut self, base: Config) {
        let disabled: BTreeSet<&String> = self.extend.disabled_rules.iter().collect();

        for (rule_id, base_rule) in base.rules {
            if disabled.contains(&rule_id) {
                continue;
            }
            match self.rules.remove(&rule_id) {
                None => {
                    // New rule — take it wholesale.
                    for k in &base_rule.keywords {
                        self.keywords.insert(k.clone());
                    }
                    self.ordered_rules.push(rule_id.clone());
                    self.rules.insert(rule_id, base_rule);
                }
                Some(current) => {
                    // Rule exists in BOTH: start from the base and let the
                    // local config's non-empty fields override it.
                    let mut merged = base_rule;
                    if !current.description.is_empty() {
                        merged.description = current.description;
                    }
                    if current.entropy != 0.0 {
                        merged.entropy = current.entropy;
                    }
                    if current.secret_group != 0 {
                        merged.secret_group = current.secret_group;
                    }
                    if current.regex.is_some() {
                        merged.regex = current.regex;
                    }
                    if current.path.is_some() {
                        merged.path = current.path;
                    }
                    if !current.validate_expr.is_empty() {
                        merged.validate_expr = current.validate_expr;
                    }
                    if !current.confidence.is_empty() {
                        merged.confidence = current.confidence;
                    }
                    if !current.filter.is_empty() {
                        merged.filter = current.filter;
                    }
                    // Tags, keywords and allowlists ACCUMULATE rather than
                    // replace — a local config adds suppressions, it does not
                    // silently drop the shared ones.
                    merged.tags.extend(current.tags);
                    merged.keywords.extend(current.keywords);
                    merged.allowlists.extend(current.allowlists);
                    if current.components_set {
                        merged.components = current.components;
                        merged.components_set = true;
                    }
                    for k in &merged.keywords {
                        self.keywords.insert(k.clone());
                    }
                    self.rules.insert(rule_id, merged);
                }
            }
        }

        // Allowlists are appended, never merged — Go does not try to reconcile
        // two allowlists into one.
        self.allowlists.extend(base.allowlists);
        self.pending_target_allowlists.extend(base.pending_target_allowlists);

        // The local global prefilter/filter WIN if set.
        if self.prefilter.is_empty() {
            self.prefilter = base.prefilter;
        }
        if self.filter.is_empty() {
            self.filter = base.filter;
        }

        self.ordered_rules.sort();
        self.ordered_rules.dedup();
    }

    /// Build `keyword_to_rules` + `no_keyword_rules`. Walks `ordered_rules` so
    /// the per-keyword rule lists are in catalogue order, not map order.
    fn build_keyword_index(&mut self) {
        self.keyword_to_rules.clear();
        self.no_keyword_rules.clear();
        for id in &self.ordered_rules {
            let Some(rule) = self.rules.get(id) else { continue };
            if rule.keywords.is_empty() {
                self.no_keyword_rules.push(id.clone());
                continue;
            }
            for k in &rule.keywords {
                self.keyword_to_rules.entry(k.clone()).or_default().push(id.clone());
            }
        }
    }

    /// Run [`Rule::validate`] over every rule, in catalogue order.
    pub fn validate_rules(&mut self) -> Result<(), ConfigError> {
        let ids = self.ordered_rules.clone();
        for id in ids {
            if let Some(rule) = self.rules.get_mut(&id) {
                rule.validate()?;
            }
        }
        Ok(())
    }

    pub fn prefilter_program(&self) -> &Program {
        &self.prefilter_program
    }
    pub fn set_prefilter_program(&mut self, p: Program) {
        self.prefilter_program = p;
    }
    pub fn filter_program(&self) -> &Program {
        &self.filter_program
    }
    pub fn set_filter_program(&mut self, p: Program) {
        self.filter_program = p;
    }
}

/// Go `legacyComponentWithin` — renders the deprecated `withinLines` /
/// `withinColumns` pair into the `within` grammar.
fn legacy_component_within(lines: Option<i64>, columns: Option<i64>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(l) = lines {
        parts.push(format!("{l}L"));
    }
    if let Some(c) = columns {
        parts.push(format!("{c}C"));
    }
    parts.join(",")
}

/// Go `validateMinVersion`.
///
/// **This function WARNS; it does not fail** (except on an unparseable version).
/// It is also skipped entirely on a dev build — and an unstamped build reports
/// `version::VERSION == version::DEFAULT_MSG`, so on the default path this is a
/// no-op. Ported faithfully, including that short-circuit.
///
/// **Reshape (flagged):** Go uses `hashicorp/go-version`, which is LAXER than
/// strict semver. Pulling the `semver` crate would reject inputs Go accepts, so
/// the comparison is a hand-rolled numeric-triple compare after stripping a
/// leading `v`.
fn validate_min_version(
    gitleaks_min_ver: &str,
    betterleaks_min_ver: &str,
    config_path: &str,
) -> Result<(), ConfigError> {
    let is_dev = version::VERSION == version::DEFAULT_MSG;

    if !gitleaks_min_ver.is_empty() {
        if is_dev {
            logging::debug()
                .str("required", gitleaks_min_ver)
                .msg("dev build, skipping gitleaks minVersion check.");
        } else {
            let min = parse_semver(gitleaks_min_ver)
                .ok_or_else(|| ConfigError::InvalidMinVersion(gitleaks_min_ver.to_string()))?;
            let compat = parse_semver(version::GITLEAKS_COMPAT)
                .ok_or_else(|| ConfigError::InvalidMinVersion(version::GITLEAKS_COMPAT.to_string()))?;
            if compat < min {
                logging::warn()
                    .str("required", gitleaks_min_ver)
                    .str("current", version::GITLEAKS_COMPAT)
                    .str("config path", config_path)
                    .msg("config minVersion exceeds this build's gitleaks compatibility level");
            }
        }
    }

    if !betterleaks_min_ver.is_empty() && is_dev {
        logging::debug()
            .str("required", betterleaks_min_ver)
            .msg("dev build, skipping betterleaks minVersion check.");
    }

    Ok(())
}

/// Strip an optional leading `v` and read a numeric triple. Missing components
/// are 0, matching go-version's tolerance for `v1` and `v1.2`.
fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim();
    let s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
    // Drop any pre-release / build metadata before comparing.
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let mut it = core.split('.');
    let major = it.next()?.parse::<u64>().ok()?;
    let minor = it.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = it.next().map_or(Some(0), |p| p.parse().ok())?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests;
