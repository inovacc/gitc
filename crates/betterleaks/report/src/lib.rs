//! Faithful port of Go `report`.
//!
//! Ported: [`Finding`] and its helpers, the JSON / CSV / SARIF / JUnit
//! emitters, both verbose printers ([`print_pretty`] and [`print_legacy`]), and
//! [`ValidationStatus`].
//!
//! **Not ported: the `template` format.** It renders a user-supplied Go
//! `text/template`, which means porting a templating LANGUAGE rather than a
//! report writer. The CLI refuses `--report-format template` with a message
//! saying so, rather than emitting some other format under that name.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

mod csv;
mod finding;
mod json;
mod print_legacy;
mod print_pretty;
mod junit;
mod reporter;
mod sarif;
pub mod template;
pub use csv::CsvReporter;
pub use finding::{ComponentFinding, ComponentSet, Finding, Fragment};
pub use json::JsonReporter;
pub use print_legacy::{format_match_context, locate_match, print_legacy};
pub use print_pretty::{print_pretty, redact_for_display};
pub use junit::JunitReporter;
pub use reporter::{Reporter, CWE, CWE_DESCRIPTION, STDOUT_REPORT_PATH};
pub use sarif::SarifReporter;

/// The liveness state of a finding's secret, as determined by the validation
/// engine (faithful port of Go `report.ValidationStatus`).
///
/// Go models this as `type ValidationStatus string` — a string-backed type whose
/// *value* can be any string (callers build one from dynamic input, e.g.
/// `ValidationStatus(strings.ToLower(s))`). So the faithful Rust model is a
/// newtype over `Cow<'static, str>` (const-friendly for the known values, owned
/// for dynamic ones) — NOT a closed enum, which would forbid arbitrary strings.
/// `Deserialize` too, so a previous JSON report can be read back as a baseline.
/// The newtype is transparent both ways, which keeps a round trip exact.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidationStatus(pub Cow<'static, str>);

impl Default for ValidationStatus {
    /// Go zero value is `ValidationStatusNone` (`""`).
    fn default() -> Self {
        ValidationStatus::NONE
    }
}

impl ValidationStatus {
    /// Zero value: no validation was performed (Go `ValidationStatusNone = ""`).
    pub const NONE: ValidationStatus = ValidationStatus(Cow::Borrowed(""));
    /// The secret was confirmed active.
    pub const VALID: ValidationStatus = ValidationStatus(Cow::Borrowed("valid"));
    /// Could not be validated automatically; needs a manual check.
    pub const NEEDS_VALIDATION: ValidationStatus =
        ValidationStatus(Cow::Borrowed("needs_validation"));
    /// The secret was rejected by the provider.
    pub const INVALID: ValidationStatus = ValidationStatus(Cow::Borrowed("invalid"));
    /// The secret is known to be revoked.
    pub const REVOKED: ValidationStatus = ValidationStatus(Cow::Borrowed("revoked"));
    /// Validation produced an indeterminate result.
    pub const UNKNOWN: ValidationStatus = ValidationStatus(Cow::Borrowed("unknown"));
    /// Validation could not be completed due to an error.
    pub const ERROR: ValidationStatus = ValidationStatus(Cow::Borrowed("error"));

    /// Build a status from a dynamic string (mirrors Go's `ValidationStatus(s)`
    /// cast — the value need not be one of the known constants).
    pub fn from_string(s: String) -> Self {
        ValidationStatus(Cow::Owned(s))
    }

    /// The underlying string value (Go's `String()` / the string cast).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Characterization test: Go `validation_status.go` has no tests of its own,
    // so this pins the observable behavior (constant string values, `String()`,
    // and dynamic construction) that `internal/validate` relies on.
    #[test]
    fn constants_and_string_value() {
        assert_eq!(ValidationStatus::NONE.as_str(), "");
        assert_eq!(ValidationStatus::VALID.as_str(), "valid");
        assert_eq!(ValidationStatus::NEEDS_VALIDATION.as_str(), "needs_validation");
        assert_eq!(ValidationStatus::INVALID.as_str(), "invalid");
        assert_eq!(ValidationStatus::REVOKED.as_str(), "revoked");
        assert_eq!(ValidationStatus::UNKNOWN.as_str(), "unknown");
        assert_eq!(ValidationStatus::ERROR.as_str(), "error");
        // String() / Display
        assert_eq!(ValidationStatus::VALID.to_string(), "valid");
        // Dynamic construction (the arbitrary-string capability) + equality with a
        // known constant.
        assert_eq!(ValidationStatus::from_string("valid".to_string()), ValidationStatus::VALID);
        assert_eq!(ValidationStatus::from_string("bogus".to_string()).as_str(), "bogus");
    }
}
