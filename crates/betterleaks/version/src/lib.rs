//! Port of Go `version/version.go`.
//!
//! **Reshape (flagged):** Go declares `DefaultMsg` and `Version` as package-level
//! `var`s precisely so a release build can overwrite them with
//! `-ldflags "-X version.Version=…"`. Rust has no link-time string injection, so
//! the port reads `option_env!` at COMPILE time instead — set `BETTERLEAKS_VERSION`
//! / `BETTERLEAKS_DEFAULT_MSG` in the build environment to stamp a real version.
//! Both default to `"dev"`, matching an unstamped Go build. The Go source comment
//! "these two gotta be the same" is preserved as an invariant test.

/// Go `version.DefaultMsg`.
pub const DEFAULT_MSG: &str = match option_env!("BETTERLEAKS_DEFAULT_MSG") {
    Some(v) => v,
    None => "dev",
};

/// Go `version.Version`.
pub const VERSION: &str = match option_env!("BETTERLEAKS_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// Go `version.GitleaksCompat` — the gitleaks config format version this build
/// supports, checked against a config file's `minVersion` field.
pub const GITLEAKS_COMPAT: &str = "8.25.0";

#[cfg(test)]
mod tests {
    use super::*;

    /// Characterization (no Go test): the unstamped defaults.
    #[test]
    fn unstamped_defaults_are_dev() {
        // Only assert the default when the build did NOT stamp a version;
        // otherwise this test would fail a legitimately-stamped release build.
        if option_env!("BETTERLEAKS_VERSION").is_none() {
            assert_eq!(VERSION, "dev");
        }
        if option_env!("BETTERLEAKS_DEFAULT_MSG").is_none() {
            assert_eq!(DEFAULT_MSG, "dev");
        }
    }

    /// The Go source's own stated invariant: "these two gotta be the same".
    #[test]
    fn default_msg_and_version_agree() {
        if option_env!("BETTERLEAKS_VERSION").is_none()
            && option_env!("BETTERLEAKS_DEFAULT_MSG").is_none()
        {
            assert_eq!(DEFAULT_MSG, VERSION);
        }
    }

    /// Characterization (no Go test): the compat constant is a wire-visible
    /// value compared against config `minVersion`, so pin it byte-for-byte.
    #[test]
    fn gitleaks_compat_pinned() {
        assert_eq!(GITLEAKS_COMPAT, "8.25.0");
    }
}
