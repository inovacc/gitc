//! Port of Go `internal/redact` — mask credentials embedded in git argument
//! vectors before they are written to the forensic audit log.
//!
//! The backend still executes the real, unmodified arguments — only the STORED
//! copy is masked. It strips only unambiguous secrets (URL userinfo, Authorization
//! tokens) while preserving everything forensically useful (command, host, path,
//! remaining flags).

use regex::Regex;
use std::sync::OnceLock;

const MASK: &str = "***";

/// URL scheme + userinfo + `@`, e.g. `https://user:pass@host` / `https://tok@host`.
fn url_cred() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/@\s]+)@").unwrap())
}

/// An Authorization header value, e.g. `Authorization: Bearer x`.
fn auth_header() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(authorization:\s*[a-z]+\s+)(\S+)").unwrap())
}

/// Go `Args` — a copy of `args` with embedded credentials masked; the input is
/// not modified.
pub fn args(args: &[String]) -> Vec<String> {
    args.iter().map(|a| string(a)).collect()
}

/// Go `String` — mask credentials found anywhere in `s`.
pub fn string(s: &str) -> String {
    let stripped = url_cred().replace_all(s, |caps: &regex::Captures| {
        let scheme = &caps[1];
        let userinfo = &caps[2];
        // user:pass -> keep the username, mask the secret; a single field
        // (typically a token used as the username) is masked whole.
        match userinfo.find(':') {
            Some(i) => format!("{scheme}{}:{MASK}@", &userinfo[..i]),
            None => format!("{scheme}{MASK}@"),
        }
    });
    auth_header()
        .replace_all(&stripped, format!("${{1}}{MASK}").as_str())
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_masks_credentials() {
        let cases = [
            (
                "https://alice:s3cr3t@github.com/x.git",
                "https://alice:***@github.com/x.git",
            ),
            (
                "https://ghp_ABC123def456@github.com/x.git",
                "https://***@github.com/x.git",
            ),
            ("ssh://git:key@host:22/repo", "ssh://git:***@host:22/repo"),
            (
                "https://github.com/inovacc/gitc.git",
                "https://github.com/inovacc/gitc.git",
            ),
            ("status", "status"),
            (
                "Authorization: Bearer abcdef123",
                "Authorization: Bearer ***",
            ),
            (
                "authorization: Basic dXNlcjpwYXNz",
                "authorization: Basic ***",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(string(input), want, "String({input:?})");
        }
    }

    #[test]
    fn args_masks_and_copies() {
        let input = vec![
            "clone".to_string(),
            "https://x:tok@github.com/r.git".to_string(),
        ];
        let got = args(&input);
        assert_eq!(got[1], "https://x:***@github.com/r.git");
        assert!(!got.join(" ").contains("tok@"), "token leaked: {got:?}");
        // must not mutate the input.
        assert_eq!(input[1], "https://x:tok@github.com/r.git");
    }
}
