//! Port of Go `internal/origin` — pin the upstream repository URLs gitc may talk
//! to and guard each with a sha256 of its URL string.
//!
//! The URLs are compile-time constants (no runtime override). [`verify`]
//! recomputes each URL's digest and refuses to proceed on a mismatch, so a
//! supply-chain edit that redirects a URL cannot pass silently. This is
//! tamper-evidence + fail-closed behavior, not a claim that source cannot be edited.

use sha2::{Digest, Sha256};

/// The canonical gitc repository — self-update endpoints derive from this only.
pub const GITC_REPO: &str = "https://github.com/inovacc/gitc";
/// `sha256(GITC_REPO)`, enforced by [`verify`].
pub const GITC_REPO_SHA256: &str =
    "73f5c1a10b1e134ff8b44857a065e51e5cec7af976ce157c155daf124ed1eab7";

/// The upstream MinGit source repository.
pub const GIT_FOR_WINDOWS_REPO: &str = "https://github.com/git-for-windows/git";
/// `sha256(GIT_FOR_WINDOWS_REPO)`, enforced by [`verify`].
pub const GIT_FOR_WINDOWS_REPO_SHA256: &str =
    "e83ef8ed2fa5ca9e95eb11db22eea2ffcfce65cdde1f92ee5b552dd9c9dc05c9";

const GITHUB_PREFIX: &str = "https://github.com/";

/// The base message of Go's `ErrTampered`.
const TAMPERED_MSG: &str = "origin: pinned repository URL failed its sha256 integrity check";

/// A pinned-origin error (Go returns `error`; `ErrTampered` is matched via
/// [`Error::Tampered`]).
#[derive(Debug)]
pub enum Error {
    /// A pinned URL did not match its recorded digest (Go `ErrTampered`).
    Tampered(String),
    /// The repository is not one of the pinned constants.
    NotPinned(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Tampered(detail) => write!(f, "{TAMPERED_MSG}: {detail}"),
            Error::NotPinned(url) => write!(f, "origin: {url:?} is not a pinned repository"),
        }
    }
}

impl std::error::Error for Error {}

/// A URL constant paired with its expected digest.
struct Pin {
    url: &'static str,
    sha256: &'static str,
}

fn pins() -> [Pin; 2] {
    [
        Pin {
            url: GITC_REPO,
            sha256: GITC_REPO_SHA256,
        },
        Pin {
            url: GIT_FOR_WINDOWS_REPO,
            sha256: GIT_FOR_WINDOWS_REPO_SHA256,
        },
    ]
}

/// Go `Verify` — recompute every pinned URL's sha256; `Err(Tampered)` on mismatch.
pub fn verify() -> Result<(), Error> {
    verify_pins(&pins())
}

/// Go (unexported) `verify` — check an explicit pin set (so tests can exercise a
/// tampered set without mutating the package global).
fn verify_pins(ps: &[Pin]) -> Result<(), Error> {
    for p in ps {
        let got = sha256_hex(p.url);
        if got != p.sha256 {
            return Err(Error::Tampered(format!(
                "{} (got {}, want {})",
                p.url, got, p.sha256
            )));
        }
    }
    Ok(())
}

/// Go `APIBase` — verify all pins, then return the GitHub REST base for `repo_url`
/// (`https://api.github.com/repos/<owner>/<repo>`). `repo_url` must be pinned.
pub fn api_base(repo_url: &str) -> Result<String, Error> {
    verify()?;
    if !is_pinned(repo_url) {
        return Err(Error::NotPinned(repo_url.to_string()));
    }
    let tail = repo_url.strip_prefix(GITHUB_PREFIX).unwrap_or(repo_url);
    Ok(format!("https://api.github.com/repos/{tail}"))
}

fn is_pinned(repo_url: &str) -> bool {
    pins().iter().any(|p| p.url == repo_url)
}

/// Lowercase-hex sha256 of `s`.
fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_match_independent_record() {
        // An INDEPENDENT record — drift requires editing the constant, its digest,
        // AND this table (mirrors the Go test's triple-edit tripwire).
        let want = [
            (GITC_REPO, GITC_REPO_SHA256),
            (GIT_FOR_WINDOWS_REPO, GIT_FOR_WINDOWS_REPO_SHA256),
        ];
        assert_eq!(GITC_REPO_SHA256, want[0].1);
        assert_eq!(GIT_FOR_WINDOWS_REPO_SHA256, want[1].1);
        for (url, w) in want {
            assert_eq!(sha256_hex(url), w, "sha256({url})");
        }
    }

    #[test]
    fn verify_passes() {
        verify().expect("Verify on unmodified pins");
    }

    #[test]
    fn verify_detects_tamper() {
        // A swapped URL kept against the old digest — the supply-chain edit the pin
        // exists to catch.
        let tampered = [Pin {
            url: "https://github.com/evil/redirect",
            sha256: GITC_REPO_SHA256,
        }];
        assert!(
            matches!(verify_pins(&tampered), Err(Error::Tampered(_))),
            "verify should return Tampered on a swapped URL"
        );
    }

    #[test]
    fn api_base_derives_and_rejects() {
        assert_eq!(
            api_base(GITC_REPO).unwrap(),
            "https://api.github.com/repos/inovacc/gitc"
        );
        assert!(api_base("https://github.com/someone/else").is_err());
    }
}
