//! Port of Go `sources/scm` (M15) — the SCM platform enum and the shared,
//! token-safe git clone helper.
//!
//! **Credentials never reach the command line or the remote URL.** The token is
//! injected as a temporary git config entry through `GIT_CONFIG_*` environment
//! variables, and every string that could carry it back out (errors, git
//! output) goes through [`sanitize_output`] first. That design is the reason
//! this is a `git` SUBPROCESS wrapper rather than a git library binding.

use std::collections::BTreeMap;
use std::fmt;

/// Go `scm.Platform`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Platform {
    #[default]
    Unknown,
    /// Explicitly disables the feature (Go `NoPlatform`).
    None,
    GitHub,
    GitLab,
    AzureDevOps,
    Gitea,
    Bitbucket,
}

impl Platform {
    /// Go `Platform.String()`.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Unknown => "unknown",
            Platform::None => "none",
            Platform::GitHub => "github",
            Platform::GitLab => "gitlab",
            Platform::AzureDevOps => "azuredevops",
            Platform::Gitea => "gitea",
            Platform::Bitbucket => "bitbucket",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Go `PlatformFromString`. An EMPTY string is `Unknown`, not an error.
pub fn platform_from_string(s: &str) -> Result<Platform, String> {
    match s.to_lowercase().as_str() {
        "" | "unknown" => Ok(Platform::Unknown),
        "none" => Ok(Platform::None),
        "github" => Ok(Platform::GitHub),
        "gitlab" => Ok(Platform::GitLab),
        "azuredevops" => Ok(Platform::AzureDevOps),
        "gitea" => Ok(Platform::Gitea),
        "bitbucket" => Ok(Platform::Bitbucket),
        other => Err(format!("invalid scm platform value: {other}")),
    }
}

/// Go `scm.GitConfig` — one `-c key=value` equivalent, passed via env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitConfig {
    pub key: String,
    pub value: String,
}

/// Go `scm.CloneOptions`. The zero value is valid: a full, non-bare,
/// non-mirror clone.
#[derive(Debug, Clone, Default)]
pub struct CloneOptions {
    /// `--bare` — no working tree. Recommended for scanning, which only needs
    /// objects.
    pub bare: bool,
    /// `--mirror` (implies bare) — the full ref set, including PR refs and tags.
    pub mirror: bool,
    /// `--single-branch`.
    pub single_branch: bool,
    /// `--depth N` when > 0.
    pub depth: u32,
    /// Extra git config applied to THIS invocation only.
    pub configs: Vec<GitConfig>,
}

/// Build the argv for `git clone`, in Go's exact order.
///
/// Split out from the process spawn so the argument construction — the part
/// that must not leak a credential — is testable without running git.
pub fn clone_args(remote: &str, dest: &str, opts: &CloneOptions) -> Vec<String> {
    let mut args = vec!["clone".to_string(), "--quiet".to_string()];
    // Go: mirror wins over bare, they are not combined.
    if opts.mirror {
        args.push("--mirror".to_string());
    } else if opts.bare {
        args.push("--bare".to_string());
    }
    if opts.single_branch {
        args.push("--single-branch".to_string());
    }
    if opts.depth > 0 {
        args.push("--depth".to_string());
        args.push(opts.depth.to_string());
    }
    args.push(remote.to_string());
    args.push(dest.to_string());
    args
}

/// Go `authCloneConfigs` — turn a token into an `http.<scheme>://<host>.extraHeader`
/// config entry.
///
/// Returns nothing (not an error) for an empty token, an SSH remote, or a
/// non-HTTP scheme: none of those can carry a bearer token, and Go passes them
/// through untouched.
pub fn auth_clone_configs(remote: &str, token: &str) -> Result<Vec<GitConfig>, String> {
    if token.is_empty() || is_ssh_remote(remote) {
        return Ok(Vec::new());
    }
    let Some((scheme, rest)) = remote.split_once("://") else {
        return Ok(Vec::new());
    };
    if scheme != "http" && scheme != "https" {
        return Ok(Vec::new());
    }
    // Host is everything up to the first '/', minus any userinfo.
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return Err(format!("cannot parse host from remote: {remote}"));
    }
    let cred = base64_encode(format!("x-access-token:{token}").as_bytes());
    Ok(vec![GitConfig {
        key: format!("http.{scheme}://{host}.extraHeader"),
        value: format!("Authorization: basic {cred}"),
    }])
}

/// Go `isSSHRemote` — the scp-style remote GitHub and friends emit
/// (`git@github.com:owner/repo.git`), which is NOT a parseable RFC 3986 URL.
pub fn is_ssh_remote(s: &str) -> bool {
    if s.starts_with("ssh://") {
        return true;
    }
    let Some(at) = s.find('@') else { return false };
    if at == 0 {
        return false;
    }
    let Some(colon) = s[at..].find(':') else { return false };
    if colon == 0 {
        return false;
    }
    // Reject `http(s)://user:pass@host:` forms.
    !s[..at].contains("://")
}

/// Go `gitCloneEnv` — the environment overrides applied to a clone.
///
/// Returns only the OVERRIDES (Go merges them into `os.Environ()`); keeping them
/// separate makes the set testable and makes the caller's merge explicit.
///
/// The point of `GIT_CONFIG_GLOBAL`/`SYSTEM` pointing at the null device is that
/// the clone must not pick up ambient credentials or rewrite rules from the
/// user's own git config.
pub fn git_clone_env(configs: &[GitConfig]) -> BTreeMap<String, String> {
    // ⚠ DELIBERATE DIVERGENCE FROM GO — a fix, not a port slip.
    //
    // Go picks `NUL` on Windows (`runtime.GOOS == "windows"`). Git for Windows is
    // an MSYS2 build and does NOT accept it:
    //
    //     GIT_CONFIG_GLOBAL=NUL git -C repo log -p
    //     fatal: unable to access 'NUL': Invalid argument     (exit 128, no output)
    //
    // Measured on git 2.55. The consequence upstream is not a cosmetic warning —
    // running the Go binary against a repository containing a live-format AWS key
    // produces:
    //
    //     ERR failed to scan Git repository error="git stderr: fatal: unable to access 'NUL'"
    //     WRN scanned ~0 bytes (0)
    //     WRN no leaks found in partial scan
    //
    // i.e. git history scanning is entirely non-functional on Windows AND the
    // failure is reported as a clean result. `/dev/null` is what git itself
    // documents for disabling a config file and works on every platform here, so
    // the port uses it unconditionally. Recorded in PORT-TRACK.md § Deviations.
    let null_device = "/dev/null";
    let mut overrides = BTreeMap::new();
    overrides.insert("GIT_CONFIG_GLOBAL".to_string(), null_device.to_string());
    overrides.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    overrides.insert("GIT_CONFIG_SYSTEM".to_string(), null_device.to_string());
    overrides.insert("GIT_NO_REPLACE_OBJECTS".to_string(), "1".to_string());
    overrides.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());

    if !configs.is_empty() {
        overrides.insert("GIT_CONFIG_COUNT".to_string(), configs.len().to_string());
        for (i, cfg) in configs.iter().enumerate() {
            overrides.insert(format!("GIT_CONFIG_KEY_{i}"), cfg.key.clone());
            overrides.insert(format!("GIT_CONFIG_VALUE_{i}"), cfg.value.clone());
        }
    }
    overrides
}

/// Go `CloneAuthed` — clone `remote` into `dest`, authenticating with `token`
/// if the remote is HTTP(S).
///
/// The token is passed through git config env vars, never on the command line,
/// and every returned message is sanitized.
pub fn clone_authed(
    remote: &str,
    token: &str,
    dest: &str,
    opts: &CloneOptions,
) -> Result<(), String> {
    if remote.is_empty() {
        return Err("scm.CloneAuthed: empty remote".to_string());
    }
    if dest.is_empty() {
        return Err("scm.CloneAuthed: empty dest".to_string());
    }

    let auth = auth_clone_configs(remote, token).map_err(|e| format!("clone auth config: {e}"))?;
    let mut configs = opts.configs.clone();
    configs.extend(auth);

    let args = clone_args(remote, dest, opts);
    let mut cmd = std::process::Command::new("git");
    cmd.args(&args);
    for (k, v) in git_clone_env(&configs) {
        cmd.env(k, v);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("git clone {}: {e}", sanitize_output(remote, token)))?;
    if !out.status.success() {
        // Go uses CombinedOutput; both streams are sanitized before surfacing.
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        return Err(format!(
            "git clone {}: exit {}: {}",
            sanitize_output(remote, token),
            out.status.code().unwrap_or(-1),
            sanitize_output(&combined, token)
        ));
    }
    Ok(())
}

/// Go `SanitizeOutput` — redact the token (and its URL-encoded form) and strip
/// userinfo from any `https://user:pass@host` URL.
///
/// Use this on ANY text that may have come from a git invocation before logging
/// or wrapping it.
pub fn sanitize_output(text: &str, token: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut out = text.to_string();
    if !token.is_empty() {
        out = out.replace(token, "***");
        let encoded = query_escape(token);
        if encoded != token {
            out = out.replace(&encoded, "***");
        }
    }
    // Go: `(https?)://[^/\s@]+@` -> `$1://***@`
    let re = regexp::must_compile(r"(https?)://[^/\s@]+@");
    re.replace_all(&out, "$1://***@")
}

/// Go `url.QueryEscape` — percent-encoding with `+` for space.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Standard base64, hand-rolled — the same call this crate would otherwise pull
/// a dependency for, and the `codec` port already establishes the precedent.
fn base64_encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests;
