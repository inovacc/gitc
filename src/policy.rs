//! Port of Go `internal/policy` — the machine/org enforcement policy plus gitc's
//! opinionated passthrough defaults.
//!
//! Two responsibilities live here, as in the Go package:
//!
//! - **Enforcement** ([`Policy`], [`load_policy`]): a `policy.json` gitc reads but
//!   never lets a git flag override, so an AI agent flowing through the shim cannot
//!   disable a gate at the command line. An ABSENT policy file means no enforcement
//!   — enforcement is strictly opt-in by dropping a `policy.json`. Covers the
//!   secret gate ([`Policy::secret_gate_applies`]) and the remote allowlist
//!   ([`Policy::remote_refs`] / [`Policy::remote_allowed`]).
//! - **Passthrough defaults** ([`init_needs_branch`] / [`inject_initial_branch`]):
//!   new repositories default their initial branch to `main` instead of `master`,
//!   never overriding an explicit user choice.
//!
//! This is SECURITY code (remote-allowlist / secret-gate); the value-consuming
//! flag maps per subcommand and the scp-style URL host/owner extraction are
//! preserved bug-for-bug against the Go source so a value-flag desync cannot
//! smuggle an exfil URL past the check (SEC-3) and low-level push plumbing is
//! vetted too (SEC-5).

use std::path::Path;

use crate::gitargs::subcommand_index;

/// The machine/org enforcement policy (`policy.json`). A zero value enforces
/// nothing (a missing file yields this via [`load_policy`]).
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Policy schema version.
    pub version: i64,
    /// The secret gate (Go `secretGate`).
    #[serde(rename = "secretGate")]
    pub secret_gate: SecretGate,
    /// The remote allowlist (Go `remoteAllowlist`).
    #[serde(rename = "remoteAllowlist")]
    pub remote_allow: RemoteAllowlist,
    /// External pre/post stage commands run around git core. Rust-only addition
    /// (no Go analog) — see [`Stages`].
    pub stages: Stages,
}

/// External commands run around git core, from the MACHINE policy only.
///
/// ## Why this lives in `policy.json` and not in user settings
///
/// A pre stage can refuse a git command and a post stage runs on every single git
/// invocation — so "which program runs here" is a privilege decision, not a
/// preference. `policy.json` is resolved from the admin-owned machine directory
/// (`%ProgramData%` / `/etc`), which the user-writable settings file and the
/// environment are not. Sourcing stage commands from a user-writable file would
/// hand any local process a persistence hook that executes on every `git` call.
/// There is deliberately **no environment-variable override** for the same reason.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct Stages {
    /// Commands run BEFORE git core. A non-zero exit blocks git (see [`StageCmd`]).
    pub pre: Vec<StageCmd>,
    /// Commands run AFTER git core. Advisory — the exit code is ignored.
    pub post: Vec<StageCmd>,
}

/// One external stage command.
///
/// `run` is the program path plus its fixed arguments; the git argv is NOT appended
/// (a stage that wants it reads `GITC_STAGE_ARGV`), so a stage cannot be turned into
/// an argument-injection vector by a crafted git command line.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct StageCmd {
    /// A short label used in diagnostics.
    pub name: String,
    /// Program path followed by fixed arguments. Empty entries are ignored.
    pub run: Vec<String>,
    /// Per-command timeout in milliseconds; 0 means [`STAGE_DEFAULT_TIMEOUT_MS`].
    ///
    /// A stage that hangs would hang every git invocation on the machine, so the
    /// timeout is not optional — it only selects the value.
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
}

/// Timeout applied to a [`StageCmd`] that does not set its own.
pub const STAGE_DEFAULT_TIMEOUT_MS: u64 = 5_000;

impl StageCmd {
    /// The effective timeout, substituting the default for 0.
    pub fn timeout(&self) -> std::time::Duration {
        let ms = if self.timeout_ms == 0 {
            STAGE_DEFAULT_TIMEOUT_MS
        } else {
            self.timeout_ms
        };
        std::time::Duration::from_millis(ms)
    }
}

/// Blocks a gated git command when a working-tree secret scan finds anything.
/// `commands` defaults to commit + push when empty. `mode` "warn" reports findings
/// but lets the command proceed; the default (empty / "block") refuses.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct SecretGate {
    /// Whether the gate is active.
    pub enabled: bool,
    /// Gated subcommands; empty means the commit + push default.
    pub commands: Vec<String>,
    /// "warn" reports but proceeds; anything else (incl. empty / "block") refuses.
    pub mode: String,
}

impl SecretGate {
    /// Reports whether a finding should refuse the command rather than warn.
    pub fn blocks(&self) -> bool {
        self.mode != "warn"
    }
}

/// Blocks push/fetch/clone to a URL whose host (or host/owner) is not listed,
/// preventing exfiltration to unapproved hosts.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct RemoteAllowlist {
    /// Whether the allowlist is enforced.
    pub enabled: bool,
    /// Permitted `host` or `host/owner` entries.
    pub hosts: Vec<String>,
}

/// An error loading `policy.json` (Go returned `error`).
#[derive(Debug)]
pub enum Error {
    /// The file existed but could not be read.
    Io(std::io::Error),
    /// The file's JSON did not parse (Go `parse policy <path>: <err>`).
    Parse {
        /// The policy path that failed to parse.
        path: String,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Parse { path, source } => write!(f, "parse policy {path}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse { source, .. } => Some(source),
        }
    }
}

/// Reads `policy.json`. A missing file yields a zero (no-enforcement) [`Policy`]
/// with `Ok`. Faithful port of Go `LoadPolicy`.
pub fn load_policy(path: &Path) -> Result<Policy, Error> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Policy::default()),
        Err(e) => return Err(Error::Io(e)),
    };

    serde_json::from_slice(&data).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })
}

impl Policy {
    /// Reports whether `args` is a gated command (commit/push by default) with the
    /// secret gate enabled. Faithful port of Go `SecretGateApplies`.
    pub fn secret_gate_applies(&self, args: &[String]) -> bool {
        if !self.secret_gate.enabled {
            return false;
        }

        let sub = match subcommand_of(args) {
            Some(s) => s,
            None => return false,
        };

        if self.secret_gate.commands.is_empty() {
            sub == "commit" || sub == "push"
        } else {
            self.secret_gate.commands.iter().any(|c| c == sub)
        }
    }

    /// Returns the remote references a remote-facing command targets — URL
    /// arguments and configured remote NAMES — for the allowlist to vet, plus
    /// whether the command relies on an implicit/default remote (a bare
    /// `git push`), which the caller resolves to the branch's configured remote.
    /// Empty when the allowlist is disabled or the command is not remote-facing.
    /// Faithful port of Go `RemoteRefs` (returns `(refs, uses_default)`).
    pub fn remote_refs(&self, args: &[String]) -> (Vec<String>, bool) {
        if !self.remote_allow.enabled {
            return (Vec::new(), false);
        }

        let idx = match subcommand_index(args) {
            Some(i) => i,
            None => return (Vec::new(), false),
        };

        let sub = args[idx].as_str();
        // send-pack / http-push are low-level push plumbing whose first positional
        // is the destination remote — they exfil just like push and must be vetted
        // too (SEC-5).
        match sub {
            "push" | "fetch" | "pull" | "clone" | "remote" | "send-pack" | "http-push" => {}
            _ => return (Vec::new(), false),
        }

        let pos = positionals_for(sub, &args[idx + 1..]);

        match sub {
            "clone" => {
                if !pos.is_empty() {
                    (vec![pos[0].clone()], false) // the clone source URL
                } else {
                    (Vec::new(), false)
                }
            }
            "remote" => {
                // e.g. `remote add <name> <url>`
                let urls: Vec<String> = pos.into_iter().filter(|a| is_remote_url(a)).collect();
                (urls, false)
            }
            // push/fetch/pull/send-pack/http-push: first positional is the remote.
            _ => {
                if pos.is_empty() {
                    return (Vec::new(), true);
                }

                // The first positional is the remote. Also vet any OTHER positional
                // that is itself a remote URL, so a value-flag desync cannot smuggle
                // an exfil URL past the check (e.g. `push -o opt evil.com:repo`).
                let mut refs = vec![pos[0].clone()];
                for a in &pos[1..] {
                    if is_remote_url(a) {
                        refs.push(a.clone());
                    }
                }

                (refs, false)
            }
        }
    }

    /// Reports whether a remote URL's host (or host/owner) is permitted. Faithful
    /// port of Go `RemoteAllowed`.
    pub fn remote_allowed(&self, remote: &str) -> bool {
        if !self.remote_allow.enabled {
            return true;
        }

        let host = remote_host_owner(remote);
        let host_slash = format!("{host}/");
        for allowed in &self.remote_allow.hosts {
            if &host == allowed || host_slash.starts_with(&format!("{allowed}/")) {
                return true;
            }
        }

        false
    }
}

/// Per remote-facing subcommand, the flags that take a SEPARATE value argument
/// (the space form, e.g. `-o opt`). That value must be skipped when locating
/// positionals, else it is mistaken for the remote (SEC-3). The `--flag=value`
/// form carries its own value and never consumes the next token, so it is not
/// matched here. Faithful port of Go `valueConsumingFlags`.
fn value_consuming_flags(sub: &str) -> &'static [&'static str] {
    match sub {
        "push" => &[
            "-o",
            "--push-option",
            "--receive-pack",
            "--exec",
            "--repo",
            "--force-with-lease",
        ],
        "fetch" => &[
            "--upload-pack",
            "--exec",
            "--depth",
            "--deepen",
            "--refmap",
            "--shallow-since",
            "--shallow-exclude",
            "--negotiation-tip",
            "--server-option",
            "-o",
        ],
        "pull" => &[
            "--upload-pack",
            "--exec",
            "--depth",
            "--deepen",
            "-s",
            "--strategy",
            "-X",
            "--strategy-option",
            "--shallow-since",
            "--shallow-exclude",
            "--server-option",
        ],
        "send-pack" => &["--receive-pack", "--exec", "--max-pack-size"],
        "http-push" => &[],
        "clone" => &[
            "-u",
            "--upload-pack",
            "-b",
            "--branch",
            "-o",
            "--origin",
            "-c",
            "--config",
            "--reference",
            "--reference-if-able",
            "--depth",
            "--template",
            "-j",
            "--jobs",
            "--filter",
            "--separate-git-dir",
            "--shallow-since",
            "--shallow-exclude",
            "--server-option",
            "--bundle-uri",
        ],
        _ => &[],
    }
}

/// Returns the non-flag arguments for a subcommand, skipping the values of that
/// subcommand's value-consuming flags (space form) and treating a bare `--` as
/// the end of options. This locates the true remote positional even when preceded
/// by a value flag. Faithful port of Go `positionalsFor`.
fn positionals_for(sub: &str, args: &[String]) -> Vec<String> {
    let consumes = value_consuming_flags(sub);
    let mut out = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let a = &args[i];

        if a == "--" {
            out.extend_from_slice(&args[i + 1..]);
            break;
        }

        if a.starts_with('-') {
            if consumes.contains(&a.as_str()) && i + 1 < args.len() {
                i += 1; // skip this flag's separate value
            }
            i += 1;
            continue;
        }

        out.push(a.clone());
        i += 1;
    }

    out
}

/// Reports whether `s` is a network git remote URL (scheme:// or scp-style
/// `git@host:path`) rather than a configured remote name or local path. Faithful
/// port of Go `IsRemoteURL` / `looksLikeRemoteURL`.
pub fn is_remote_url(s: &str) -> bool {
    if s.contains("://") {
        return true;
    }

    match (s.find('@'), s.find(':')) {
        (Some(at), Some(colon)) => colon > at, // git@host:owner/repo
        _ => false,
    }
}

/// Returns the git subcommand token past any leading global flags, or `None`.
/// Faithful port of Go `subcommandOf`.
fn subcommand_of(args: &[String]) -> Option<&str> {
    let idx = subcommand_index(args)?;
    Some(args[idx].as_str())
}

/// Extracts "host/owner" (or just "host") from a git remote URL, for matching
/// against allowlist entries. Faithful port of Go `remoteHostOwner`.
fn remote_host_owner(remote: &str) -> String {
    let mut s = remote.to_string();

    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
        if let Some(at) = s.find('@') {
            s = s[at + 1..].to_string(); // strip userinfo
        }
    } else if let Some(at) = s.find('@') {
        // scp-style git@host:owner/repo -> host/owner/repo
        s = s[at + 1..].to_string();
        s = s.replacen(':', "/", 1);
    }

    let parts: Vec<&str> = s.splitn(3, '/').collect();
    if parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts[0].to_string()
    }
}

/// Reports whether `args` is a `git init` invocation with no explicit
/// initial-branch choice, and returns the index of the `init` token. `None` means
/// pass `args` through unchanged. Faithful port of Go `InitNeedsBranch` (Go's
/// `(idx, ok)` → `Option<usize>`).
pub fn init_needs_branch(args: &[String]) -> Option<usize> {
    let idx = subcommand_index(args)?;
    if args[idx] != "init" {
        return None;
    }

    for a in &args[idx + 1..] {
        if a == "-b" || a == "--initial-branch" || a.starts_with("--initial-branch=") {
            return None;
        }
    }

    Some(idx)
}

/// Returns a copy of `args` with `--initial-branch=<branch>` inserted immediately
/// after the init token at `init_idx`. Faithful port of Go `InjectInitialBranch`.
pub fn inject_initial_branch(args: &[String], init_idx: usize, branch: &str) -> Vec<String> {
    let flag = format!("--initial-branch={branch}");
    let mut out = Vec::with_capacity(args.len() + 1);
    out.extend_from_slice(&args[..init_idx + 1]);
    out.push(flag);
    out.extend_from_slice(&args[init_idx + 1..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("gitc_policy_test_{}_{}", std::process::id(), name));
        p
    }

    fn contains(refs: &[String], want: &str) -> bool {
        refs.iter().any(|r| r == want)
    }

    #[test]
    fn load_policy_missing_is_empty() {
        let path = tmp_path("missing.json");
        let _ = std::fs::remove_file(&path);

        let p = load_policy(&path).expect("missing policy should not error");
        assert!(
            !p.secret_gate.enabled && !p.remote_allow.enabled,
            "absent policy must enforce nothing, got {p:?}"
        );
    }

    #[test]
    fn load_policy_parses() {
        let path = tmp_path("parses.json");
        let body = r#"{"version":1,"secretGate":{"enabled":true},"remoteAllowlist":{"enabled":true,"hosts":["github.com/inovacc"]}}"#;
        std::fs::write(&path, body).unwrap();

        let p = load_policy(&path).expect("LoadPolicy");
        assert!(
            p.secret_gate.enabled && p.remote_allow.enabled && p.remote_allow.hosts.len() == 1,
            "policy did not parse: {p:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn secret_gate_applies() {
        let on = Policy {
            secret_gate: SecretGate {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            on.secret_gate_applies(&argv(&["commit", "-m", "x"])),
            "commit should be gated"
        );
        assert!(
            on.secret_gate_applies(&argv(&["-c", "x=y", "push"])),
            "push behind a global flag should still be gated"
        );
        assert!(
            !on.secret_gate_applies(&argv(&["status"])),
            "status is not a gated command"
        );

        let off = Policy {
            secret_gate: SecretGate {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            !off.secret_gate_applies(&argv(&["commit"])),
            "disabled gate must not apply"
        );
    }

    #[test]
    fn remote_allowed() {
        let p = Policy {
            remote_allow: RemoteAllowlist {
                enabled: true,
                hosts: vec!["github.com/inovacc".to_string()],
            },
            ..Default::default()
        };

        assert!(
            !p.remote_allowed("https://github.com/evil/x.git"),
            "github.com/evil should be blocked"
        );
        assert!(
            p.remote_allowed("https://github.com/inovacc/gitc.git"),
            "github.com/inovacc should be allowed"
        );
        assert!(
            p.remote_allowed("git@github.com:inovacc/gitc.git"),
            "scp-style inovacc remote should be allowed"
        );

        let off = Policy {
            remote_allow: RemoteAllowlist {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            off.remote_allowed("https://anything/x"),
            "disabled allowlist must permit everything"
        );
    }

    #[test]
    fn remote_refs() {
        let p = Policy {
            remote_allow: RemoteAllowlist {
                enabled: true,
                hosts: vec!["github.com".to_string()],
            },
            ..Default::default()
        };

        // Explicit URL argument.
        let (refs, def) = p.remote_refs(&argv(&["push", "https://github.com/evil/x.git"]));
        assert!(
            refs.len() == 1 && !def,
            "url push: refs={refs:?} default={def}"
        );

        // Named remote → returned as a ref (the caller resolves it to a URL).
        let (refs, def) = p.remote_refs(&argv(&["push", "origin", "main"]));
        assert!(
            refs.len() == 1 && refs[0] == "origin" && !def,
            "named remote: refs={refs:?} default={def}"
        );

        // Bare push → uses the default/implicit remote.
        let (refs, def) = p.remote_refs(&argv(&["-c", "x=y", "push"]));
        assert!(
            refs.is_empty() && def,
            "bare push should use default remote: refs={refs:?} default={def}"
        );

        // Non-remote command and disabled allowlist → nothing to check.
        let (refs, _) = p.remote_refs(&argv(&["status"]));
        assert!(refs.is_empty(), "status is not remote-facing: {refs:?}");

        let off = Policy {
            remote_allow: RemoteAllowlist {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let (refs, def) = off.remote_refs(&argv(&["push", "origin"]));
        assert!(refs.is_empty() && !def, "disabled allowlist yields no refs");
    }

    /// SEC-3/H-28 regression: a value-flag before the remote must not shift the
    /// detected positional, and any URL-looking positional must be vetted — so an
    /// exfil remote can't hide behind a flag value.
    #[test]
    fn remote_refs_value_flag_confusion() {
        let p = Policy {
            remote_allow: RemoteAllowlist {
                enabled: true,
                hosts: vec!["github.com".to_string()],
            },
            ..Default::default()
        };

        // `-o opt` consumes "opt"; the real remote URL must still be detected.
        let (refs, _) = p.remote_refs(&argv(&["push", "-o", "opt", "evil.com:repo", "main"]));
        assert!(
            contains(&refs, "evil.com:repo"),
            "value-flag push: exfil URL not vetted, refs={refs:?}"
        );
        assert!(
            !contains(&refs, "opt"),
            "the flag value must not be treated as the remote, refs={refs:?}"
        );

        // The `=` form does not consume the next token; the URL is the positional.
        let (refs, _) = p.remote_refs(&argv(&["push", "--push-option=x", "evil.com:repo"]));
        assert!(
            contains(&refs, "evil.com:repo"),
            "--flag=value push: exfil URL not vetted, refs={refs:?}"
        );

        // clone: `-b main` value must be skipped so the source URL is the positional.
        let (refs, _) = p.remote_refs(&argv(&[
            "clone",
            "-b",
            "main",
            "https://evil.example/x",
            "dir",
        ]));
        assert!(
            contains(&refs, "https://evil.example/x"),
            "clone with value flag: source URL not detected, refs={refs:?}"
        );

        // Plain named push still resolves to the single named remote.
        let (refs, _) = p.remote_refs(&argv(&["push", "origin", "main"]));
        assert!(
            refs.len() == 1 && refs[0] == "origin",
            "plain named push regressed: refs={refs:?}"
        );
    }

    /// SEC-5/H-31 regression: low-level push plumbing (send-pack, http-push) must
    /// be vetted by the allowlist too.
    #[test]
    fn remote_refs_plumbing_verbs() {
        let p = Policy {
            remote_allow: RemoteAllowlist {
                enabled: true,
                hosts: vec!["github.com".to_string()],
            },
            ..Default::default()
        };

        let (refs, _) = p.remote_refs(&argv(&["send-pack", "evil.com:repo", "HEAD"]));
        assert!(
            !refs.is_empty() && refs[0] == "evil.com:repo",
            "send-pack remote not vetted: {refs:?}"
        );

        let (refs, _) = p.remote_refs(&argv(&["http-push", "https://evil.example/x", "main"]));
        assert!(
            !refs.is_empty() && refs[0] == "https://evil.example/x",
            "http-push URL not vetted: {refs:?}"
        );

        // Value flag before the destination must be skipped.
        let (refs, _) = p.remote_refs(&argv(&[
            "send-pack",
            "--receive-pack",
            "rp",
            "evil.com:repo",
            "HEAD",
        ]));
        assert!(
            !refs.is_empty() && refs[0] == "evil.com:repo",
            "send-pack value-flag destination not detected: {refs:?}"
        );
    }

    #[test]
    fn secret_gate_mode() {
        assert!(
            SecretGate::default().blocks(),
            "default (empty) mode should block"
        );
        assert!(
            SecretGate {
                mode: "block".to_string(),
                ..Default::default()
            }
            .blocks(),
            "block mode should block"
        );
        assert!(
            !SecretGate {
                mode: "warn".to_string(),
                ..Default::default()
            }
            .blocks(),
            "warn mode should not block"
        );
    }

    #[test]
    fn init_needs_branch_table() {
        // (name, args, want_ok, want_idx)
        let cases: &[(&str, &[&str], bool, usize)] = &[
            ("plain init", &["init"], true, 0),
            ("init with path", &["init", "myrepo"], true, 0),
            ("init bare", &["init", "--bare"], true, 0),
            ("global -C before init", &["-C", "/tmp/x", "init"], true, 2),
            (
                "global -c before init",
                &["-c", "core.x=1", "init"],
                true,
                2,
            ),
            ("double dash then init", &["--", "init"], true, 1),
            ("explicit -b skips", &["init", "-b", "trunk"], false, 0),
            (
                "explicit --initial-branch skips",
                &["init", "--initial-branch", "dev"],
                false,
                0,
            ),
            (
                "explicit --initial-branch= skips",
                &["init", "--initial-branch=dev"],
                false,
                0,
            ),
            ("not init", &["status"], false, 0),
            ("clone is not init", &["clone", "url"], false, 0),
            ("empty", &[], false, 0),
        ];

        for (name, args, want_ok, want_idx) in cases {
            let got = init_needs_branch(&argv(args));
            assert_eq!(got.is_some(), *want_ok, "{name}: ok mismatch");
            if *want_ok {
                assert_eq!(got, Some(*want_idx), "{name}: idx mismatch");
            }
        }
    }

    #[test]
    fn inject_initial_branch_table() {
        // (name, args, idx, want)
        let cases: &[(&str, &[&str], usize, &str)] = &[
            ("plain", &["init"], 0, "init --initial-branch=main"),
            (
                "with path",
                &["init", "repo"],
                0,
                "init --initial-branch=main repo",
            ),
            (
                "with global",
                &["-C", "/x", "init"],
                2,
                "-C /x init --initial-branch=main",
            ),
            (
                "bare preserved",
                &["init", "--bare"],
                0,
                "init --initial-branch=main --bare",
            ),
        ];

        for (name, args, idx, want) in cases {
            let got = inject_initial_branch(&argv(args), *idx, "main").join(" ");
            assert_eq!(&got, want, "{name}");
        }
    }
}
