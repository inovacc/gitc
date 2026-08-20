//! Tests for the SCM helper. The security-relevant properties — that a token
//! never lands on a command line and never survives into an error string — get
//! the most attention, because they are the ones whose failure is silent.

use super::*;

// ── Platform ────────────────────────────────────────────────────────────────

#[test]
fn platform_round_trips() {
    for (s, p) in [
        ("unknown", Platform::Unknown),
        ("none", Platform::None),
        ("github", Platform::GitHub),
        ("gitlab", Platform::GitLab),
        ("azuredevops", Platform::AzureDevOps),
        ("gitea", Platform::Gitea),
        ("bitbucket", Platform::Bitbucket),
    ] {
        assert_eq!(platform_from_string(s).unwrap(), p);
        assert_eq!(p.as_str(), s);
    }
}

/// An EMPTY string is `Unknown`, not an error — Go treats "" and "unknown" the
/// same, which is what lets the flag be optional.
#[test]
fn empty_platform_is_unknown_not_an_error() {
    assert_eq!(platform_from_string("").unwrap(), Platform::Unknown);
}

#[test]
fn platform_parsing_is_case_insensitive() {
    assert_eq!(platform_from_string("GitHub").unwrap(), Platform::GitHub);
    assert_eq!(platform_from_string("AZUREDEVOPS").unwrap(), Platform::AzureDevOps);
}

#[test]
fn unknown_platform_string_errors() {
    let e = platform_from_string("sourcehut").unwrap_err();
    assert_eq!(e, "invalid scm platform value: sourcehut");
}

// ── clone args ──────────────────────────────────────────────────────────────

#[test]
fn clone_args_default() {
    let a = clone_args("https://h/r.git", "/dest", &CloneOptions::default());
    assert_eq!(a, vec!["clone", "--quiet", "https://h/r.git", "/dest"]);
}

/// `--mirror` WINS over `--bare`; Go does not combine them.
#[test]
fn mirror_beats_bare() {
    let opts = CloneOptions { bare: true, mirror: true, ..Default::default() };
    let a = clone_args("r", "d", &opts);
    assert!(a.contains(&"--mirror".to_string()));
    assert!(!a.contains(&"--bare".to_string()));
}

#[test]
fn bare_single_branch_and_depth() {
    let opts = CloneOptions {
        bare: true,
        single_branch: true,
        depth: 50,
        ..Default::default()
    };
    let a = clone_args("r", "d", &opts);
    assert_eq!(
        a,
        vec!["clone", "--quiet", "--bare", "--single-branch", "--depth", "50", "r", "d"]
    );
}

/// depth 0 means "not shallow" and must emit no flag.
#[test]
fn depth_zero_emits_nothing() {
    let a = clone_args("r", "d", &CloneOptions { depth: 0, ..Default::default() });
    assert!(!a.contains(&"--depth".to_string()));
}

/// **The token goes in the ENV and never in argv.** This is the whole reason
/// for the GIT_CONFIG_* indirection: argv is world-readable on most systems.
///
/// Asserting only "argv lacks the token" would be vacuous — `clone_args` is
/// never handed one. So this drives the SAME path `clone_authed` does: build
/// the auth config from the token, merge it into the env, and check both sides.
#[test]
fn token_goes_in_the_env_never_in_argv() {
    let token = "ghp_supersecrettokenvalue";
    let remote = "https://github.com/o/r.git";

    let auth = auth_clone_configs(remote, token).unwrap();
    assert!(!auth.is_empty(), "precondition: an https remote yields auth config");

    let args = clone_args(remote, "/dest", &CloneOptions::default());
    for a in &args {
        assert!(!a.contains(token), "token leaked into argv: {a}");
        // The base64 form must not leak either.
        assert!(!a.contains("eC1hY2Nlc3Mt"), "encoded token leaked into argv: {a}");
    }

    // …and it IS carried, via the env, or the clone could not authenticate.
    let env = git_clone_env(&auth);
    let carried = env.values().any(|v| v.contains("Authorization: basic"));
    assert!(carried, "the credential must reach git through the environment");
}

// ── auth config ─────────────────────────────────────────────────────────────

#[test]
fn auth_config_builds_an_extra_header() {
    let cfgs = auth_clone_configs("https://github.com/o/r.git", "tok").unwrap();
    assert_eq!(cfgs.len(), 1);
    assert_eq!(cfgs[0].key, "http.https://github.com.extraHeader");
    // base64("x-access-token:tok")
    assert_eq!(cfgs[0].value, "Authorization: basic eC1hY2Nlc3MtdG9rZW46dG9r");
}

#[test]
fn auth_config_is_empty_without_a_token() {
    assert!(auth_clone_configs("https://github.com/o/r.git", "").unwrap().is_empty());
}

/// SSH remotes cannot carry a bearer token, so Go passes them through rather
/// than erroring.
#[test]
fn ssh_remotes_get_no_auth_config() {
    assert!(auth_clone_configs("git@github.com:o/r.git", "tok").unwrap().is_empty());
    assert!(auth_clone_configs("ssh://git@github.com/o/r.git", "tok").unwrap().is_empty());
}

#[test]
fn non_http_schemes_get_no_auth_config() {
    assert!(auth_clone_configs("file:///tmp/repo", "tok").unwrap().is_empty());
}

/// Userinfo already in the URL must not end up in the config KEY — the key is
/// keyed by host only.
#[test]
fn auth_config_key_uses_host_without_userinfo() {
    let cfgs = auth_clone_configs("https://user:pw@git.example.com/o/r.git", "tok").unwrap();
    assert_eq!(cfgs[0].key, "http.https://git.example.com.extraHeader");
}

#[test]
fn is_ssh_remote_discriminates() {
    assert!(is_ssh_remote("git@github.com:o/r.git"));
    assert!(is_ssh_remote("ssh://git@github.com/o/r.git"));
    assert!(!is_ssh_remote("https://github.com/o/r.git"));
    // http(s) with userinfo is NOT an ssh remote.
    assert!(!is_ssh_remote("https://user:pw@github.com/o/r.git"));
    assert!(!is_ssh_remote("/local/path"));
}

// ── environment ─────────────────────────────────────────────────────────────

/// The clone must not inherit the user's git config — otherwise ambient
/// credentials or URL rewrites could apply.
#[test]
fn env_isolates_the_clone_from_ambient_config() {
    let env = git_clone_env(&[]);
    // `/dev/null` on EVERY platform, including Windows — see the divergence note
    // in `git_clone_env`. Git for Windows rejects Go's `NUL` with
    // `fatal: unable to access 'NUL': Invalid argument`, which silently reduces a
    // history scan to zero bytes.
    assert_eq!(env["GIT_CONFIG_GLOBAL"], "/dev/null");
    assert_eq!(env["GIT_CONFIG_SYSTEM"], "/dev/null");
    assert_eq!(env["GIT_CONFIG_NOSYSTEM"], "1");
    assert_eq!(env["GIT_NO_REPLACE_OBJECTS"], "1");
    // No interactive credential prompt — a clone that blocks forever is worse
    // than one that fails.
    assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
    assert!(!env.contains_key("GIT_CONFIG_COUNT"), "no configs, no count");
}

#[test]
fn env_carries_indexed_config_entries() {
    let cfgs = vec![
        GitConfig { key: "a.b".into(), value: "1".into() },
        GitConfig { key: "c.d".into(), value: "2".into() },
    ];
    let env = git_clone_env(&cfgs);
    assert_eq!(env["GIT_CONFIG_COUNT"], "2");
    assert_eq!(env["GIT_CONFIG_KEY_0"], "a.b");
    assert_eq!(env["GIT_CONFIG_VALUE_0"], "1");
    assert_eq!(env["GIT_CONFIG_KEY_1"], "c.d");
    assert_eq!(env["GIT_CONFIG_VALUE_1"], "2");
}

// ── sanitization ────────────────────────────────────────────────────────────

#[test]
fn sanitize_redacts_the_raw_token() {
    let out = sanitize_output("fatal: auth failed for ghp_abc123", "ghp_abc123");
    assert_eq!(out, "fatal: auth failed for ***");
}

/// A token can come back URL-ENCODED inside a URL, which a naive substring
/// replace would miss.
#[test]
fn sanitize_redacts_the_url_encoded_token() {
    let token = "tok/with+special=chars";
    let encoded = "tok%2Fwith%2Bspecial%3Dchars";
    let out = sanitize_output(&format!("https://x/{encoded}"), token);
    assert!(!out.contains(encoded), "encoded token survived: {out}");
    assert!(out.contains("***"));
}

/// Userinfo is stripped even when the token is unknown — a credential can reach
/// a log through a URL nobody passed us.
#[test]
fn sanitize_strips_userinfo_without_a_token() {
    assert_eq!(
        sanitize_output("cloning https://user:pass@github.com/o/r.git", ""),
        "cloning https://***@github.com/o/r.git"
    );
    assert_eq!(
        sanitize_output("http://tok@host/x", ""),
        "http://***@host/x"
    );
}

#[test]
fn sanitize_leaves_clean_text_alone() {
    assert_eq!(sanitize_output("all good", "tok"), "all good");
    assert_eq!(sanitize_output("", "tok"), "");
    assert_eq!(
        sanitize_output("https://github.com/o/r.git", ""),
        "https://github.com/o/r.git"
    );
}

// ── clone_authed guards ─────────────────────────────────────────────────────

#[test]
fn clone_rejects_empty_remote_and_dest() {
    let o = CloneOptions::default();
    assert_eq!(clone_authed("", "t", "/d", &o).unwrap_err(), "scm.CloneAuthed: empty remote");
    assert_eq!(clone_authed("r", "t", "", &o).unwrap_err(), "scm.CloneAuthed: empty dest");
}

#[test]
fn base64_matches_known_vectors() {
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_encode(b"x-access-token:tok"), "eC1hY2Nlc3MtdG9rZW46dG9r");
}
