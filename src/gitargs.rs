//! Minimal git argv parser — the foundation every gate check reads.
//!
//! git accepts a set of GLOBAL options before the subcommand (`git [globals]
//! <verb> [args]`), some of which take a value (`-c name=value`, `-C <dir>`,
//! `--git-dir <dir>`, …). The gate must understand these because they are exactly
//! the surfaces an attacker uses to smuggle policy past a naive check (e.g.
//! `-c alias.push=…`, `-c credential.helper=…`). This mirrors the relevant slice
//! of git's own `handle_options` (git.c) — enough to identify the verb and every
//! `-c` / `--config-env` override, not a full reimplementation.

/// A parsed git invocation (`argv[0]` = program).
#[derive(Debug, Default)]
pub struct Invocation {
    /// `-c name=value` overrides, name lowercased. A bare `-c name` yields
    /// `(name, "true")`, matching git's boolean shorthand.
    pub configs: Vec<(String, String)>,
    /// `--config-env name=ENVVAR` — a config key sourced from an env var (another
    /// override vector). Stored as the lowercased config key.
    pub config_env_keys: Vec<String>,
    /// `-C <dir>` chdir values, in order.
    pub c_dirs: Vec<String>,
    /// `--git-dir[=<dir>]` if present.
    pub git_dir: Option<String>,
    /// The subcommand (`add`, `commit`, `push`, …), if any.
    pub verb: Option<String>,
    /// Args after the verb (the subcommand's own args).
    pub rest: Vec<String>,
    /// `--exec-path[=<path>]` seen. git resolves transport helpers (git-remote-*)
    /// from exec-path, so pointing it at an attacker dir is an RCE vector — the
    /// gate refuses it on network verbs. Tracked as a flag, not a value.
    pub exec_path: bool,
}

/// Global options that consume the FOLLOWING token as their value (space form).
/// Their `--opt=value` attached form is handled separately. NOTE: `--exec-path`
/// is deliberately NOT here — real git treats a bare `--exec-path` as
/// print-and-exit (it consumes NO value), so listing it as a space-form value opt
/// made the parser swallow the following token (e.g. the verb in
/// `git --exec-path push`), nulling the verb and skipping the network checks.
const VALUE_OPTS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// Parse `argv` (including `argv[0]`) into an [`Invocation`].
pub fn parse(argv: &[String]) -> Invocation {
    let mut inv = Invocation::default();
    let mut i = 1; // skip argv[0]

    while i < argv.len() {
        let tok = &argv[i];

        // First non-option token is the subcommand.
        if !tok.starts_with('-') {
            inv.verb = Some(tok.clone());
            inv.rest = argv[i + 1..].to_vec();
            return inv;
        }

        // Attached `--opt=value` forms we care about.
        if let Some(v) = tok.strip_prefix("--git-dir=") {
            inv.git_dir = Some(v.to_string());
            i += 1;
            continue;
        }
        if let Some(v) = tok.strip_prefix("-c").filter(|v| !v.is_empty()) {
            // git does NOT accept `-cname=value` attached, but be defensive.
            record_config(&mut inv, v);
            i += 1;
            continue;
        }
        if let Some(v) = tok.strip_prefix("--config-env=") {
            record_config_env(&mut inv, v);
            i += 1;
            continue;
        }

        // `--exec-path` / `--exec-path=<path>` — optional-attached-value in git.
        // Neither form consumes the following token (bare = print-and-exit); mark
        // it seen so the gate can refuse it on network verbs.
        if tok == "--exec-path" || tok.starts_with("--exec-path=") {
            inv.exec_path = true;
            i += 1;
            continue;
        }

        // Space-form value options: consume the next token as the value.
        if VALUE_OPTS.contains(&tok.as_str()) {
            let val = argv.get(i + 1).cloned().unwrap_or_default();
            match tok.as_str() {
                "-c" => record_config(&mut inv, &val),
                "-C" => inv.c_dirs.push(val),
                "--git-dir" => inv.git_dir = Some(val),
                "--config-env" => record_config_env(&mut inv, &val),
                _ => {}
            }
            i += 2;
            continue;
        }

        // Any other global flag (`-p`, `--bare`, `--paginate`, `--version`, …):
        // no value to consume.
        i += 1;
    }

    inv // no subcommand (e.g. bare `git`, `git --version`)
}

/// Git global options that consume the FOLLOWING argument, so the subcommand
/// scanner must skip their value too (e.g. `git -C dir init`). This mirrors Go
/// `gitargs.valueGlobals` exactly — it is intentionally the set the Go
/// `SubcommandIndex` scanner uses, NOT the broader [`VALUE_OPTS`] above (which
/// also carries `--attr-source`), so `subcommand_index` stays bug-for-bug with
/// the Go policy layer that depends on it.
const SUBCOMMAND_VALUE_GLOBALS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
];

/// Returns the index of the git subcommand token in `argv`, skipping leading
/// global options and the values of the globals that consume a following
/// argument. A bare `--` ends options: the token after it (if any) is the
/// subcommand. Returns `None` when no subcommand is present (empty argv, or only
/// global flags) — Go's `-1`.
///
/// Faithful port of Go `gitargs.SubcommandIndex`. NOTE: unlike [`parse`], this
/// scans from `argv[0]` (the caller passes the git args WITHOUT the program
/// name, e.g. `["-c", "x=y", "push"]`), matching the Go signature.
pub fn subcommand_index(argv: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];

        if a == "--" {
            return if i + 1 < argv.len() {
                Some(i + 1)
            } else {
                None
            };
        }

        if a.starts_with('-') {
            if SUBCOMMAND_VALUE_GLOBALS.contains(&a.as_str()) {
                i += 1; // also skip this flag's value
            }
            i += 1;
            continue;
        }

        return Some(i);
    }

    None
}

/// Record a `-c name=value` (or bare `-c name`) override, name lowercased.
fn record_config(inv: &mut Invocation, spec: &str) {
    match spec.split_once('=') {
        Some((k, v)) => inv.configs.push((k.to_ascii_lowercase(), v.to_string())),
        None => inv
            .configs
            .push((spec.to_ascii_lowercase(), "true".to_string())),
    }
}

/// Record a `--config-env name=ENVVAR` key (lowercased).
fn record_config_env(inv: &mut Invocation, spec: &str) {
    let key = spec.split_once('=').map(|(k, _)| k).unwrap_or(spec);
    inv.config_env_keys.push(key.to_ascii_lowercase());
}

impl Invocation {
    /// The subcommand as a `&str`, or `""` when absent.
    pub fn verb(&self) -> &str {
        self.verb.as_deref().unwrap_or("")
    }

    /// Every config key touched via `-c` or `--config-env` (lowercased).
    pub fn all_config_keys(&self) -> impl Iterator<Item = &str> {
        self.configs
            .iter()
            .map(|(k, _)| k.as_str())
            .chain(self.config_env_keys.iter().map(String::as_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plain_verb() {
        let inv = parse(&argv(&["git", "push", "origin"]));
        assert_eq!(inv.verb(), "push");
        assert_eq!(inv.rest, vec!["origin".to_string()]);
    }

    #[test]
    fn dashc_space_and_attached() {
        let inv = parse(&argv(&["git", "-c", "user.name=X", "commit"]));
        assert_eq!(inv.verb(), "commit");
        assert!(inv.all_config_keys().any(|k| k == "user.name"));
    }

    #[test]
    fn bare_exec_path_does_not_swallow_verb() {
        // Regression: `--exec-path` must NOT consume `push` as its value.
        let inv = parse(&argv(&["git", "--exec-path", "push", "origin"]));
        assert_eq!(inv.verb(), "push", "bare --exec-path nulled the verb");
        assert!(inv.exec_path);
    }

    #[test]
    fn attached_exec_path_flags_and_keeps_verb() {
        let inv = parse(&argv(&["git", "--exec-path=/tmp/evil", "fetch"]));
        assert_eq!(inv.verb(), "fetch");
        assert!(inv.exec_path);
    }

    #[test]
    fn config_env_key_recorded() {
        let inv = parse(&argv(&[
            "git",
            "--config-env",
            "credential.helper=EVILVAR",
            "push",
        ]));
        assert_eq!(inv.verb(), "push");
        assert!(inv.all_config_keys().any(|k| k == "credential.helper"));
    }

    #[test]
    fn subcommand_index_cases() {
        // (argv, expected index) — mirrors the semantics the policy layer relies on.
        let cases: &[(&[&str], Option<usize>)] = &[
            (&["init"], Some(0)),
            (&["-C", "/tmp/x", "init"], Some(2)),
            (&["-c", "core.x=1", "init"], Some(2)),
            (&["--", "init"], Some(1)),
            (&["--git-dir", "/g", "status"], Some(2)),
            (&["-c", "x=y", "push"], Some(2)),
            // only globals / a dangling `--` → no subcommand.
            (&["-c", "x=y"], None),
            (&["--"], None),
            (&[], None),
        ];

        for (input, want) in cases {
            let got = subcommand_index(&argv(input));
            assert_eq!(got, *want, "subcommand_index({input:?})");
        }
    }
}
