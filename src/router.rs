//! Port of Go `internal/router` — classifies a gitc invocation into a passthrough
//! git command, a built-in shortcut, or a gitc-native command.
//!
//! gitc IS the git binary: it provides its own commands first-class (e.g.
//! `git scan`, `git audit`, `git scrub`) and forwards everything else to the git
//! engine. Only gitc-native names are intercepted; names that collide with real
//! git subcommands are deliberately NOT taken first-class (real `git version`
//! and `git clean` pass through — gitc's equivalents are `git gitc version` and
//! `git scrub`). The explicit `git gitc <cmd>` namespace forces gitc's own
//! resolution and remains for back-compat.

use crate::gitargs;
use crate::shortcut::Shortcut;

/// The classified invocation type (Go `Kind`, an `iota` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Forwards `args` verbatim to the git backend.
    Passthrough,
    /// Runs `shortcut` with `args` (arguments after the shortcut name).
    RunShortcut,
    /// Runs a gitc-native command; `args[0]` is the command name.
    Meta,
}

/// Forces gitc's own namespace. `git gitc <cmd>` resolves `<cmd>` against gitc's
/// commands — including names that otherwise pass through to git (e.g. version).
/// Bare `git gitc` shows gitc self-info. (Go `GitcToken`.)
pub const GITC_TOKEN: &str = "gitc";

/// gitc-native commands exposed directly as `git <cmd>`. Names that collide with
/// real git subcommands (version, clean) are omitted so real git keeps them;
/// gitc's equivalents are reachable via the gitc token (version) or a
/// non-colliding name (scrub, not clean). (Go `firstClassMeta` map.)
const FIRST_CLASS_META: &[&str] = &[
    "scan",
    "audit",
    "scrub",
    "install",
    "uninstall",
    "where",
    "fetch-git",
    "update",
    "doctor",
    "cmdtree",
    "backend-update",
];

fn is_first_class_meta(name: &str) -> bool {
    FIRST_CLASS_META.contains(&name)
}

/// The result of classification (Go `Decision`).
///
/// `shortcut` is only meaningful when `kind == Kind::RunShortcut`. It borrows
/// from the `shortcuts` slice passed to [`classify`] (Go stored a `Shortcut`
/// value; the ported `Shortcut` is a non-`Clone` handle, so a borrow preserves
/// identity without re-porting it).
pub struct Decision<'a> {
    pub kind: Kind,
    /// Valid only when `kind == Kind::RunShortcut`.
    pub shortcut: Option<&'a Shortcut>,
    pub args: Vec<String>,
}

/// Routes `args` (the arguments after the program name). It resolves the
/// subcommand past any leading git global flags (via [`gitargs`]), so
/// gitc-native commands and shortcuts still fire when prefixed, e.g.
/// `git -c x=y scan`.
///
/// gitc-native commands and shortcuts are gitc concepts, not git subcommands:
/// when routed as `Meta`/`RunShortcut` the leading git globals are dropped (they
/// do not apply to gitc's own commands). Anything not gitc-native passes through
/// verbatim — full args, globals intact — so real git behavior is untouched.
pub fn classify<'a>(args: &[String], shortcuts: &'a [Shortcut]) -> Decision<'a> {
    if args.is_empty() {
        return Decision {
            kind: Kind::Passthrough,
            shortcut: None,
            args: Vec::new(),
        };
    }

    let idx = match gitargs::subcommand_index(args) {
        Some(i) => i,
        // Only global flags, no subcommand: pass through verbatim.
        None => {
            return Decision {
                kind: Kind::Passthrough,
                shortcut: None,
                args: args.to_vec(),
            };
        }
    };

    let sub = &args[idx];

    // `git gitc ...` forces gitc's namespace (explicit escape + back-compat).
    // Args after the token (args[0] = the gitc command, empty => self-info).
    if sub == GITC_TOKEN {
        return Decision {
            kind: Kind::Meta,
            shortcut: None,
            args: args[idx + 1..].to_vec(),
        };
    }
    // First-class gitc-native commands: `git scan`, `git audit`, ...
    if is_first_class_meta(sub) {
        return Decision {
            kind: Kind::Meta,
            shortcut: None,
            args: args[idx..].to_vec(),
        };
    }
    // Built-in shortcuts.
    for sc in shortcuts {
        if sub == sc.name {
            return Decision {
                kind: Kind::RunShortcut,
                shortcut: Some(sc),
                args: args[idx + 1..].to_vec(),
            };
        }
    }
    // Everything else is real git.
    Decision {
        kind: Kind::Passthrough,
        shortcut: None,
        args: args.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcut;

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn classify() {
        let shortcuts = shortcut::all();

        // (name, args, want_kind, want_sc, want_args)
        struct Case {
            name: &'static str,
            args: Vec<String>,
            want_kind: Kind,
            want_sc: &'static str,
            want_args: Vec<String>,
        }

        let c = |name, args: &[&str], want_kind, want_sc, want_args: &[&str]| Case {
            name,
            args: s(args),
            want_kind,
            want_sc,
            want_args: s(want_args),
        };

        let tests = vec![
            c("empty is passthrough", &[], Kind::Passthrough, "", &[]),
            c(
                "status passes through",
                &["status"],
                Kind::Passthrough,
                "",
                &["status"],
            ),
            c(
                "real git subcommand version passes through",
                &["version"],
                Kind::Passthrough,
                "",
                &["version"],
            ),
            c(
                "help passes through",
                &["help"],
                Kind::Passthrough,
                "",
                &["help"],
            ),
            c(
                "commit with flags passes through",
                &["commit", "-m", "x"],
                Kind::Passthrough,
                "",
                &["commit", "-m", "x"],
            ),
            c("sync shortcut", &["sync"], Kind::RunShortcut, "sync", &[]),
            c("undo shortcut", &["undo"], Kind::RunShortcut, "undo", &[]),
            c(
                "log-graph shortcut with extra args",
                &["log-graph", "-n", "5"],
                Kind::RunShortcut,
                "log-graph",
                &["-n", "5"],
            ),
            c(
                "quick-commit passes message",
                &["quick-commit", "msg"],
                Kind::RunShortcut,
                "quick-commit",
                &["msg"],
            ),
            c(
                "meta namespace",
                &["gitc", "audit", "5"],
                Kind::Meta,
                "",
                &["audit", "5"],
            ),
            // First-class gitc-native commands.
            c(
                "scan is first-class meta",
                &["scan"],
                Kind::Meta,
                "",
                &["scan"],
            ),
            c(
                "scan with path",
                &["scan", "src"],
                Kind::Meta,
                "",
                &["scan", "src"],
            ),
            c(
                "scrub is first-class meta",
                &["scrub", "--path", "x"],
                Kind::Meta,
                "",
                &["scrub", "--path", "x"],
            ),
            c(
                "audit is first-class meta",
                &["audit", "5"],
                Kind::Meta,
                "",
                &["audit", "5"],
            ),
            c(
                "where/install/uninstall first-class",
                &["where"],
                Kind::Meta,
                "",
                &["where"],
            ),
            // Collisions with real git pass through, not intercepted.
            c(
                "real git clean passes through",
                &["clean", "-fd"],
                Kind::Passthrough,
                "",
                &["clean", "-fd"],
            ),
            c(
                "real git version passes through",
                &["version"],
                Kind::Passthrough,
                "",
                &["version"],
            ),
            // gitc token forces the namespace (back-compat) incl. colliding names.
            c(
                "gitc token unwraps scan",
                &["gitc", "scan"],
                Kind::Meta,
                "",
                &["scan"],
            ),
            c(
                "gitc token reaches version",
                &["gitc", "version"],
                Kind::Meta,
                "",
                &["version"],
            ),
            c("bare gitc is self-info", &["gitc"], Kind::Meta, "", &[]),
            // Leading git global flags must not hide gitc-native commands / shortcuts.
            c(
                "global -c before scan still meta",
                &["-c", "x=y", "scan"],
                Kind::Meta,
                "",
                &["scan"],
            ),
            c(
                "global -C before sync still shortcut",
                &["-C", "dir", "sync"],
                Kind::RunShortcut,
                "sync",
                &[],
            ),
            c(
                "globals before gitc token",
                &["-c", "a=b", "gitc", "audit", "5"],
                Kind::Meta,
                "",
                &["audit", "5"],
            ),
            c(
                "globals before real subcommand pass through verbatim",
                &["-c", "x=y", "status"],
                Kind::Passthrough,
                "",
                &["-c", "x=y", "status"],
            ),
            c(
                "only globals, no subcommand, passes through",
                &["-c", "x=y"],
                Kind::Passthrough,
                "",
                &["-c", "x=y"],
            ),
        ];

        for tt in tests {
            let got = super::classify(&tt.args, &shortcuts);
            assert_eq!(got.kind, tt.want_kind, "Kind for {:?}", tt.name);

            if got.kind == Kind::RunShortcut {
                let name = got.shortcut.map(|sc| sc.name).unwrap_or("");
                assert_eq!(name, tt.want_sc, "Shortcut for {:?}", tt.name);
            }

            assert_eq!(got.args, tt.want_args, "Args for {:?}", tt.name);
        }
    }
}
