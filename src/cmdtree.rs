//! Port of Go `internal/cmdtree` — renders gitc's command catalog as a navigable
//! tree (the `git cmdtree` command). The catalog is built from gitc's real command
//! surface — its first-class meta commands, the gitc namespace, and the shortcut
//! set — rather than a cobra tree, since gitc uses a manual router.
//!
//! Faithful 1:1 port of the Go implementation: identical dispatch semantics, exit
//! codes, and rendered output. `Run(args) int` → `run(args) -> i32`.

use serde::Serialize;

use crate::shortcut;

// ASCII tree characters for consistent width across all terminals.
const TREE_MIDDLE: &str = "+-- ";
const TREE_LAST: &str = "\\-- ";
const TREE_INDENT: &str = "|   ";
const TREE_SPACE: &str = "    ";
const MAX_DESC_LEN: usize = 44;
const COMMENT_COL: usize = 52;

/// `cmdFlag` — a single flag on a gitc command.
#[derive(Debug, Clone, Serialize)]
struct CmdFlag {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    shorthand: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    default: String,
    description: String,
}

/// `cmdNode` — one node of gitc's command catalog.
#[derive(Debug, Clone, Serialize)]
struct CmdNode {
    name: String,
    usage: String,
    short: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    long: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<CmdFlag>,
    #[serde(rename = "commands", skip_serializing_if = "Vec::is_empty")]
    subcommands: Vec<CmdNode>,
}

/// Build a simple node with only name/usage/short set.
fn node(name: &str, usage: &str, short: &str) -> CmdNode {
    CmdNode {
        name: name.to_string(),
        usage: usage.to_string(),
        short: short.to_string(),
        long: String::new(),
        flags: Vec::new(),
        subcommands: Vec::new(),
    }
}

/// Build a flag. `shorthand` and `default` may be empty (omitted from JSON).
fn flag(name: &str, shorthand: &str, type_: &str, default: &str, description: &str) -> CmdFlag {
    CmdFlag {
        name: name.to_string(),
        shorthand: shorthand.to_string(),
        type_: type_.to_string(),
        default: default.to_string(),
        description: description.to_string(),
    }
}

/// `gitcTree` — gitc's full command catalog rooted at `git`.
fn gitc_tree() -> CmdNode {
    let scan_flags = vec![
        flag(
            "audit",
            "",
            "bool",
            "",
            "scan the audit DB's captured argv/env for secrets",
        ),
        flag(
            "strict",
            "",
            "bool",
            "",
            "exit non-zero if any file could not be read",
        ),
    ];
    let scrub_flags = vec![
        flag("path", "", "string", "", "path glob to purge (repeatable)"),
        flag(
            "invert-paths",
            "",
            "bool",
            "",
            "remove matched paths instead of keeping only them",
        ),
        flag(
            "replace-text",
            "",
            "string",
            "",
            "file of redaction rules to apply to blobs",
        ),
        flag(
            "match-email",
            "",
            "string",
            "",
            "exact identity email to rewrite",
        ),
        flag(
            "match-name",
            "",
            "string",
            "",
            "exact identity name to rewrite",
        ),
        flag("name", "", "string", "", "replacement identity name"),
        flag("email", "", "string", "", "replacement identity email"),
        flag(
            "author-only",
            "",
            "bool",
            "",
            "rewrite authors but not committers",
        ),
        flag(
            "committer-only",
            "",
            "bool",
            "",
            "rewrite committers but not authors",
        ),
        flag(
            "prune",
            "",
            "string",
            "auto",
            "prune empty commits: auto|always|never",
        ),
        flag(
            "dry-run",
            "",
            "bool",
            "",
            "run export+transform but discard the import",
        ),
        flag("force", "", "bool", "", "apply the rewrite (irreversible)"),
    ];
    let fetch_flags = vec![
        flag(
            "latest",
            "",
            "bool",
            "",
            "query git-for-windows for the newest release (unpinned)",
        ),
        flag(
            "list",
            "",
            "bool",
            "",
            "list recent git-for-windows releases",
        ),
        flag(
            "busybox",
            "",
            "bool",
            "",
            "install the busybox MinGit (bundles POSIX sh for hooks)",
        ),
        flag(
            "full",
            "",
            "bool",
            "",
            "install the full git (bash + sh; the default); persists",
        ),
        flag(
            "minimal",
            "",
            "bool",
            "",
            "install the shell-less MinGit (smallest; no hooks); persists",
        ),
        flag(
            "i-accept-unverified",
            "",
            "bool",
            "",
            "allow --latest despite no sha256 verification",
        ),
    ];
    let update_flags = vec![
        flag(
            "check",
            "",
            "bool",
            "",
            "report whether a newer gitc release exists",
        ),
        flag(
            "apply",
            "",
            "bool",
            "",
            "download and replace this binary with the latest",
        ),
    ];
    let install_flags = vec![flag(
        "apply",
        "",
        "bool",
        "",
        "prepend the shim dir to the user PATH",
    )];

    let mut native = vec![
        {
            let mut n = node(
                "scan",
                "git scan [path]",
                "Detect secrets (exit 1 if any found)",
            );
            n.flags = scan_flags;
            n
        },
        {
            let mut n = node(
                "scrub",
                "git scrub [flags]",
                "Rewrite history: purge paths / redact text",
            );
            n.flags = scrub_flags;
            n
        },
        {
            let mut n = node(
                "audit",
                "git audit [N] [--wide|--plain|--verify]",
                "Browse audited invocations (interactive TUI on a terminal)",
            );
            n.flags = vec![
                flag(
                    "wide",
                    "w",
                    "bool",
                    "",
                    "full record text render instead of the TUI",
                ),
                flag(
                    "plain",
                    "",
                    "bool",
                    "",
                    "compact text render instead of the TUI (auto when piped)",
                ),
                flag(
                    "verify",
                    "",
                    "bool",
                    "",
                    "verify the tamper-evident hash chain",
                ),
            ];
            n
        },
        node(
            "where",
            "git where",
            "Show resolved git backend and audit DB path",
        ),
        node(
            "doctor",
            "git doctor",
            "Health-check the install, backend, PATH shim, and audit DB",
        ),
        {
            let mut n = node(
                "update",
                "git update [--check|--apply]",
                "Self-update gitc from GitHub releases",
            );
            n.flags = update_flags;
            n
        },
        {
            let mut n = node(
                "fetch-git",
                "git fetch-git [--latest|--list]",
                "Download a git backend (pinned MinGit)",
            );
            n.flags = fetch_flags;
            n
        },
        {
            let mut n = node("install", "git install [--apply]", "Install the PATH shim");
            n.flags = install_flags;
            n
        },
        node("uninstall", "git uninstall", "Remove the PATH shim"),
        node(
            "cmdtree",
            "git cmdtree [-b|-c NAME|--json]",
            "Display this command tree",
        ),
    ];

    let mut shortcuts: Vec<CmdNode> = Vec::new();
    for sc in shortcut::all() {
        let use_ = if !sc.usage.is_empty() {
            format!("git {}", sc.usage)
        } else {
            format!("git {}", sc.name)
        };
        shortcuts.push(node(sc.name, &use_, sc.short));
    }

    // Append the gitc `version` subcommand to the native namespace.
    native.push(node(
        "version",
        "git gitc version",
        "Print gitc's own version",
    ));

    let mut gitc_ns = node(
        "gitc",
        "git gitc <cmd>",
        "Force gitc's own namespace (also `git <cmd>` directly)",
    );
    gitc_ns.subcommands = native;

    let mut shortcuts_ns = node(
        "<shortcuts>",
        "git <shortcut>",
        "Built-in convenience commands",
    );
    shortcuts_ns.subcommands = shortcuts;

    let mut root = node(
        "git",
        "git <command> [args]",
        "gitc: a git binary with forensic audit, secret scan, history scrub",
    );
    root.subcommands = vec![
        gitc_ns,
        shortcuts_ns,
        node(
            "<git>",
            "git <anything else>",
            "Passthrough to the real git engine (audited)",
        ),
    ];
    root
}

/// Parsed `git cmdtree` flags.
#[derive(Default)]
struct CmdtreeOpts {
    brief: bool,
    command: String,
    as_json: bool,
}

/// `Run` renders gitc's command catalog as a tree (verbose by default). It parses
/// `git cmdtree` flags (-b brief, -c NAME single command, --json) and returns a
/// process exit code.
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_cmdtree_flags(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("git cmdtree: {e}");
            return 2;
        }
    };

    let root = gitc_tree();

    if !opts.command.is_empty() {
        let node = match find_node(&root, &opts.command) {
            Some(n) => n,
            None => {
                eprintln!("git cmdtree: command not found: {}", opts.command);
                return 1;
            }
        };

        if opts.as_json {
            return encode_json(node);
        }

        let mut out = String::new();
        print_single_node(&mut out, node);
        print!("{out}");

        return 0;
    }

    if opts.as_json {
        return encode_json(&root);
    }

    let mut out = String::new();
    out.push_str(&root.name);
    out.push('\n');

    if opts.brief {
        print_nodes(&mut out, &root.subcommands, "");
    } else {
        print_verbose_nodes(&mut out, &root.subcommands, "");
    }

    print!("{out}");

    0
}

/// Parses cmdtree's flags in gitc's manual style.
fn parse_cmdtree_flags(args: &[String]) -> Result<CmdtreeOpts, String> {
    let mut opts = CmdtreeOpts::default();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-b" | "--brief" => opts.brief = true,
            "-v" | "--verbose" => opts.brief = false,
            "--json" => opts.as_json = true,
            "-c" | "--command" => {
                if i + 1 >= args.len() {
                    return Err(format!("{a} requires a value"));
                }
                i += 1;
                opts.command = args[i].clone();
            }
            _ => return Err(format!("unknown flag {a:?}")),
        }
        i += 1;
    }

    Ok(opts)
}

/// Saturating `max(a - b, floor)` for `usize` differences that may go negative.
fn pad(a: usize, b: usize, floor: usize) -> usize {
    (a as isize - b as isize).max(floor as isize) as usize
}

/// Renders the compact tree (name + short description).
fn print_nodes(w: &mut String, nodes: &[CmdNode], prefix: &str) {
    for (i, n) in nodes.iter().enumerate() {
        let is_last = i == nodes.len() - 1;

        let connector = if is_last { TREE_LAST } else { TREE_MIDDLE };

        let mut desc = n.short.clone();
        if desc.len() > MAX_DESC_LEN {
            desc = format!("{}...", &desc[..MAX_DESC_LEN - 3]);
        }

        let cmd_part = format!("{prefix}{connector}{}", n.name);
        let padding = pad(COMMENT_COL, cmd_part.len(), 2);

        w.push_str(&format!("{cmd_part}{}# {desc}\n", " ".repeat(padding)));

        if !n.subcommands.is_empty() {
            let next = if is_last {
                format!("{prefix}{TREE_SPACE}")
            } else {
                format!("{prefix}{TREE_INDENT}")
            };
            print_nodes(w, &n.subcommands, &next);
        }
    }
}

/// Renders the full tree (usage, description, flags).
fn print_verbose_nodes(w: &mut String, nodes: &[CmdNode], prefix: &str) {
    for (i, n) in nodes.iter().enumerate() {
        let is_last = i == nodes.len() - 1;

        let connector = if is_last { TREE_LAST } else { TREE_MIDDLE };

        w.push_str(&format!("{prefix}{connector}{}\n", n.name));

        let detail = if is_last {
            format!("{prefix}{TREE_SPACE}")
        } else {
            format!("{prefix}{TREE_INDENT}")
        };

        if !n.usage.is_empty() {
            w.push_str(&format!("{detail}Usage: {}\n", n.usage));
        }

        if !n.short.is_empty() {
            w.push_str(&format!("{detail}Description: {}\n", n.short));
        }

        if !n.flags.is_empty() {
            w.push_str(&format!("{detail}Flags:\n"));
            let fp = format!("{detail}  ");
            for f in &n.flags {
                print_flag(w, &fp, f);
            }
        }

        w.push_str(&format!("{detail}\n"));

        if !n.subcommands.is_empty() {
            print_verbose_nodes(w, &n.subcommands, &detail);
        }
    }
}

/// Renders one command's full detail.
fn print_single_node(w: &mut String, n: &CmdNode) {
    w.push_str(&format!("# {}\n\n", n.name));
    w.push_str(&format!("Usage: {}\n\n", n.usage));

    if !n.short.is_empty() {
        w.push_str(&format!("Description: {}\n\n", n.short));
    }

    if !n.flags.is_empty() {
        w.push_str("Flags:\n");
        for f in &n.flags {
            print_flag(w, "  ", f);
        }
        w.push('\n');
    }

    if !n.subcommands.is_empty() {
        w.push_str("Subcommands:\n");
        for sub in &n.subcommands {
            w.push_str(&format!("  {} - {}\n", sub.name, sub.short));
        }
    }
}

/// Renders one flag with aligned description.
fn print_flag(w: &mut String, prefix: &str, f: &CmdFlag) {
    let mut flag_str = if !f.shorthand.is_empty() {
        format!("-{}, --{}", f.shorthand, f.name)
    } else {
        format!("    --{}", f.name)
    };

    if f.type_ != "bool" && !f.type_.is_empty() {
        flag_str.push(' ');
        flag_str.push_str(&f.type_);
    }

    let padding = pad(28, flag_str.len(), 2);
    w.push_str(&format!(
        "{prefix}{flag_str}{}{}\n",
        " ".repeat(padding),
        f.description
    ));
}

/// Locates a node by name anywhere in the catalog.
fn find_node<'a>(root: &'a CmdNode, name: &str) -> Option<&'a CmdNode> {
    if root.name == name {
        return Some(root);
    }

    for sub in &root.subcommands {
        if let Some(found) = find_node(sub, name) {
            return Some(found);
        }
    }

    None
}

/// Writes a node as indented JSON to stdout (2-space indent, trailing newline),
/// matching Go's `json.Encoder` with `SetIndent("", "  ")`.
fn encode_json(n: &CmdNode) -> i32 {
    match serde_json::to_string_pretty(n) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("git cmdtree: json encode: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Exercises the command-tree renderer in its output modes; each must render
    /// without error (exit 0).
    #[test]
    fn run_modes() {
        let cases: Vec<Vec<String>> = vec![
            args(&[]),              // default tree
            args(&["-b"]),          // brief
            args(&["--json"]),      // JSON
            args(&["-c", "scan"]),  // single-node lookup
            args(&["-c", "audit"]), // another node
        ];

        for a in &cases {
            let code = run(a);
            assert_eq!(code, 0, "run({a:?}) = {code}, want 0");
        }
    }

    #[test]
    fn run_unknown_flag() {
        assert_ne!(
            run(&args(&["--bogus"])),
            0,
            "an unknown flag should be a non-zero exit"
        );
    }

    #[test]
    fn run_unknown_node() {
        // -c on a command that does not exist should not render a node as success.
        assert_ne!(
            run(&args(&["-c", "definitely-not-a-command"])),
            0,
            "an unknown node lookup should be non-zero"
        );
    }
}
