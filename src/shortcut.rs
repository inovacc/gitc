//! Port of Go `internal/shortcut` — gitc's built-in convenience commands. Each
//! shortcut is a thin composition of real git argument vectors (never a
//! reimplementation of git logic), so every underlying git call runs through the
//! same audited backend as passthrough commands.

/// A named sequence of git argument vectors run in order. Steps stop at the first
/// non-zero exit (see the runner). `steps` is a plain fn pointer — the Go closures
/// capture nothing.
pub struct Shortcut {
    pub name: &'static str,
    pub short: &'static str,
    /// Ordered git arg vectors for the given user args.
    pub steps: fn(&[String]) -> Vec<Vec<String>>,
    /// Minimum number of positional args required.
    pub min_args: usize,
    /// Usage documentation, shown on misuse.
    pub usage: &'static str,
}

/// Build an owned arg vector from string literals.
fn v(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Go `All` — the starter shortcut set (intentionally small, extensible later).
pub fn all() -> Vec<Shortcut> {
    vec![
        Shortcut {
            name: "sync",
            short: "Fetch, rebase onto the upstream tracking branch, then push",
            min_args: 0,
            usage: "",
            steps: |_| vec![v(&["fetch", "--prune"]), v(&["rebase"]), v(&["push"])],
        },
        Shortcut {
            name: "undo",
            short: "Soft-reset the last commit, keeping its changes staged",
            min_args: 0,
            usage: "",
            steps: |_| vec![v(&["reset", "--soft", "HEAD~1"])],
        },
        Shortcut {
            name: "log-graph",
            short: "Show a decorated commit graph across all refs",
            min_args: 0,
            usage: "",
            steps: |args| {
                let mut base = v(&["log", "--graph", "--oneline", "--decorate", "--all"]);
                base.extend(args.iter().cloned());
                vec![base]
            },
        },
        Shortcut {
            name: "quick-commit",
            short: "Stage all changes and commit with a message",
            min_args: 1,
            usage: "quick-commit <message>",
            steps: |args| {
                let msg = args.first().cloned().unwrap_or_default();
                vec![
                    v(&["add", "-A"]),
                    vec!["commit".to_string(), "-m".to_string(), msg],
                ]
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn by_name() -> HashMap<&'static str, Shortcut> {
        all().into_iter().map(|s| (s.name, s)).collect()
    }

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn shortcut_steps() {
        let sc = by_name();
        let cases: [(&str, Vec<String>, Vec<Vec<String>>); 3] = [
            (
                "sync",
                vec![],
                vec![s(&["fetch", "--prune"]), s(&["rebase"]), s(&["push"])],
            ),
            ("undo", vec![], vec![s(&["reset", "--soft", "HEAD~1"])]),
            (
                "quick-commit",
                s(&["hello"]),
                vec![s(&["add", "-A"]), s(&["commit", "-m", "hello"])],
            ),
        ];
        for (name, args, want) in cases {
            let sh = sc
                .get(name)
                .unwrap_or_else(|| panic!("shortcut {name:?} missing"));
            assert_eq!((sh.steps)(&args), want, "{name} steps");
        }
    }

    #[test]
    fn log_graph_appends_args() {
        let sc = by_name();
        let steps = (sc["log-graph"].steps)(&s(&["-n", "5"]));
        assert_eq!(steps.len(), 1, "log-graph should be one step: {steps:?}");
        let last = &steps[0];
        assert_eq!(last.last().unwrap(), "5");
        assert_eq!(last[0], "log");
    }

    #[test]
    fn quick_commit_requires_message() {
        assert_eq!(by_name()["quick-commit"].min_args, 1);
    }
}
