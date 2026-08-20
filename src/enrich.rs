//! Port of Go `internal/enrich` — augment audit records with a structured snapshot
//! of repository state at the moment a git command ran.
//!
//! The default implementation is dependency-light: it shells out to the resolved
//! git backend for `status --porcelain=v2 --branch` and parses the result. The
//! [`Enricher`] trait is the extension seam. Enrichment must NEVER fail an
//! invocation — every implementation degrades to `None` on any error.

use serde::Serialize;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bounds the out-of-band `git status` call (Go `enrichTimeout`). Best-effort, so
/// a stalled status must never delay the primary command or its audit write.
const ENRICH_TIMEOUT: Duration = Duration::from_secs(5);

/// A minimal cancellation context (Go `context.Context`): a shared cancel flag +
/// an optional deadline. `background()` never cancels; `with_timeout` narrows the
/// deadline; `cancel()` trips the flag (Go's `WithCancel` cancel func).
#[derive(Clone, Default)]
pub struct Ctx {
    cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl Ctx {
    pub fn background() -> Self {
        Ctx::default()
    }

    /// Trip the cancel flag (Go's `cancel()`), affecting every clone that shares it.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn is_done(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
            || self.deadline.map(|d| Instant::now() >= d).unwrap_or(false)
    }

    fn with_timeout(&self, dur: Duration) -> Ctx {
        let cap = Instant::now() + dur;
        let deadline = Some(self.deadline.map(|e| e.min(cap)).unwrap_or(cap));
        Ctx {
            cancelled: self.cancelled.clone(),
            deadline,
        }
    }
}

/// Go `Enricher` — produce an optional structured JSON blob describing repo state
/// at `cwd`. `None` means "no enrichment available". Never errors.
pub trait Enricher {
    fn enrich(&self, ctx: &Ctx, cwd: &str) -> Option<Vec<u8>>;
}

/// Go `Noop` — an enricher that always yields nothing.
pub fn noop() -> Box<dyn Enricher> {
    Box::new(Noop)
}

struct Noop;
impl Enricher for Noop {
    fn enrich(&self, _ctx: &Ctx, _cwd: &str) -> Option<Vec<u8>> {
        None
    }
}

/// Go `NewExec` — an enricher that captures repo state by running git at
/// `git_path`. An empty path falls back to a no-op.
pub fn new_exec(git_path: &str) -> Box<dyn Enricher> {
    if git_path.is_empty() {
        return Box::new(Noop);
    }
    Box::new(ExecEnricher {
        git_path: git_path.to_string(),
    })
}

struct ExecEnricher {
    git_path: String,
}

/// The structured snapshot recorded per invocation (Go `Status`).
#[derive(Debug, Default, Serialize)]
pub struct Status {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub oid: String,
    pub ahead: i64,
    pub behind: i64,
    pub staged: i64,
    pub unstaged: i64,
    pub untracked: i64,
    pub conflicts: i64,
}

impl Enricher for ExecEnricher {
    fn enrich(&self, ctx: &Ctx, cwd: &str) -> Option<Vec<u8>> {
        let ctx = ctx.with_timeout(ENRICH_TIMEOUT);
        if ctx.is_done() {
            return None; // already cancelled/expired — degrade silently
        }
        let mut cmd = Command::new(&self.git_path);
        cmd.args(["status", "--porcelain=v2", "--branch"]);
        if !cwd.is_empty() {
            cmd.current_dir(cwd);
        }
        let out = run_bounded(cmd, &ctx)?;
        let st = parse_status(&String::from_utf8_lossy(&out));
        // Enrichment must never surface an error → drop a marshal failure to None.
        serde_json::to_vec(&st).ok()
    }
}

/// Run `cmd` capturing stdout, bounded by `ctx`'s deadline/cancel. Any failure
/// (spawn, non-zero exit, timeout) yields `None` — enrichment never errors. Stdout
/// is drained on a side thread so a full pipe can't deadlock the wait.
fn run_bounded(mut cmd: Command, ctx: &Ctx) -> Option<Vec<u8>> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if ctx.is_done() {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = reader.join();
                return None;
            }
        }
    };
    let buf = reader.join().ok()?;
    if status.success() {
        Some(buf)
    } else {
        None
    }
}

/// Parse `git status --porcelain=v2 --branch` output (Go `parseStatus`).
fn parse_status(out: &str) -> Status {
    let mut st = Status::default();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("# branch.head ") {
            st.branch = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("# branch.oid ") {
            st.oid = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("# branch.ab ") {
            let (a, b) = parse_ahead_behind(rest);
            st.ahead = a;
            st.behind = b;
        } else if line.starts_with("1 ") || line.starts_with("2 ") {
            // Ordinary/renamed change: "1 <XY> ..." — X=staged, Y=unstaged.
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1].len() == 2 {
                let xy = fields[1].as_bytes();
                if xy[0] != b'.' {
                    st.staged += 1;
                }
                if xy[1] != b'.' {
                    st.unstaged += 1;
                }
            }
        } else if line.starts_with("u ") {
            st.conflicts += 1;
        } else if line.starts_with("? ") {
            st.untracked += 1;
        }
    }
    st
}

/// Parse `"+A -B"` into `(A, B)` (Go `parseAheadBehind`).
fn parse_ahead_behind(s: &str) -> (i64, i64) {
    let (mut ahead, mut behind) = (0i64, 0i64);
    for tok in s.split_whitespace() {
        if tok.len() < 2 {
            continue;
        }
        let Ok(n) = tok[1..].parse::<i64>() else {
            continue;
        };
        match tok.as_bytes()[0] {
            b'+' => ahead = n,
            b'-' => behind = n,
            _ => {}
        }
    }
    (ahead, behind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_counts() {
        let out = concat!(
            "# branch.oid abc123\n",
            "# branch.head main\n",
            "# branch.ab +2 -1\n",
            "1 A. N... 100644 100644 100644 0000 1111 added.go\n",
            "1 MM N... 100644 100644 100644 2222 3333 both.go\n",
            "1 .M N... 100644 100644 100644 4444 4444 work.go\n",
            "u UU N... 100644 100644 100644 100644 5555 6666 7777 conflict.go\n",
            "? untracked.go\n",
        );
        let st = parse_status(out);
        assert_eq!(st.branch, "main");
        assert_eq!(st.oid, "abc123");
        assert_eq!((st.ahead, st.behind), (2, 1));
        assert_eq!(st.staged, 2, "A. and MM");
        assert_eq!(st.unstaged, 2, "MM and .M");
        assert_eq!(st.untracked, 1);
        assert_eq!(st.conflicts, 1);
    }

    #[test]
    fn parse_status_clean() {
        let out = "# branch.oid deadbeef\n# branch.head release\n# branch.ab +0 -0\n";
        let st = parse_status(out);
        assert_eq!(st.staged + st.unstaged + st.untracked + st.conflicts, 0);
        assert_eq!(st.branch, "release");
    }

    #[test]
    fn new_exec_empty_path_is_noop() {
        // An empty path yields the no-op enricher — it never enriches, even with a
        // real cwd (behavioral check; Go asserts the concrete `noop` type).
        assert!(new_exec("").enrich(&Ctx::background(), ".").is_none());
    }

    #[test]
    fn enrich_degrades_on_cancelled_context() {
        let e = ExecEnricher {
            git_path: "git".to_string(),
        };
        let ctx = Ctx::background();
        ctx.cancel();
        assert!(
            e.enrich(&ctx, "").is_none(),
            "Enrich on a cancelled context must yield None"
        );
    }
}
