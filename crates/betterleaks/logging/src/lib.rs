//! Port of Go `logging/log.go` — the package-level zerolog wrapper.
//!
//! **Reshape (flagged):** Go wraps `github.com/rs/zerolog`
//! (`zerolog.ConsoleWriter{Out: os.Stderr}`, `InfoLevel`, `.With().Timestamp()`).
//! Rust std has no logger, and pulling `tracing` + a subscriber would be a large
//! ecosystem dependency for a 39-line stderr writer that NO test asserts. So the
//! port hand-rolls an equivalent: the same levels, the same default gating, the
//! same fluent Event API, the same stderr destination.
//!
//! **Quirk preserved:** the Go source comment says *"send all logs to stdout"*
//! but the code writes to `os.Stderr`. The CODE is the behaviour, so this port
//! writes to stderr too — the comment is wrong upstream and is reproduced here
//! only as this note.
//!
//! **Approximated (flagged):** zerolog's exact ConsoleWriter layout (colour
//! codes, timestamp formatting, field alignment) is NOT byte-reproduced. Nothing
//! observable depends on it; the shape is `<TAG> <message> key=value…`.

/// Go 	ime.Duration formatting — see the module docs.
pub mod duration;

use std::fmt::Display;
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/// Go `zerolog.Level`, restricted to the levels the wrapper exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

impl Default for Level {
    /// Go: `.Level(zerolog.InfoLevel)`.
    fn default() -> Level {
        Level::Info
    }
}

impl Level {
    /// zerolog's ConsoleWriter three-letter tag.
    pub fn tag(self) -> &'static str {
        match self {
            Level::Trace => "TRC",
            Level::Debug => "DBG",
            Level::Info => "INF",
            Level::Warn => "WRN",
            Level::Error => "ERR",
            Level::Fatal => "FTL",
            Level::Panic => "PNC",
        }
    }

    /// Would an event at `self` be emitted when the logger is set to `minimum`?
    pub fn enabled_at(self, minimum: Level) -> bool {
        self >= minimum
    }

    fn as_u8(self) -> u8 {
        match self {
            Level::Trace => 0,
            Level::Debug => 1,
            Level::Info => 2,
            Level::Warn => 3,
            Level::Error => 4,
            Level::Fatal => 5,
            Level::Panic => 6,
        }
    }

    fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::Trace,
            1 => Level::Debug,
            3 => Level::Warn,
            4 => Level::Error,
            5 => Level::Fatal,
            6 => Level::Panic,
            _ => Level::Info,
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(2); // Info

/// The logger's current minimum level.
pub fn level() -> Level {
    Level::from_u8(LEVEL.load(Ordering::Relaxed))
}

/// Go's `Logger = zerolog.New(...).Level(l)` — reset the minimum level.
pub fn set_level(l: Level) {
    LEVEL.store(l.as_u8(), Ordering::Relaxed);
}

/// Go `*zerolog.Event` — a fluent, single-use log record.
pub struct Event {
    level: Level,
    enabled: bool,
    fields: Vec<(String, String)>,
    /// Test mode: `render` returns the line instead of writing it to stderr.
    capture: bool,
}

impl Event {
    fn new(level: Level) -> Event {
        Event {
            level,
            enabled: level.enabled_at(self::level()),
            fields: Vec::new(),
            capture: false,
        }
    }

    /// An event that will never emit — the cheap path for suppressed levels.
    pub fn disabled(level: Level) -> Event {
        Event {
            level,
            enabled: false,
            fields: Vec::new(),
            capture: false,
        }
    }

    /// An always-enabled, non-writing event, for asserting rendering.
    pub fn for_test(level: Level) -> Event {
        Event {
            level,
            enabled: true,
            fields: Vec::new(),
            capture: true,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Go `Event.Str(key, value)`.
    pub fn str(mut self, key: &str, value: impl Display) -> Event {
        if self.enabled {
            self.fields.push((key.to_string(), value.to_string()));
        }
        self
    }

    /// Go `Event.Int` / `Event.Int64`.
    pub fn int(mut self, key: &str, value: i64) -> Event {
        if self.enabled {
            self.fields.push((key.to_string(), value.to_string()));
        }
        self
    }

    /// Go `Event.Err(err)` — attaches under the conventional `error` key.
    pub fn err(mut self, e: &dyn Display) -> Event {
        if self.enabled {
            self.fields.push(("error".to_string(), e.to_string()));
        }
        self
    }

    /// Go `Event.Msg(msg)`. Terminal: Fatal exits, Panic panics.
    pub fn msg(self, msg: &str) {
        let level = self.level;
        let line = self.render(msg);
        if !line.is_empty() {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
        // zerolog: Fatal calls os.Exit(1) and Panic panics, AFTER writing.
        match level {
            Level::Fatal => std::process::exit(1),
            Level::Panic => panic!("{msg}"),
            _ => {}
        }
    }

    /// Go `Event.Send()` — emit with an empty message.
    pub fn send(self) {
        self.msg("");
    }

    /// Build the output line. Returns an empty string when the event is
    /// suppressed. Public for tests via [`Event::for_test`].
    pub fn render(self, msg: &str) -> String {
        if !self.enabled {
            return String::new();
        }
        let mut out = String::new();
        out.push_str(self.level.tag());
        out.push(' ');
        out.push_str(msg);
        for (k, v) in &self.fields {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            if v.contains(' ') {
                out.push('"');
                out.push_str(v);
                out.push('"');
            } else {
                out.push_str(v);
            }
        }
        let _ = self.capture; // capture only distinguishes msg() from render()
        out
    }
}

/// Go `logging.Trace()`.
pub fn trace() -> Event {
    Event::new(Level::Trace)
}
/// Go `logging.Debug()`.
pub fn debug() -> Event {
    Event::new(Level::Debug)
}
/// Go `logging.Info()`.
pub fn info() -> Event {
    Event::new(Level::Info)
}
/// Go `logging.Warn()`.
pub fn warn() -> Event {
    Event::new(Level::Warn)
}
/// Go `logging.Error()`.
pub fn error() -> Event {
    Event::new(Level::Error)
}
/// Go `logging.Err(err)` — an Error-level event with the error attached.
pub fn err(e: &dyn Display) -> Event {
    Event::new(Level::Error).err(e)
}
/// Go `logging.Fatal()` — emits, then exits with status 1.
pub fn fatal() -> Event {
    Event::new(Level::Fatal)
}
/// Go `logging.Panic()` — emits, then panics.
pub fn panic() -> Event {
    Event::new(Level::Panic)
}

#[cfg(test)]
mod tests;
