//! Characterization tests for the `logging` port. Go `logging/log.go` has NO
//! test file, so these pin the behaviour read off the source: the default level,
//! level gating, the fluent field API, and the stderr destination.

use super::*;

#[test]
fn default_level_is_info() {
    assert_eq!(Level::default(), Level::Info);
}

/// Go builds the logger with `.Level(zerolog.InfoLevel)`, so Trace and Debug are
/// suppressed by default and everything Info-and-above is emitted.
#[test]
fn info_level_gating() {
    assert!(!Level::Trace.enabled_at(Level::Info));
    assert!(!Level::Debug.enabled_at(Level::Info));
    assert!(Level::Info.enabled_at(Level::Info));
    assert!(Level::Warn.enabled_at(Level::Info));
    assert!(Level::Error.enabled_at(Level::Info));
    assert!(Level::Fatal.enabled_at(Level::Info));
    assert!(Level::Panic.enabled_at(Level::Info));
}

#[test]
fn trace_level_enables_everything() {
    for l in [
        Level::Trace,
        Level::Debug,
        Level::Info,
        Level::Warn,
        Level::Error,
    ] {
        assert!(l.enabled_at(Level::Trace), "{l:?} at Trace");
    }
}

/// zerolog's ConsoleWriter renders a three-letter uppercase level tag.
#[test]
fn level_tags() {
    assert_eq!(Level::Trace.tag(), "TRC");
    assert_eq!(Level::Debug.tag(), "DBG");
    assert_eq!(Level::Info.tag(), "INF");
    assert_eq!(Level::Warn.tag(), "WRN");
    assert_eq!(Level::Error.tag(), "ERR");
    assert_eq!(Level::Fatal.tag(), "FTL");
    assert_eq!(Level::Panic.tag(), "PNC");
}

/// The fluent field API: `.str()`, `.int()`, `.err()` accumulate in CALL ORDER
/// and render as `key=value` after the message, like zerolog's ConsoleWriter.
#[test]
fn event_renders_fields_in_order() {
    let line = Event::for_test(Level::Info)
        .str("rule", "aws-access-token")
        .int("line", 42)
        .render("secret detected");
    assert_eq!(
        line,
        "INF secret detected rule=aws-access-token line=42"
    );
}

#[test]
fn event_without_fields_is_just_level_and_message() {
    assert_eq!(Event::for_test(Level::Warn).render("careful"), "WRN careful");
}

/// `Send()` in zerolog emits with an EMPTY message.
#[test]
fn send_emits_empty_message() {
    let line = Event::for_test(Level::Info).str("k", "v").render("");
    assert_eq!(line, "INF  k=v");
}

/// `.err()` attaches under the conventional `error` key.
#[test]
fn err_field_uses_error_key() {
    let e = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
    let line = Event::for_test(Level::Error).err(&e).render("open failed");
    // The message has spaces, so the space-quoting rule applies to it too.
    assert_eq!(line, "ERR open failed error=\"no such file\"");

    // A space-free error is unquoted.
    let e = std::io::Error::new(std::io::ErrorKind::NotFound, "ENOENT");
    let line = Event::for_test(Level::Error).err(&e).render("open failed");
    assert_eq!(line, "ERR open failed error=ENOENT");
}

/// A disabled event accumulates nothing and renders nothing — the cheap path
/// that makes 18 `Trace()` call sites free at the default level.
#[test]
fn disabled_event_is_inert() {
    let ev = Event::disabled(Level::Trace);
    assert!(!ev.is_enabled());
    assert_eq!(ev.str("k", "v").int("n", 1).render("msg"), "");
}

/// Values containing a space are quoted so `key=value` stays parseable.
#[test]
fn values_with_spaces_are_quoted() {
    let line = Event::for_test(Level::Info)
        .str("path", "C:\\Program Files\\x")
        .render("m");
    assert_eq!(line, "INF m path=\"C:\\Program Files\\x\"");
}
