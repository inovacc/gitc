//! Port of Go `report/template.go` — `--report-format template`.
//!
//! ## The dependency call
//!
//! Go builds this on `text/template` plus `go-sprout/sprout/sprigin`. Both are
//! whole languages' worth of behaviour: a lexer, a parser, a pipeline
//! evaluator, and ~200 template functions. Hand-porting them is exactly what
//! the dependency rubric names as a review defect — so this uses:
//!
//! * **`gtmpl`** (`gtmpl-rust`) — an implementation of Go's `text/template`
//!   grammar in Rust: actions, pipelines, `range`/`with`/`if`, variables, and
//!   the `{{-` / `-}}` trim markers, with Go's own builtins (`eq`, `ne`, `len`,
//!   `index`, `printf`, …);
//! * **`sprig`** (`sprig-rust`, by the same author) — a Rust port of a slice of
//!   sprig's function set.
//!
//! ## What is NOT there, and why that is safe
//!
//! `sprig-rust` carries 35 of sprig's functions. This module adds the ones the
//! shipped templates need and that arithmetic/quoting templates reach for
//! first — see [`EXTRA_FUNCS`] — but the set is still a SUBSET.
//!
//! That is safe because an unknown function is a **parse error naming the
//! function**, exactly as in Go, before a single finding is written. A template
//! using something unsupported fails loudly at load time; it never renders a
//! quietly wrong report. The error is normalised to Go's wording,
//! `function "x" not defined`, because that is the string Go's own tests assert
//! and what a template author will search for.
//!
//! ## The three deleted functions
//!
//! Go explicitly deletes `env`, `expandenv` and `getHostByName` from the func
//! map before parsing. A report template is frequently supplied by whoever
//! controls CI config rather than the repository owner, and those three turn a
//! formatting template into an environment exfiltrator (`{{ env "AWS_SECRET_
//! ACCESS_KEY" }}`) or an outbound DNS request. `sprig-rust` does not implement
//! them, and [`assert_dangerous_funcs_absent`] makes their absence a TESTED
//! property rather than a lucky accident of the crate's coverage.

use crate::finding::Finding;
use gtmpl::{Func, FuncError, Template, Value};
use std::collections::HashMap;

/// Go `TemplateReporter`.
pub struct TemplateReporter {
    template: Template,
}

/// `gtmpl::Template` holds function pointers and is not `Debug`, so this is
/// written by hand — without it `unwrap_err()` on a construction failure will
/// not compile.
impl std::fmt::Debug for TemplateReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateReporter")
            .field("name", &self.template.name)
            .field("funcs", &self.template.funcs.len())
            .finish()
    }
}

/// The three functions Go removes from sprig's map before parsing.
///
/// Kept as data so the test can assert on it, and so adding a richer sprig
/// port later cannot silently reintroduce them.
pub const DANGEROUS_FUNCS: &[&str] = &["env", "expandenv", "getHostByName"];

impl TemplateReporter {
    /// Go `NewTemplateReporter`.
    ///
    /// Parses at construction so a broken template fails BEFORE the scan's
    /// findings are thrown at it — Go does the same, and it is the difference
    /// between "your template has a typo" and "the scan finished and produced
    /// nothing".
    pub fn new(template_path: &str) -> Result<TemplateReporter, String> {
        if template_path.is_empty() {
            return Err("template path cannot be empty".to_string());
        }
        let text = std::fs::read_to_string(template_path)
            .map_err(|e| format!("error reading file: {e}"))?;
        TemplateReporter::from_text(&text)
    }

    /// The parse half, split out so tests need no temp files.
    pub fn from_text(text: &str) -> Result<TemplateReporter, String> {
        let mut template = Template::with_name("custom");
        template.add_funcs(sprig::SPRIG);
        template.add_funcs(EXTRA_FUNCS);
        for name in DANGEROUS_FUNCS {
            template.funcs.remove(*name);
        }

        template
            .parse(text)
            .map_err(|e| normalise_undefined_function(&e.to_string()))?;
        Ok(TemplateReporter { template })
    }

    /// Go `(*TemplateReporter).Write`.
    ///
    /// Takes `&mut dyn Write` rather than a generic so the trait impl can
    /// forward to it — a `dyn Write` is unsized and cannot satisfy `W: Write`.
    pub fn write(
        &self,
        w: &mut dyn std::io::Write,
        findings: &[Finding],
    ) -> Result<(), String> {
        let data = Value::Array(findings.iter().map(finding_to_value).collect());
        let rendered = self
            .template
            .render(&gtmpl::Context::from(data))
            .map_err(|e| e.to_string())?;
        w.write_all(rendered.as_bytes())
            .map_err(|e| e.to_string())
    }
}

/// gtmpl says `function env not defined`; Go says `function "env" not defined`.
///
/// Normalised rather than left alone because the quoted form is what Go's tests
/// assert and what anyone searching for the message will type.
fn normalise_undefined_function(msg: &str) -> String {
    const MARKER: &str = "function ";
    const TAIL: &str = " not defined";
    let Some(start) = msg.find(MARKER) else {
        return msg.to_string();
    };
    let name_start = start + MARKER.len();
    let Some(rel_end) = msg[name_start..].find(TAIL) else {
        return msg.to_string();
    };
    let name = &msg[name_start..name_start + rel_end];
    if name.starts_with('"') {
        return msg.to_string();
    }
    format!(
        "{}{MARKER}\"{name}\"{TAIL}{}",
        &msg[..start],
        &msg[name_start + rel_end + TAIL.len()..]
    )
}

/// One `report.Finding` as a template context.
///
/// Built field by field from the STRUCT rather than via the JSON encoder,
/// because the JSON form omits empty fields (`omitempty`) while Go's template
/// sees a struct where every field always exists. Going through JSON would make
/// `{{ .SymlinkFile }}` fail on exactly the findings where it is empty — which
/// is most of them.
///
/// The keys are Go's EXPORTED FIELD NAMES, which is what a template writes.
fn finding_to_value(f: &Finding) -> Value {
    let mut m: HashMap<String, Value> = HashMap::new();
    let mut set = |k: &str, v: Value| {
        m.insert(k.to_string(), v);
    };

    set("RuleID", Value::from(f.rule_id.clone()));
    set("Description", Value::from(f.description.clone()));
    set("StartLine", Value::from(f.start_line));
    set("EndLine", Value::from(f.end_line));
    set("StartColumn", Value::from(f.start_column));
    set("EndColumn", Value::from(f.end_column));
    set("Match", Value::from(f.r#match.clone()));
    set("Secret", Value::from(f.secret.clone()));
    set("MatchContext", Value::from(f.match_context.clone()));
    set("Line", Value::from(f.line.clone()));
    set("File", Value::from(f.file.clone()));
    set("SymlinkFile", Value::from(f.symlink_file.clone()));
    set("Commit", Value::from(f.commit.clone()));
    set("Link", Value::from(f.link.clone()));
    // Go's field is a float32 and `%v` prints the shortest decimal that
    // round-trips AS A FLOAT32 — `4.121928`. Handing gtmpl the f32 directly
    // widens it to f64 first, and the shortest f64 round-trip of that same
    // value is `4.1219282150268555`. Formatting at f32 precision and reparsing
    // pins the value to the digits Go would print.
    set("Entropy", Value::from(reparse_as_f32_precision(f.entropy)));
    set("Author", Value::from(f.author.clone()));
    set("Email", Value::from(f.email.clone()));
    set("Date", Value::from(f.date.clone()));
    set("Message", Value::from(f.message.clone()));
    set("Fingerprint", Value::from(f.fingerprint.clone()));
    set(
        "Tags",
        Value::Array(f.tags.iter().cloned().map(Value::from).collect()),
    );
    set(
        "CaptureGroups",
        Value::Object(
            f.capture_groups
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.clone())))
                .collect(),
        ),
    );
    set(
        "Attributes",
        Value::Object(
            f.attributes
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.clone())))
                .collect(),
        ),
    );
    set("ValidationStatus", Value::from(f.validation_status.as_str()));
    set("ValidationReason", Value::from(f.validation_reason.clone()));

    Value::Object(m)
}

/// A render failure is an `io::Error` so the reporter fits the shared trait.
/// The template's own error text is carried through rather than flattened -
/// "unexpected .Nope" is the only thing that tells the author what to fix.
impl crate::Reporter for TemplateReporter {
    fn write(&self, w: &mut dyn std::io::Write, findings: &[Finding]) -> std::io::Result<()> {
        TemplateReporter::write(self, w, findings)
            .map_err(|e| std::io::Error::other(e))
    }
}

/// The sprig functions this port supplies on top of `sprig-rust`'s 35.
///
/// Chosen from what the shipped templates actually use — `quote` and `sub` are
/// both in `testdata/report/jsonextra.tmpl` — plus the arithmetic and quoting
/// neighbours a template reaches for in the same breath. Everything else still
/// fails loudly by name.
pub static EXTRA_FUNCS: &[(&str, Func)] = &[
    ("quote", quote as Func),
    ("squote", squote as Func),
    ("add", add as Func),
    ("sub", sub as Func),
    ("mul", mul as Func),
    ("div", div as Func),
    ("mod", modulo as Func),
    ("max", max as Func),
    ("min", min as Func),
    ("title", title as Func),
    ("date", date as Func),
];

/// sprig `quote` — wrap each argument in double quotes, space-separated.
///
/// Go's sprig escapes with `%q`, so an embedded quote or backslash comes back
/// escaped. A template emitting JSON (`jsonextra.tmpl`) depends on that: a
/// secret containing a `"` would otherwise produce an unparseable report.
fn quote(args: &[Value]) -> Result<Value, FuncError> {
    Ok(Value::from(
        args.iter()
            .map(|v| go_quote(&to_display(v)))
            .collect::<Vec<_>>()
            .join(" "),
    ))
}

/// sprig `squote` — single quotes, and NO escaping, matching sprig.
fn squote(args: &[Value]) -> Result<Value, FuncError> {
    Ok(Value::from(
        args.iter()
            .map(|v| format!("'{}'", to_display(v)))
            .collect::<Vec<_>>()
            .join(" "),
    ))
}

/// Go's `%q` for a string: double quotes, with `"`, `\`, and the control
/// characters escaped the way Go's `strconv.Quote` does.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Go escapes the remaining C0 controls and DEL as \xNN.
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// sprig's arithmetic is int64 and variadic where Go's is.
fn add(args: &[Value]) -> Result<Value, FuncError> {
    Ok(Value::from(ints(args)?.iter().sum::<i64>()))
}

/// `sub a b` is `a - b` — NOT a fold. Getting this backwards would silently
/// change every index computed as `sub (len .) 1`.
fn sub(args: &[Value]) -> Result<Value, FuncError> {
    let n = pair("sub", args)?;
    Ok(Value::from(n.0.wrapping_sub(n.1)))
}

fn mul(args: &[Value]) -> Result<Value, FuncError> {
    Ok(Value::from(
        ints(args)?.iter().fold(1i64, |a, b| a.wrapping_mul(*b)),
    ))
}

fn div(args: &[Value]) -> Result<Value, FuncError> {
    let n = pair("div", args)?;
    if n.1 == 0 {
        return Err(FuncError::Generic("div: division by zero".into()));
    }
    Ok(Value::from(n.0 / n.1))
}

fn modulo(args: &[Value]) -> Result<Value, FuncError> {
    let n = pair("mod", args)?;
    if n.1 == 0 {
        return Err(FuncError::Generic("mod: division by zero".into()));
    }
    Ok(Value::from(n.0 % n.1))
}

fn max(args: &[Value]) -> Result<Value, FuncError> {
    ints(args)?
        .into_iter()
        .max()
        .map(Value::from)
        .ok_or_else(|| FuncError::AtLeastXArgs("max".into(), 1))
}

fn min(args: &[Value]) -> Result<Value, FuncError> {
    ints(args)?
        .into_iter()
        .min()
        .map(Value::from)
        .ok_or_else(|| FuncError::AtLeastXArgs("min".into(), 1))
}

/// sprig `title` — capitalise the first letter of each word.
fn title(args: &[Value]) -> Result<Value, FuncError> {
    let s = to_display(args.first().unwrap_or(&Value::NoValue));
    let mut out = String::with_capacity(s.len());
    let mut start_of_word = true;
    for c in s.chars() {
        if start_of_word {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
        start_of_word = c.is_whitespace();
    }
    Ok(Value::from(out))
}

/// sprig `date LAYOUT TIME` — format a timestamp with a GO REFERENCE LAYOUT.
///
/// The time comes either as `sprig-rust`'s `now` (a map carrying `Unix`) or as
/// a bare integer of Unix seconds. Only the layout tokens are supported; an
/// unrecognised run of the layout is copied through, which is what Go does with
/// literal text.
///
/// The calendar maths is Howard Hinnant's `civil_from_days`, the inverse of the
/// `days_from_civil` already used to parse git dates. Everything is UTC: sprig
/// has no zone handling here and inventing one would make reports differ by
/// machine.
fn date(args: &[Value]) -> Result<Value, FuncError> {
    if args.len() < 2 {
        return Err(FuncError::ExactlyXArgs("date".into(), 2));
    }
    let layout = to_display(&args[0]);
    let secs = unix_seconds(&args[1])
        .ok_or_else(|| FuncError::Generic("date: expected a time value".into()))?;
    Ok(Value::from(format_go_layout(&layout, secs)))
}

fn unix_seconds(v: &Value) -> Option<i64> {
    match v {
        Value::Object(m) | Value::Map(m) => m.get("Unix").and_then(unix_seconds),
        Value::Number(n) => n.as_i64().or_else(|| n.as_u64().map(|u| u as i64)),
        _ => None,
    }
}

/// The subset of Go's reference layout (`Mon Jan 2 15:04:05 MST 2006`) that a
/// report template plausibly uses. Longest tokens first — `2006` must be tried
/// before `2`, or a year would render as a day-of-month.
fn format_go_layout(layout: &str, unix_secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];

    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // 1970-01-01 was a Thursday (index 4).
    let weekday = (days.rem_euclid(7) + 4) as usize % 7;
    let hour12 = if hh % 12 == 0 { 12 } else { hh % 12 };

    let tokens: &[(&str, String)] = &[
        ("2006", format!("{y:04}")),
        ("January", MONTHS[(m - 1) as usize].to_string()),
        ("Monday", DAYS[weekday].to_string()),
        ("Jan", MONTHS[(m - 1) as usize][..3].to_string()),
        ("Mon", DAYS[weekday][..3].to_string()),
        ("-0700", "+0000".to_string()),
        ("Z07:00", "Z".to_string()),
        ("MST", "UTC".to_string()),
        ("PM", if hh < 12 { "AM" } else { "PM" }.to_string()),
        ("01", format!("{m:02}")),
        ("02", format!("{d:02}")),
        ("03", format!("{hour12:02}")),
        ("04", format!("{mm:02}")),
        ("05", format!("{ss:02}")),
        ("15", format!("{hh:02}")),
        ("06", format!("{:02}", y.rem_euclid(100))),
        ("1", format!("{m}")),
        ("2", format!("{d}")),
        ("3", format!("{hour12}")),
    ];

    let mut out = String::with_capacity(layout.len() + 8);
    let bytes = layout.as_bytes();
    let mut i = 0;
    'outer: while i < bytes.len() {
        for (token, value) in tokens {
            if layout[i..].starts_with(token) {
                out.push_str(value);
                i += token.len();
                continue 'outer;
            }
        }
        // Not a token: copy the character through, respecting UTF-8.
        let ch = layout[i..].chars().next().expect("i is a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Howard Hinnant's `civil_from_days` — days since the Unix epoch to a
/// proleptic-Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// An `f32` as the `f64` whose shortest representation is the f32's digits.
///
/// `4.121928_f32 as f64` is `4.1219282150268555`; this gives `4.121928`, which
/// is what Go prints for the same float32. Rust's `{}` for `f32` already emits
/// the shortest round-tripping decimal, so reparsing that string is the whole
/// trick.
fn reparse_as_f32_precision(v: f32) -> f64 {
    format!("{v}").parse::<f64>().unwrap_or(v as f64)
}

/// Coerce a value the way a template prints it, so `quote 3` gives `"3"`.
fn to_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::NoValue | Value::Nil => String::new(),
        other => other.to_string(),
    }
}

fn ints(args: &[Value]) -> Result<Vec<i64>, FuncError> {
    args.iter()
        .map(|v| to_i64(v).ok_or_else(|| FuncError::Generic(format!("expected a number, got {v}"))))
        .collect()
}

fn pair(name: &str, args: &[Value]) -> Result<(i64, i64), FuncError> {
    if args.len() != 2 {
        return Err(FuncError::ExactlyXArgs(name.into(), 2));
    }
    let a = to_i64(&args[0])
        .ok_or_else(|| FuncError::Generic(format!("{name}: expected a number, got {}", args[0])))?;
    let b = to_i64(&args[1])
        .ok_or_else(|| FuncError::Generic(format!("{name}: expected a number, got {}", args[1])))?;
    Ok((a, b))
}

fn to_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().map(|u| u as i64))
            .or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
