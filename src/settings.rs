//! Port of Go `internal/settings` (settings.go + lock.go) — persists gitc's
//! on-disk configuration (`settings.json`): the active managed-git backend pointer
//! and the background-update policy (ADR 0005). It is the single source of truth
//! for backend resolution and update throttling.
//!
//! Writes are **atomic** (temp file in the same dir + rename) so a crash mid-write
//! can never leave a partially-written settings file, and cross-process
//! read-modify-write cycles are serialized by an **advisory lockfile**
//! ([`with_lock`] / [`mutate`]).
//!
//! ## Time handling (preserved quirks)
//!
//! - `Update.interval` is a Go `time.Duration` STRING (e.g. `"336h0m0s"`).
//!   Go's `time.ParseDuration` / `Duration.String()` have no std-Rust equivalent,
//!   so a faithful hand-port of the h/m/s(/ms/µs/ns) subset lives here
//!   ([`parse_go_duration`] / [`format_go_duration`]) — matching Go's algorithm
//!   bug-for-bug (overflow guards, trailing-zero trimming, the `µs`/`μs` units).
//! - RFC 3339 timestamps use the `time` crate (std has no RFC 3339).
//! - [`Update::interval_duration`] falls back to [`DEFAULT_INTERVAL`] on an empty
//!   OR invalid OR non-positive value; [`Update::due_since`] treats an
//!   empty/invalid `last` as always-due and a disabled policy as never-due —
//!   EXACTLY as Go, pinned by the tests.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The `settings.json` format version; bumped when the shape changes (migrations
/// follow the deprecation policy). Go `schemaVersion`.
const SCHEMA_VERSION: i64 = 1;

/// The fallback background-update check cadence (2 weeks). Go `DefaultInterval`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// Only activates a sha256-verified install. Go `ChannelPinned`.
pub const CHANNEL_PINNED: &str = "pinned";
/// Allows the newest upstream release without a pinned digest (unverified) —
/// opt-in only. Go `ChannelLatest`.
pub const CHANNEL_LATEST: &str = "latest";

// --- advisory lock timing (Go lock.go consts) ---
const LOCK_SUFFIX: &str = ".lock";
const LOCK_STALE: Duration = Duration::from_secs(10);
const LOCK_ACQUIRE_MAX: Duration = Duration::from_secs(5);
const LOCK_SPIN: Duration = Duration::from_millis(2);

/// The full `settings.json` document. Go `Settings`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version.
    pub version: i64,
    /// The active managed-git backend pointer.
    pub backend: Backend,
    /// The background-update policy + throttle state.
    pub update: Update,
}

/// Points at the active managed-git install (and a rollback target), as paths
/// relative to the gitc root. Go `Backend`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Backend {
    /// The active install path.
    pub active: String,
    /// The rollback target (Go `previous,omitempty`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub previous: String,
    /// The provisioned variant (`""`/`minimal`/`busybox`/`full`) — Go
    /// `flavor,omitempty`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub flavor: String,
}

/// The background-update policy and throttle state. Go `Update`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Update {
    /// Whether background checks are enabled.
    pub enabled: bool,
    /// The channel (`pinned`/`latest`).
    pub channel: String,
    /// The check cadence as a Go duration string (e.g. `"336h0m0s"`).
    pub interval: String,
    /// Last backend check timestamp, RFC 3339 (Go `backendLastCheck,omitempty`).
    #[serde(rename = "backendLastCheck", skip_serializing_if = "String::is_empty")]
    pub backend_last_check: String,
    /// Last gitc check timestamp, RFC 3339 (Go `gitcLastCheck,omitempty`).
    #[serde(rename = "gitcLastCheck", skip_serializing_if = "String::is_empty")]
    pub gitc_last_check: String,
}

/// An error persisting or loading `settings.json` (Go returned `error`).
#[derive(Debug)]
pub enum Error {
    /// An I/O error (read/write/rename/mkdir). Preserves `ErrorKind::NotFound`
    /// so callers can distinguish "no config yet" (Go `os.ErrNotExist`).
    Io(io::Error),
    /// The file existed but its JSON did not parse (Go `parse settings <p>: <e>`).
    Parse {
        /// The settings path that failed to parse.
        path: String,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
    /// The advisory lock could not be acquired within [`LOCK_ACQUIRE_MAX`].
    LockTimeout {
        /// The lockfile path.
        path: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Parse { path, source } => write!(f, "parse settings {path}: {source}"),
            Error::LockTimeout { path } => write!(
                f,
                "acquire settings lock {path}: timed out after {}",
                format_go_duration(LOCK_ACQUIRE_MAX)
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse { source, .. } => Some(source),
            Error::LockTimeout { .. } => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// The out-of-the-box settings: background checks enabled every two weeks on the
/// verified (pinned) channel, with no backend selected yet. Go `Default`.
pub fn default() -> Settings {
    Settings {
        version: SCHEMA_VERSION,
        backend: Backend::default(),
        update: Update {
            enabled: true,
            channel: CHANNEL_PINNED.to_string(),
            interval: format_go_duration(DEFAULT_INTERVAL),
            backend_last_check: String::new(),
            gitc_last_check: String::new(),
        },
    }
}

/// Reads and parses `settings.json`. A missing file is reported as
/// [`Error::Io`] with `ErrorKind::NotFound` so callers can distinguish "no config
/// yet" from a parse error. Go `Load`.
pub fn load(path: &Path) -> Result<Settings, Error> {
    let data = fs::read(path)?;
    match serde_json::from_slice::<Settings>(&data) {
        Ok(s) => Ok(s),
        Err(source) => Err(Error::Parse {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Loads `settings.json`, creating it with [`default`] when it does not exist yet.
/// Go `LoadOrInit`.
pub fn load_or_init(path: &Path) -> Result<Settings, Error> {
    match load(path) {
        Ok(s) => Ok(s),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            let s = default();
            save(path, &s)?;
            Ok(s)
        }
        Err(e) => Err(e),
    }
}

/// Writes settings atomically (temp file in the same dir + rename), with
/// owner-only permissions (on Unix). Go `Save`.
pub fn save(path: &Path, s: &Settings) -> Result<(), Error> {
    let dir = create_parent_dir(path)?;

    let data = serde_json::to_vec_pretty(s).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })?;

    let (mut tmp, tmp_name) = create_temp(&dir, ".settings-", ".json")?;

    if let Err(e) = io::Write::write_all(&mut tmp, &data) {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Io(e));
    }
    if let Err(e) = tmp.sync_all() {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Io(e));
    }
    drop(tmp); // close before rename (Windows requires the handle closed)

    if let Err(e) = set_owner_only(&tmp_name) {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Io(e));
    }

    if let Err(e) = fs::rename(&tmp_name, path) {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Io(e));
    }

    Ok(())
}

impl Update {
    /// Parses [`Update::interval`], falling back to [`DEFAULT_INTERVAL`] on an
    /// empty, invalid, or non-positive value. Go `IntervalDuration`.
    pub fn interval_duration(&self) -> Duration {
        match parse_go_duration(&self.interval) {
            Ok(d) if d > 0 => Duration::from_nanos(d as u64),
            _ => DEFAULT_INTERVAL,
        }
    }

    /// Reports whether at least [`Update::interval_duration`] has elapsed since the
    /// RFC 3339 timestamp `last`. An empty/invalid `last` is always due; a disabled
    /// policy is never due. Go `DueSince`.
    pub fn due_since(&self, last: &str, now: OffsetDateTime) -> bool {
        if !self.enabled {
            return false;
        }

        let t = match OffsetDateTime::parse(last, &Rfc3339) {
            Ok(t) => t,
            Err(_) => return true,
        };

        let elapsed = now - t; // time::Duration (signed)
        elapsed.whole_nanoseconds() >= self.interval_duration().as_nanos() as i128
    }
}

// --- advisory lock (Go lock.go) ---

/// Releases the advisory lock (removes the lockfile) when dropped — the RAII
/// equivalent of Go's returned `release func()`.
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(LOCK_SUFFIX);
    PathBuf::from(p)
}

/// Takes an advisory lock for the settings file at `path`, spinning until it wins,
/// a stale lock is reclaimed, or [`LOCK_ACQUIRE_MAX`] elapses. Go `acquireLock`.
fn acquire_lock(path: &Path) -> Result<LockGuard, Error> {
    let lp = lock_path(path);
    create_parent_dir(path)?;

    let start = Instant::now();

    loop {
        match OpenOptions::new().create_new(true).write(true).open(&lp) {
            Ok(_f) => return Ok(LockGuard { path: lp }),
            Err(_open_err) => {
                // Reclaim a lock abandoned by a crashed holder.
                if let Ok(meta) = fs::metadata(&lp) {
                    if let Ok(modified) = meta.modified() {
                        if modified.elapsed().unwrap_or_default() > LOCK_STALE {
                            let _ = fs::remove_file(&lp);
                            continue;
                        }
                    }
                }

                if start.elapsed() > LOCK_ACQUIRE_MAX {
                    return Err(Error::LockTimeout {
                        path: lp.display().to_string(),
                    });
                }

                std::thread::sleep(LOCK_SPIN);
            }
        }
    }
}

/// Runs `f` while holding the settings advisory lock. Use it for a read-only
/// critical section that must not overlap a [`mutate`]. Go `WithLock`.
pub fn with_lock<F: FnOnce()>(path: &Path, f: F) -> Result<(), Error> {
    let _guard = acquire_lock(path)?;
    f();
    Ok(())
}

/// Applies `f` to the settings at `path` under the advisory lock, so concurrent
/// read-modify-write cycles from multiple gitc processes cannot clobber one
/// another. Loads the current settings (starting from [`default`] when the file
/// does not exist yet), applies `f`, and atomically saves the result — all while
/// holding the lock. Go `Mutate`.
pub fn mutate<F: FnOnce(&mut Settings)>(path: &Path, f: F) -> Result<(), Error> {
    let _guard = acquire_lock(path)?;

    let mut s = match load(path) {
        Ok(s) => s,
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => default(),
        Err(e) => return Err(e),
    };

    f(&mut s);

    save(path, &s)
}

// --- filesystem helpers ---

/// Creates the parent directory of `path` (Go `os.MkdirAll(filepath.Dir(path),
/// 0o700)`) and returns it. Returns the parent path for temp-file placement.
fn create_parent_dir(path: &Path) -> Result<PathBuf, Error> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent)?;
    set_dir_owner_only(&parent);
    Ok(parent)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> io::Result<()> {
    // Go's os.Chmod(0o600) on Windows only clears the read-only bit (0o600 has the
    // write bit set), so it is effectively a no-op — faithfully skipped here.
    Ok(())
}

#[cfg(unix)]
fn set_dir_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_owner_only(_path: &Path) {}

/// Creates a uniquely-named temp file in `dir` (Go `os.CreateTemp(dir,
/// ".settings-*.json")`). Uniqueness is enforced by `create_new` retrying on
/// collision — std has no `mkstemp`, so a pid/nanos/counter name seeds the retry.
fn create_temp(dir: &Path, prefix: &str, suffix: &str) -> Result<(File, PathBuf), Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let pid = std::process::id();
    loop {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("{prefix}{pid}-{nanos}-{n}{suffix}");
        let p = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(f) => return Ok((f, p)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

// --- Go time.Duration string parse/format (faithful hand-port) ---

const NANO: u64 = 1;
const MICRO: u64 = 1_000;
const MILLI: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;
const MIN: u64 = 60 * SEC;
const HOUR: u64 = 60 * MIN;

fn unit_map(u: &[u8]) -> Option<u64> {
    match u {
        b"ns" => Some(NANO),
        b"us" => Some(MICRO),
        // "µs" (U+00B5, 0xC2 0xB5) and "μs" (U+03BC, 0xCE 0xBC)
        [0xC2, 0xB5, b's'] | [0xCE, 0xBC, b's'] => Some(MICRO),
        b"ms" => Some(MILLI),
        b"s" => Some(SEC),
        b"m" => Some(MIN),
        b"h" => Some(HOUR),
        _ => None,
    }
}

/// Port of Go `time.leadingInt`.
fn leading_int(s: &[u8]) -> Result<(u64, &[u8]), ()> {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > (1u64 << 63) / 10 {
            return Err(());
        }
        x = x * 10 + (c - b'0') as u64;
        if x > (1u64 << 63) {
            return Err(());
        }
        i += 1;
    }
    Ok((x, &s[i..]))
}

/// Port of Go `time.leadingFraction`.
fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if !overflow {
            if x > ((1u64 << 63) - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + (c - b'0') as u64;
                if y > (1u64 << 63) {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, &s[i..])
}

/// Faithful port of Go `time.ParseDuration` (the h/m/s/ms/µs/ns subset). Returns
/// signed nanoseconds like a Go `Duration`; `Err(())` mirrors Go's error.
fn parse_go_duration(orig: &str) -> Result<i64, ()> {
    let mut s: &[u8] = orig.as_bytes();
    let mut d: u64 = 0;
    let mut neg = false;

    // Consume [-+]?
    if let Some(&c) = s.first() {
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            s = &s[1..];
        }
    }

    // Special case: bare "0".
    if s == b"0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(());
    }

    while !s.is_empty() {
        // The next character must be [0-9.]
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(());
        }

        // Consume [0-9]*
        let pl = s.len();
        let (v0, rem) = leading_int(s)?;
        s = rem;
        let pre = pl != s.len();

        // Consume (\.[0-9]*)?
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if !s.is_empty() && s[0] == b'.' {
            s = &s[1..];
            let pl2 = s.len();
            let (fx, sc, rem2) = leading_fraction(s);
            f = fx;
            scale = sc;
            s = rem2;
            post = pl2 != s.len();
        }

        if !pre && !post {
            // no digits (e.g. ".s" or "-.s")
            return Err(());
        }

        // Consume unit.
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            if c == b'.' || c.is_ascii_digit() {
                break;
            }
            i += 1;
        }
        if i == 0 {
            return Err(()); // missing unit
        }
        let unit_bytes = &s[..i];
        s = &s[i..];
        let unit = match unit_map(unit_bytes) {
            Some(u) => u,
            None => return Err(()), // unknown unit
        };

        let mut v = v0;
        if v > (1u64 << 63) / unit {
            return Err(()); // overflow
        }
        v *= unit;
        if f > 0 {
            // float64 is needed to be nanosecond accurate for fractions of hours.
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > (1u64 << 63) {
                return Err(()); // overflow
            }
        }
        d = d.wrapping_add(v);
        if d > (1u64 << 63) {
            return Err(()); // overflow
        }
    }

    if neg {
        return Ok(-(d as i64));
    }
    if d > (1u64 << 63) - 1 {
        return Err(());
    }
    Ok(d as i64)
}

/// Port of Go `time.fmtInt`: right-to-left decimal into `buf` ending at `end`.
fn fmt_int(buf: &mut [u8], end: usize, v0: u128) -> usize {
    let mut w = end;
    let mut v = v0;
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = (v % 10) as u8 + b'0';
            v /= 10;
        }
    }
    w
}

/// Port of Go `time.fmtFrac`: prints the fractional part, trimming trailing zeros
/// (and the decimal point when nothing prints). Returns `(new_w, integer_part)`.
fn fmt_frac(buf: &mut [u8], end: usize, v0: u128, prec: usize) -> (usize, u128) {
    let mut w = end;
    let mut v = v0;
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = digit as u8 + b'0';
        }
        v /= 10;
    }
    if print {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

/// Faithful port of Go `time.Duration.String()` (the positive `std::time::Duration`
/// range). Yields e.g. `"336h0m0s"`, `"1h0m0s"`, `"1.5ms"`, `"0s"`.
fn format_go_duration(d: Duration) -> String {
    let mut u: u128 = d.as_nanos();
    let second: u128 = SEC as u128;

    let mut buf = [0u8; 32];
    let mut w = buf.len();

    if u < second {
        // Sub-second: use smaller units, like "1.2ms".
        w -= 1;
        buf[w] = b's';
        let prec: usize;
        if u == 0 {
            return "0s".to_string();
        } else if u < MICRO as u128 {
            prec = 0;
            w -= 1;
            buf[w] = b'n';
        } else if u < MILLI as u128 {
            prec = 3;
            // U+00B5 'µ' micro sign == 0xC2 0xB5
            w -= 1;
            buf[w] = 0xB5;
            w -= 1;
            buf[w] = 0xC2;
        } else {
            prec = 6;
            w -= 1;
            buf[w] = b'm';
        }
        let (nw, nu) = fmt_frac(&mut buf, w, u, prec);
        w = nw;
        u = nu;
        w = fmt_int(&mut buf, w, u);
    } else {
        w -= 1;
        buf[w] = b's';

        let (nw, nu) = fmt_frac(&mut buf, w, u, 9);
        w = nw;
        u = nu;

        // u is now integer seconds.
        w = fmt_int(&mut buf, w, u % 60);
        u /= 60;

        // u is now integer minutes.
        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = fmt_int(&mut buf, w, u % 60);
            u /= 60;

            // u is now integer hours. Stop at hours (days differ in length).
            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = fmt_int(&mut buf, w, u);
            }
        }
    }

    String::from_utf8_lossy(&buf[w..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Unique temp directory per test (std has no `t.TempDir()`).
    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gitc-settings-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // settings_test.go: TestDefault
    #[test]
    fn default_policy() {
        let d = default();
        assert_eq!(d.version, SCHEMA_VERSION, "version");
        assert!(
            d.update.enabled && d.update.channel == CHANNEL_PINNED,
            "default update policy = {:?}, want enabled pinned",
            d.update
        );
        assert_eq!(
            d.update.interval_duration(),
            DEFAULT_INTERVAL,
            "default interval"
        );
    }

    // settings_test.go: TestSaveLoadRoundTrip
    #[test]
    fn save_load_round_trip() {
        let path = temp_dir().join("sub").join("settings.json");

        let mut input = default();
        input.backend.active = "app/abc/v2.55.0.windows.2".to_string();
        input.backend.previous = "app/xyz/v2.54.0.windows.1".to_string();

        save(&path, &input).expect("Save");
        let got = load(&path).expect("Load");

        assert_eq!(
            (got.backend.active.as_str(), got.backend.previous.as_str()),
            (
                input.backend.active.as_str(),
                input.backend.previous.as_str()
            ),
            "round trip mismatch"
        );
    }

    // settings_test.go: TestLoadOrInitCreates
    #[test]
    fn load_or_init_creates() {
        let path = temp_dir().join("settings.json");

        let s = load_or_init(&path).expect("LoadOrInit");
        assert!(
            s.update.enabled,
            "initialized settings should have update enabled"
        );

        // The file must now exist and reload identically.
        load(&path).expect("settings file not created");
    }

    // settings_test.go: TestIntervalDurationFallback
    #[test]
    fn interval_duration_fallback() {
        let invalid = Update {
            interval: "nonsense".to_string(),
            ..Update::default()
        };
        assert_eq!(
            invalid.interval_duration(),
            DEFAULT_INTERVAL,
            "invalid interval should fall back to default"
        );

        let valid = Update {
            interval: "1h".to_string(),
            ..Update::default()
        };
        assert_eq!(
            valid.interval_duration(),
            Duration::from_secs(3600),
            "valid interval should parse"
        );
    }

    // settings_test.go: TestDueSince
    #[test]
    fn due_since() {
        let now = time::macros::datetime!(2026-07-09 12:00:00 UTC);
        let u = Update {
            enabled: true,
            interval: "336h".to_string(),
            ..Update::default()
        };

        assert!(u.due_since("", now), "empty last-check should be due");

        let recent = (now - time::Duration::hours(1)).format(&Rfc3339).unwrap();
        assert!(
            !u.due_since(&recent, now),
            "a check 1h ago should not be due within a 2-week interval"
        );

        let old = (now - time::Duration::days(15)).format(&Rfc3339).unwrap();
        assert!(u.due_since(&old, now), "a check 15 days ago should be due");

        let disabled = Update {
            enabled: false,
            interval: "336h".to_string(),
            ..Update::default()
        };
        assert!(
            !disabled.due_since("", now),
            "disabled updates are never due"
        );
    }

    // lock_test.go: TestMutateSerializesConcurrentWrites
    #[test]
    fn mutate_serializes_concurrent_writes() {
        let path = temp_dir().join("settings.json");
        const N: i64 = 50;

        let mut handles = Vec::new();
        for _ in 0..N {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                let _ = mutate(&p, |s| s.version += 1);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let s = load(&path).expect("Load");
        // The first Mutate starts from Default (version=1) and increments to 2;
        // each subsequent one adds 1. Under the advisory lock there are no lost
        // updates.
        assert_eq!(
            s.version,
            1 + N,
            "version after {N} concurrent Mutate (lost updates?)"
        );
    }

    // lock_test.go: TestAcquireLockExclusiveThenRelease
    #[test]
    fn acquire_lock_exclusive_then_release() {
        let path = temp_dir().join("settings.json");
        let lp = lock_path(&path);

        let guard = acquire_lock(&path).expect("acquire");
        assert!(lp.exists(), "lockfile should exist while held");

        drop(guard);
        assert!(!lp.exists(), "lockfile should be removed after release");

        let guard2 = acquire_lock(&path).expect("re-acquire after release should succeed");
        drop(guard2);
    }
}
