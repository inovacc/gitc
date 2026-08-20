//! Port of Go `internal/selfupdate` — check the gitc GitHub releases for a newer
//! version and replace the running binary in place.
//!
//! It downloads the release asset matching the current platform (the goreleaser
//! naming `gitc_<os>_<arch>[.exe]`) and swaps it over the current executable using
//! the rename-then-write trick, which works even on Windows where a running `.exe`
//! cannot be overwritten directly.
//!
//! # Security invariants (preserved bug-for-bug from the Go source)
//! * [`apply`] VERIFIES the sha256 checksum BEFORE swapping the binary and REFUSES
//!   to install when the release has no `checksums.txt` — a compromised or truncated
//!   asset must never become the user's git.
//! * [`get_body`] retries transient failures (network error + 5xx) up to
//!   [`MAX_ATTEMPTS`] with an `attempt * `[`RETRY_BACKOFF`] backoff, but treats 4xx
//!   as terminal (no retry).
//! * [`is_newer`] compares MAJOR.MINOR.PATCH numerically, ignoring any pre-release
//!   suffix, so a dev build of the same version is never offered a "downgrade".
//!
//! # HTTP injection (no real network in tests)
//! Go used the blocking `net/http` default client. Here the HTTP layer is an
//! injected [`HttpClient`] trait so tests supply a fake and NO real network is
//! touched. A production wiring provides a blocking client (recommend `ureq`); the
//! retry/backoff and status classification live in THIS module (a security
//! invariant the tests pin), so the injected client only performs a single GET.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::origin;

/// The goreleaser checksums manifest published alongside the release binaries;
/// [`apply`] verifies the downloaded binary against it.
const CHECKSUMS_NAME: &str = "checksums.txt";

/// Bounds the retry of transient network failures (Go `maxAttempts`).
pub const MAX_ATTEMPTS: u32 = 3;

/// Base backoff between retries; attempt `n` waits `n * RETRY_BACKOFF`
/// (Go `retryBackoff`).
pub const RETRY_BACKOFF: Duration = Duration::from_millis(300);

// ── HTTP seam ───────────────────────────────────────────────────────────────

/// A completed HTTP response (any status, `body` already read).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A transport/network error from a single GET (always treated as retryable, like
/// Go's `http.DefaultClient.Do` error path).
#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The injectable HTTP layer. A single GET; the retry/backoff + status
/// classification live in [`get_body`] (they are the pinned security policy).
///
/// * `Err(HttpError)` — a transport failure (network error / body read error):
///   retryable, mirroring Go's `getBodyOnce` returning `retryable=true` on a `Do`
///   or read error.
/// * `Ok(HttpResponse)` — a completed exchange; a non-200 status is classified by
///   [`get_body_once`] (5xx retryable, 4xx terminal).
pub trait HttpClient {
    fn get(&self, url: &str, accept: &str) -> Result<HttpResponse, HttpError>;
}

// ── public data ───────────────────────────────────────────────────────────────

/// A downloadable release binary for one platform (Go `Asset`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: i64,
    /// The release's `checksums.txt` asset URL, used by [`apply`] to verify the
    /// downloaded binary's sha256 before installing it.
    pub checksums_url: String,
}

/// The result of a version check (Go `Info`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Info {
    pub current: String,
    pub latest: String,
    pub has_update: bool,
    /// The asset for this platform; a default/zero [`Asset`] if none matched.
    pub asset: Asset,
}

/// The subset of the GitHub release payload consumed (Go `ghRelease`).
#[derive(Debug, Default, Deserialize)]
struct GhRelease {
    #[serde(rename = "tag_name", default)]
    tag_name: String,
    #[serde(default)]
    assets: Vec<GhReleaseAsset>,
}

#[derive(Debug, Default, Deserialize)]
struct GhReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(rename = "browser_download_url", default)]
    url: String,
    #[serde(default)]
    size: i64,
}

// ── errors ────────────────────────────────────────────────────────────────────

/// A self-update error. Go returns `error`; the message text mirrors the Go
/// sources so a user sees the same diagnostics.
#[derive(Debug)]
pub enum Error {
    /// From [`origin::api_base`] (pinned-URL integrity / not-pinned).
    Origin(origin::Error),
    /// No asset matched the running platform (`no release asset for <os>/<arch>`).
    NoAsset { os: String, arch: String },
    /// A terminal HTTP failure; `message` already carries Go's `http get: ...` or
    /// `unexpected status ...` text.
    Http(String),
    /// `query releases: <err>` — the release-metadata GET failed.
    QueryReleases(String),
    /// `decode release: <err>` — the release JSON did not parse.
    DecodeRelease(String),
    /// `size mismatch: got <got> bytes, release lists <want>`.
    SizeMismatch { got: i64, want: i64 },
    /// `cannot verify <name>: release has no checksums.txt`.
    NoChecksums { name: String },
    /// `fetch checksums: <err>`.
    FetchChecksums(String),
    /// `<name> not listed in checksums.txt`.
    NotListed { name: String },
    /// `sha256 mismatch for <name>: got <got>, want <want>`.
    ShaMismatch {
        name: String,
        got: String,
        want: String,
    },
    /// A file-op failure during the swap; `message` carries Go's contextual text
    /// (`create temp: ...`, `install new binary: ...`, ...).
    Swap(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Origin(e) => write!(f, "{e}"),
            Error::NoAsset { os, arch } => write!(f, "no release asset for {os}/{arch}"),
            Error::Http(m) => f.write_str(m),
            Error::QueryReleases(m) => write!(f, "query releases: {m}"),
            Error::DecodeRelease(m) => write!(f, "decode release: {m}"),
            Error::SizeMismatch { got, want } => {
                write!(f, "size mismatch: got {got} bytes, release lists {want}")
            }
            Error::NoChecksums { name } => {
                write!(f, "cannot verify {name}: release has no {CHECKSUMS_NAME}")
            }
            Error::FetchChecksums(m) => write!(f, "fetch checksums: {m}"),
            Error::NotListed { name } => write!(f, "{name} not listed in {CHECKSUMS_NAME}"),
            Error::ShaMismatch { name, got, want } => {
                write!(f, "sha256 mismatch for {name}: got {got}, want {want}")
            }
            Error::Swap(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Origin(e) => Some(e),
            _ => None,
        }
    }
}

impl From<origin::Error> for Error {
    fn from(e: origin::Error) -> Self {
        Error::Origin(e)
    }
}

// ── platform naming ───────────────────────────────────────────────────────────

/// The goreleaser asset name for `os`/`arch`: `gitc_<os>_<arch>` plus `.exe` on
/// Windows. `os`/`arch` are the goreleaser (Go `GOOS`/`GOARCH`) tokens.
pub fn asset_name(os: &str, arch: &str) -> String {
    let mut name = format!("gitc_{os}_{arch}");
    if os == "windows" {
        name.push_str(".exe");
    }
    name
}

/// Map Rust's `std::env::consts::OS` to the goreleaser (Go `GOOS`) token.
fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Map Rust's `std::env::consts::ARCH` to the goreleaser (Go `GOARCH`) token.
fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

/// The asset name for the running platform (Go `AssetName()`).
fn current_asset_name() -> String {
    asset_name(goos(), goarch())
}

// ── version check ─────────────────────────────────────────────────────────────

/// Query the latest release and report whether it is newer than `current`
/// (Go `Check`). The HTTP layer is injected via `http`.
///
/// Returns `Ok(Some(info))` on success. The `Option` is the requested surface
/// shape; the Go source always produces an `Info`, so `None` is never returned —
/// `info.has_update` distinguishes "up to date" from "update available".
///
/// Deviation from Go: on error Go returns a partial `Info` alongside the error;
/// a Rust `Result` carries only one, so the partial info is dropped (no consumer
/// relied on it).
pub fn check(current: &str, http: &dyn HttpClient) -> Result<Option<Info>, Error> {
    let rel = latest_release(http)?;

    let mut info = Info {
        current: current.to_string(),
        latest: rel.tag_name.clone(),
        has_update: false,
        asset: Asset::default(),
    };

    let want = current_asset_name();
    let mut checksums_url = String::new();

    for a in &rel.assets {
        if a.name == want {
            info.asset = Asset {
                name: a.name.clone(),
                url: a.url.clone(),
                size: a.size,
                checksums_url: String::new(),
            };
        } else if a.name == CHECKSUMS_NAME {
            checksums_url = a.url.clone();
        }
    }

    info.asset.checksums_url = checksums_url;
    info.has_update = current != "dev" && is_newer(&info.latest, current);

    Ok(Some(info))
}

/// Fetch + decode the latest release metadata (Go `latestRelease`). The endpoint
/// derives from the sha256-pinned gitc repository URL (`origin`), verified before
/// any request is made.
fn latest_release(http: &dyn HttpClient) -> Result<GhRelease, Error> {
    let base = origin::api_base(origin::GITC_REPO)?;
    let url = format!("{base}/releases/latest");

    let body = get_body(http, &url, "application/vnd.github+json")
        .map_err(|e| Error::QueryReleases(e.to_string()))?;

    serde_json::from_slice(&body).map_err(|e| Error::DecodeRelease(e.to_string()))
}

// ── apply / verify ────────────────────────────────────────────────────────────

/// Download `asset`, verify its sha256 (and size) against the release checksums
/// manifest, then replace the executable at `dest` with it (Go `Apply`).
///
/// A binary that cannot be verified is NEVER installed. The ordering — download,
/// verify, swap — is a security invariant: [`swap`] runs only after [`verify`]
/// succeeds.
pub fn apply(asset: &Asset, dest: &Path, http: &dyn HttpClient) -> Result<(), Error> {
    if asset.url.is_empty() {
        return Err(Error::NoAsset {
            os: goos().to_string(),
            arch: goarch().to_string(),
        });
    }

    let data = download(http, &asset.url)?;

    verify(http, asset, &data)?;

    swap(dest, &data)
}

/// Check the downloaded bytes against the expected size and the sha256 recorded in
/// the release `checksums.txt` (Go `verify`). Refuses (never installs) when the
/// manifest is missing or the digest does not match.
fn verify(http: &dyn HttpClient, asset: &Asset, data: &[u8]) -> Result<(), Error> {
    if asset.size > 0 && data.len() as i64 != asset.size {
        return Err(Error::SizeMismatch {
            got: data.len() as i64,
            want: asset.size,
        });
    }

    if asset.checksums_url.is_empty() {
        return Err(Error::NoChecksums {
            name: asset.name.clone(),
        });
    }

    let manifest = get_body(http, &asset.checksums_url, "")
        .map_err(|e| Error::FetchChecksums(e.to_string()))?;

    let want = expected_sha(&manifest, &asset.name).ok_or_else(|| Error::NotListed {
        name: asset.name.clone(),
    })?;

    let got = hex_encode(&Sha256::digest(data)[..]);

    // Go uses strings.EqualFold; for hex digests ASCII case-insensitivity matches.
    if !got.eq_ignore_ascii_case(&want) {
        return Err(Error::ShaMismatch {
            name: asset.name.clone(),
            got,
            want,
        });
    }

    Ok(())
}

/// Parse a goreleaser `checksums.txt` (`<hex>  <name>` per line) and return the
/// digest recorded for `name` (Go `expectedSHA` → `(string, bool)` → `Option`).
fn expected_sha(manifest: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(manifest);
    for line in text.split('\n') {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == name {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// Fetch `url` and return its bytes (Go `download`); no error wrapping.
fn download(http: &dyn HttpClient, url: &str) -> Result<Vec<u8>, Error> {
    get_body(http, url, "")
}

/// Perform a GET with a small retry/backoff on transient failures — network
/// errors and 5xx responses — so a single dropped connection during a release
/// query or download does not fail the whole operation. 4xx and read errors are
/// terminal (Go `getBody`).
///
/// Note: Go bounded the whole call with an `httpTimeout` context; here the
/// per-request timeout is a concern of the injected client. Cancellation via
/// `context.Context` is dropped per the pair pack (no `select`/deadline plumbing).
fn get_body(http: &dyn HttpClient, url: &str, accept: &str) -> Result<Vec<u8>, Error> {
    let mut last_err: Option<Error> = None;

    for attempt in 1..=MAX_ATTEMPTS {
        match get_body_once(http, url, accept) {
            Ok(body) => return Ok(body),
            Err((retryable, err)) => {
                if !retryable || attempt == MAX_ATTEMPTS {
                    return Err(err);
                }
                last_err = Some(err);
                std::thread::sleep(RETRY_BACKOFF * attempt);
            }
        }
    }

    // Unreachable: the loop always returns on the final attempt.
    Err(last_err.unwrap_or_else(|| Error::Http("http get: retries exhausted".to_string())))
}

/// A single GET. The bool reports whether a failure is worth retrying (network
/// error or 5xx); 4xx and read/build errors are terminal (Go `getBodyOnce`).
fn get_body_once(http: &dyn HttpClient, url: &str, accept: &str) -> Result<Vec<u8>, (bool, Error)> {
    match http.get(url, accept) {
        Err(e) => Err((true, Error::Http(format!("http get: {}", e.message)))),
        Ok(resp) => {
            if resp.status != 200 {
                let retryable = resp.status >= 500;
                Err((
                    retryable,
                    Error::Http(format!("unexpected status {}", resp.status)),
                ))
            } else {
                Ok(resp.body)
            }
        }
    }
}

// ── binary swap ───────────────────────────────────────────────────────────────

/// Replace `dest` with `data` via rename-then-write, so it works while `dest` is
/// the running executable — a running `.exe` can be renamed but not overwritten
/// (Go `swap`).
fn swap(dest: &Path, data: &[u8]) -> Result<(), Error> {
    // Go filepath.Dir: a bare filename yields ".".
    let dir = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let (mut tmp, tmp_name) =
        create_temp(&dir).map_err(|e| Error::Swap(format!("create temp: {e}")))?;

    if let Err(e) = tmp.write_all(data) {
        drop(tmp);
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Swap(format!("write temp: {e}")));
    }

    // Flush to disk then close (the fallible close analog of Go's tmp.Close()).
    if let Err(e) = tmp.sync_all() {
        drop(tmp);
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Swap(format!("close temp: {e}")));
    }
    drop(tmp);

    if let Err(e) = set_mode_0755(&tmp_name) {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Swap(format!("chmod temp: {e}")));
    }

    // old := dest + ".old" — APPEND the suffix (do not replace the extension).
    let mut old_os = dest.as_os_str().to_owned();
    old_os.push(".old");
    let old = PathBuf::from(old_os);
    let _ = fs::remove_file(&old);

    // Move the running binary aside so its path is free, then move the new one in.
    if let Err(e) = fs::rename(dest, &old) {
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Swap(format!("move current binary aside: {e}")));
    }

    if let Err(e) = fs::rename(&tmp_name, dest) {
        // Best-effort rollback so the tool is not left without a binary.
        let _ = fs::rename(&old, dest);
        let _ = fs::remove_file(&tmp_name);
        return Err(Error::Swap(format!("install new binary: {e}")));
    }

    // The old binary may still be running (Windows keeps it locked); best-effort.
    let _ = fs::remove_file(&old);

    Ok(())
}

/// Create a fresh temp file in `dir` with an `O_EXCL`-equivalent, mirroring Go's
/// `os.CreateTemp(dir, ".gitc-update-*")`.
fn create_temp(dir: &Path) -> std::io::Result<(fs::File, PathBuf)> {
    for _ in 0..10_000 {
        let path = dir.join(format!(".gitc-update-{}", unique_suffix()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A per-process-unique suffix for temp-file names (not security-sensitive; used
/// only for uniqueness under the `create_new` guard).
fn unique_suffix() -> u64 {
    let c = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ c.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ ((std::process::id() as u64) << 32)
}

#[cfg(unix)]
fn set_mode_0755(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

/// On Windows Go's `os.Chmod(name, 0o755)` only toggles the read-only bit, which
/// a fresh temp file never has — so this is a faithful no-op.
#[cfg(not(unix))]
fn set_mode_0755(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

// ── version comparison ────────────────────────────────────────────────────────

/// Report whether `latest` is a strictly higher release than `current`, comparing
/// MAJOR.MINOR.PATCH numerically. A pre-release suffix (e.g. `-dev`) is ignored, so
/// a dev build of the same version is never offered an "update" to an equal or
/// older tagged release (Go `isNewer`).
fn is_newer(latest: &str, current: &str) -> bool {
    let lt = parse_triple(latest);
    let ct = parse_triple(current);

    for i in 0..3 {
        if lt[i] != ct[i] {
            return lt[i] > ct[i];
        }
    }

    false
}

/// Extract `[major, minor, patch]` from a version string like `v0.3.0` or
/// `0.3.0-dev`; missing or non-numeric fields default to 0 (Go `parseTriple`).
///
/// Bug-for-bug: on the FIRST non-numeric field, Go returns the triple filled so
/// far and stops (later fields stay 0) — reproduced here.
fn parse_triple(v: &str) -> [i64; 3] {
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);

    // Drop any pre-release/build metadata after the numeric core.
    let v = match v.find(['-', '+']) {
        Some(i) => &v[..i],
        None => v,
    };

    let mut out = [0i64; 3];
    for (i, part) in v.splitn(3, '.').enumerate() {
        if i >= 3 {
            break;
        }
        match part.parse::<i64>() {
            Ok(n) => out[i] = n,
            Err(_) => return out,
        }
    }
    out
}

/// Lowercase-hex of `bytes` (Go `hex.EncodeToString`).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A closure-backed [`HttpClient`] so tests inject responses with NO real
    /// network. `Fn(url, accept) -> Result<HttpResponse, HttpError>`.
    struct FnClient<F>(F);

    impl<F> HttpClient for FnClient<F>
    where
        F: Fn(&str, &str) -> Result<HttpResponse, HttpError>,
    {
        fn get(&self, url: &str, accept: &str) -> Result<HttpResponse, HttpError> {
            (self.0)(url, accept)
        }
    }

    fn ok(body: &[u8]) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: body.to_vec(),
        })
    }

    fn status(code: u16) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: code,
            body: Vec::new(),
        })
    }

    fn temp_dir() -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("gitc-selfupdate-test-{}", unique_suffix()));
        fs::create_dir_all(&d).expect("create temp dir");
        d
    }

    // TestIsNewer — MAJOR.MINOR.PATCH numeric compare, pre-release ignored.
    #[test]
    fn is_newer_table() {
        let cases: [(&str, &str, bool); 6] = [
            ("v0.3.0", "0.2.0", true),
            ("v0.2.0", "0.3.0-dev", false), // older tag must not update a newer dev build
            ("v0.2.0", "0.2.0", false),     // equal
            ("v1.0.0", "0.9.9", true),
            ("v0.2.1", "v0.2.0", true),
            ("0.2.0", "0.2.0-rc1", false), // same triple: pre-release is not "newer"
        ];

        for (latest, current, want) in cases {
            assert_eq!(
                is_newer(latest, current),
                want,
                "is_newer({latest:?}, {current:?})"
            );
        }
    }

    // TestExpectedSHA — hit on a listed asset, miss on an unlisted one.
    #[test]
    fn expected_sha_lookup() {
        let manifest = b"abc123  gitc_linux_amd64\ndef456  gitc_windows_amd64.exe\n";

        assert_eq!(
            expected_sha(manifest, "gitc_windows_amd64.exe").as_deref(),
            Some("def456"),
            "expectedSHA hit"
        );

        assert!(
            expected_sha(manifest, "gitc_darwin_arm64").is_none(),
            "expectedSHA should miss on an unlisted asset"
        );
    }

    // TestGetBodyRetriesThenSucceeds — transient 5xx retried, succeeds on the
    // MAX_ATTEMPTS-th try; exactly MAX_ATTEMPTS attempts made.
    #[test]
    fn get_body_retries_then_succeeds() {
        let calls = AtomicUsize::new(0);
        let client = FnClient(|_url: &str, _accept: &str| {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            if (n as u32) < MAX_ATTEMPTS {
                status(503)
            } else {
                ok(b"ok")
            }
        });

        let body = get_body(&client, "http://example/x", "").expect("getBody after transient 5xx");
        assert_eq!(body, b"ok", "body");
        assert_eq!(
            calls.load(Ordering::SeqCst) as u32,
            MAX_ATTEMPTS,
            "expected MAX_ATTEMPTS attempts"
        );
    }

    // TestGetBodyTerminalOn4xx — a 4xx is terminal: error returned, exactly 1 call.
    #[test]
    fn get_body_terminal_on_4xx() {
        let calls = AtomicUsize::new(0);
        let client = FnClient(|_url: &str, _accept: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            status(404)
        });

        assert!(
            get_body(&client, "http://example/x", "").is_err(),
            "expected an error on 404"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "4xx must not retry: want exactly 1 call"
        );
    }

    // TestVerify — the five verify scenarios (Go t.Run subtests).
    #[test]
    fn verify_scenarios() {
        let data = b"fake gitc binary contents";
        let good = hex_encode(&Sha256::digest(data)[..]);

        // success: matching digest + size.
        {
            let manifest = format!("{good}  gitc_test\n");
            let client = FnClient(move |_u: &str, _a: &str| ok(manifest.as_bytes()));
            let a = Asset {
                name: "gitc_test".to_string(),
                url: String::new(),
                size: data.len() as i64,
                checksums_url: "http://checksums".to_string(),
            };
            verify(&client, &a, data).expect("verify valid asset");
        }

        // sha mismatch: digest differs -> reject.
        {
            let client = FnClient(|_u: &str, _a: &str| ok(b"deadbeef  gitc_test\n"));
            let a = Asset {
                name: "gitc_test".to_string(),
                url: String::new(),
                size: data.len() as i64,
                checksums_url: "http://checksums".to_string(),
            };
            assert!(
                verify(&client, &a, data).is_err(),
                "verify should reject a digest mismatch"
            );
        }

        // size mismatch: size check fails before any download.
        {
            let client = FnClient(|_u: &str, _a: &str| status(404));
            let a = Asset {
                name: "gitc_test".to_string(),
                url: String::new(),
                size: 999,
                checksums_url: "http://unused".to_string(),
            };
            assert!(
                verify(&client, &a, data).is_err(),
                "verify should reject a size mismatch"
            );
        }

        // no checksums manifest: fail closed.
        {
            let client = FnClient(|_u: &str, _a: &str| status(404));
            let a = Asset {
                name: "gitc_test".to_string(),
                url: String::new(),
                size: data.len() as i64,
                checksums_url: String::new(),
            };
            assert!(
                verify(&client, &a, data).is_err(),
                "verify should refuse when no checksums.txt is available"
            );
        }

        // asset not listed: fail closed.
        {
            let manifest = format!("{good}  some_other_file\n");
            let client = FnClient(move |_u: &str, _a: &str| ok(manifest.as_bytes()));
            let a = Asset {
                name: "gitc_test".to_string(),
                url: String::new(),
                size: data.len() as i64,
                checksums_url: "http://checksums".to_string(),
            };
            assert!(
                verify(&client, &a, data).is_err(),
                "verify should refuse when the asset is absent from checksums.txt"
            );
        }
    }

    // TestSwapReplacesBinary — the atomic swap replaces the target's bytes.
    #[test]
    fn swap_replaces_binary() {
        let dir = temp_dir();
        let dest = dir.join("gitc.exe");
        fs::write(&dest, b"OLD").expect("seed dest");

        swap(&dest, b"NEW").expect("swap");

        assert_eq!(
            fs::read(&dest).expect("read dest"),
            b"NEW",
            "dest after swap"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // TestApplyVerifiesBeforeSwap — a matching checksum installs the binary; a
    // mismatch fails and leaves dest intact (verify BEFORE swap).
    #[test]
    fn apply_verifies_before_swap() {
        let new_bin = b"the new gitc binary bytes".to_vec();
        let name = "gitc_test_amd64";
        let good_line = format!("{}  {}\n", hex_encode(&Sha256::digest(&new_bin)[..]), name);
        let bad_line =
            format!("deadbeef00000000000000000000000000000000000000000000000000000000  {name}\n");

        let dir = temp_dir();
        let dest = dir.join("gitc.exe");

        // Matching checksum -> the binary is installed.
        fs::write(&dest, b"OLD").expect("seed dest");
        {
            let bin = new_bin.clone();
            let good = good_line.clone();
            let client = FnClient(move |url: &str, _a: &str| {
                if url.ends_with("/bin") {
                    ok(&bin)
                } else if url.ends_with("/good") {
                    ok(good.as_bytes())
                } else {
                    status(404)
                }
            });
            let good_asset = Asset {
                name: name.to_string(),
                url: "http://srv/bin".to_string(),
                size: new_bin.len() as i64,
                checksums_url: "http://srv/good".to_string(),
            };
            apply(&good_asset, &dest, &client).expect("Apply with a valid checksum");
        }
        assert_eq!(
            fs::read(&dest).expect("read dest"),
            new_bin,
            "dest not updated to the verified binary"
        );

        // Mismatched checksum -> Apply fails and the swap never happens.
        fs::write(&dest, b"OLD").expect("reseed dest");
        {
            let bin = new_bin.clone();
            let bad = bad_line.clone();
            let client = FnClient(move |url: &str, _a: &str| {
                if url.ends_with("/bin") {
                    ok(&bin)
                } else if url.ends_with("/bad") {
                    ok(bad.as_bytes())
                } else {
                    status(404)
                }
            });
            let bad_asset = Asset {
                name: name.to_string(),
                url: "http://srv/bin".to_string(),
                size: new_bin.len() as i64,
                checksums_url: "http://srv/bad".to_string(),
            };
            assert!(
                apply(&bad_asset, &dest, &client).is_err(),
                "Apply must fail on a checksum mismatch"
            );
        }
        assert_eq!(
            fs::read(&dest).expect("read dest"),
            b"OLD",
            "dest was overwritten despite the checksum mismatch"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // TestApplyRefusesWithoutChecksums — fail closed when the release has no
    // checksums manifest; dest is left intact.
    #[test]
    fn apply_refuses_without_checksums() {
        let dir = temp_dir();
        let dest = dir.join("gitc.exe");
        fs::write(&dest, b"OLD").expect("seed dest");

        let client = FnClient(|_url: &str, _a: &str| ok(b"payload"));
        let a = Asset {
            name: "gitc_test".to_string(),
            url: "http://srv".to_string(),
            size: "payload".len() as i64,
            checksums_url: String::new(),
        };

        assert!(
            apply(&a, &dest, &client).is_err(),
            "Apply must refuse when there is no checksums manifest"
        );
        assert_eq!(
            fs::read(&dest).expect("read dest"),
            b"OLD",
            "dest overwritten without verification"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
