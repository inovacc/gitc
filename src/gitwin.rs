//! Port of Go `internal/gitwin` — provision a git backend on Windows by
//! downloading a prebuilt MinGit (or full git-for-windows) distribution from the
//! `git-for-windows/git` GitHub releases and unpacking it, instead of building git
//! from source.
//!
//! This is the four Go source files (`gitwin.go`, `manifest.go`, `pinned.go`,
//! `tarbz2.go`) ported together into one module.
//!
//! # Security invariants (preserved bug-for-bug from the Go source)
//! * [`http_do`] retries transient failures (network error + 5xx) up to
//!   [`MAX_ATTEMPTS`] with an `attempt * `[`RETRY_BACKOFF`] backoff, but a 4xx (and
//!   any status `< 500`) is returned to the caller without retry — the caller vets
//!   the status.
//! * [`unzip`] and [`extract_tar_bz2`] guard every archive entry against path
//!   traversal ("zip-slip"): an entry whose cleaned target escapes the destination
//!   directory (`../`, absolute, drive) is REFUSED. The safe-join / lexical-clean
//!   logic is ported here (the crates only decode the container format).
//! * [`Manifest::ensure_pinned`] downloads, then VERIFIES the pinned sha256 BEFORE
//!   extracting, and never installs an unverified backend.
//!
//! # HTTP injection (no real network in tests)
//! Go used the blocking `net/http` default client. The HTTP layer is the injected
//! [`crate::selfupdate::HttpClient`] trait (reused verbatim — same signature), so
//! tests supply a fake and NO real network is touched. The retry/backoff + status
//! classification (a pinned security policy) live in THIS module ([`http_do`]);
//! the injected client only performs a single GET. A production wiring provides a
//! blocking client (recommend `ureq`), deferred to binary wiring.
//!
//! Deviation from Go: `context.Context` cancellation is dropped (per the pair
//! pack); the GitHub `User-Agent`/`GITHUB_TOKEN` request headers are a concern of
//! the production client (the trait carries only url + accept).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::origin;
use crate::selfupdate::{HttpClient, HttpResponse};

// ── retry policy ────────────────────────────────────────────────────────────

/// Bounds the retry of transient request failures (Go `maxAttempts`).
pub const MAX_ATTEMPTS: u32 = 3;

/// Base backoff between retries; attempt `n` waits `n * RETRY_BACKOFF`
/// (Go `retryBackoff`).
pub const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// GitHub requires this Accept header (Go sets it on every `httpDo` request).
const GITHUB_ACCEPT: &str = "application/vnd.github+json";

/// The git-for-windows release gitc pins by default (Go `pinnedVersion`).
const PINNED_VERSION: &str = "v2.55.0.windows.2";

// ── public data ─────────────────────────────────────────────────────────────

/// A downloadable release asset (Go `Asset`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Asset {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "browser_download_url", default)]
    pub url: String,
    #[serde(default)]
    pub size: i64,
}

/// A git-for-windows release (Go `Release`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Release {
    #[serde(rename = "tag_name", default)]
    pub tag: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

/// A pinned, hash-verified git distribution for one platform (Go `ManifestAsset`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ManifestAsset {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size: i64,
}

/// The pinned git-for-windows release: per-platform asset URLs + sha256 hashes for
/// a fixed version (Go `Manifest`). `assets` key = `"GOOS/GOARCH"`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub flavor: String,
    #[serde(default)]
    pub assets: HashMap<String, ManifestAsset>,
}

// ── errors ──────────────────────────────────────────────────────────────────

/// A gitwin error (Go returns `error`; the text mirrors the Go sources).
#[derive(Debug)]
pub enum Error {
    /// From [`origin::api_base`] (pinned-URL integrity / not-pinned).
    Origin(origin::Error),
    /// An I/O failure (file create/read/mkdir, download write).
    Io(std::io::Error),
    /// `request <url>: <detail>` — retries exhausted (network error / 5xx).
    Request { url: String, detail: String },
    /// `<op>: HTTP <code>` — a non-200 the caller refuses (e.g. `download: HTTP 404`).
    Status { op: String, code: u16 },
    /// `decode: <err>` — release/manifest JSON did not parse.
    Decode(String),
    /// `unsupported architecture <arch> for git-for-windows MinGit`.
    UnsupportedArch(String),
    /// `no MinGit .zip asset for <goarch> (<tag>) in the release`.
    NoAsset { goarch: String, tag: String },
    /// `unsafe path in <kind>: <name>` — a zip-slip / traversal entry (`kind` is
    /// `"zip"` or `"archive"`).
    UnsafePath { kind: &'static str, name: String },
    /// `open zip: <err>`.
    OpenZip(String),
    /// `read tar: <err>`.
    ReadTar(String),
    /// `sha256 mismatch: got <got>, want <want>`.
    Sha256Mismatch { got: String, want: String },
    /// `no sha256 pinned for asset`.
    NoSha256,
    /// `unpacked git but <path> is missing`.
    Missing { path: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Origin(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Request { url, detail } => write!(f, "request {url}: {detail}"),
            Error::Status { op, code } => write!(f, "{op}: HTTP {code}"),
            Error::Decode(m) => write!(f, "decode: {m}"),
            Error::UnsupportedArch(a) => {
                write!(
                    f,
                    "unsupported architecture {a:?} for git-for-windows MinGit"
                )
            }
            Error::NoAsset { goarch, tag } => {
                write!(
                    f,
                    "no MinGit .zip asset for {goarch} ({tag}) in the release"
                )
            }
            Error::UnsafePath { kind, name } => write!(f, "unsafe path in {kind}: {name:?}"),
            Error::OpenZip(m) => write!(f, "open zip: {m}"),
            Error::ReadTar(m) => write!(f, "read tar: {m}"),
            Error::Sha256Mismatch { got, want } => {
                write!(f, "sha256 mismatch: got {got}, want {want}")
            }
            Error::NoSha256 => f.write_str("no sha256 pinned for asset"),
            Error::Missing { path } => write!(f, "unpacked git but {path} is missing"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Origin(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<origin::Error> for Error {
    fn from(e: origin::Error) -> Self {
        Error::Origin(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ── HTTP ────────────────────────────────────────────────────────────────────

/// The git-for-windows/git releases endpoint, derived from the sha256-pinned
/// repository URL and verified before every use (Go `releasesBase`).
fn releases_base() -> Result<String, Error> {
    let base = origin::api_base(origin::GIT_FOR_WINDOWS_REPO)?;
    Ok(format!("{base}/releases"))
}

/// Perform a GET, retrying transient failures — a network error or a 5xx — up to
/// [`MAX_ATTEMPTS`] with an `attempt * `[`RETRY_BACKOFF`] backoff. Any completed
/// exchange with status `< 500` (success or a non-retryable 4xx) is returned as-is
/// for the caller to vet (Go `httpDo`).
fn http_do(http: &dyn HttpClient, url: &str) -> Result<HttpResponse, Error> {
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        match http.get(url, GITHUB_ACCEPT) {
            Ok(resp) => {
                if resp.status < 500 {
                    return Ok(resp); // success or a non-retryable 4xx
                }
                last_err = format!("HTTP {}", resp.status);
            }
            Err(e) => last_err = e.message.clone(),
        }

        if attempt == MAX_ATTEMPTS {
            break;
        }

        // Go bounded this sleep by ctx; cancellation is dropped per the pair pack.
        std::thread::sleep(RETRY_BACKOFF * attempt);
    }

    Err(Error::Request {
        url: url.to_string(),
        detail: last_err,
    })
}

/// Return the latest non-prerelease git-for-windows release (Go `Latest`).
pub fn latest(http: &dyn HttpClient) -> Result<Release, Error> {
    let base = releases_base()?;
    let resp = http_do(http, &format!("{base}/latest"))?;
    if resp.status != 200 {
        return Err(Error::Status {
            op: "query latest release".to_string(),
            code: resp.status,
        });
    }
    serde_json::from_slice(&resp.body).map_err(|e| Error::Decode(e.to_string()))
}

/// Return up to `n` recent releases, newest first (Go `List`); `n <= 0` defaults
/// to 10.
pub fn list(http: &dyn HttpClient, n: i64) -> Result<Vec<Release>, Error> {
    let n = if n <= 0 { 10 } else { n };
    let base = releases_base()?;
    let resp = http_do(http, &format!("{base}?per_page={n}"))?;
    if resp.status != 200 {
        return Err(Error::Status {
            op: "list releases".to_string(),
            code: resp.status,
        });
    }
    serde_json::from_slice(&resp.body).map_err(|e| Error::Decode(e.to_string()))
}

/// Stream the asset `url` to `dest_file` (Go `Download`).
pub fn download(http: &dyn HttpClient, url: &str, dest_file: &Path) -> Result<(), Error> {
    if let Some(parent) = dest_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let resp = http_do(http, url)?;
    if resp.status != 200 {
        return Err(Error::Status {
            op: "download".to_string(),
            code: resp.status,
        });
    }

    let mut f = fs::File::create(dest_file)?;
    f.write_all(&resp.body)?;
    Ok(())
}

// ── arch / asset selection ──────────────────────────────────────────────────

/// Map a Go `GOARCH` to the git-for-windows asset architecture token (Go `archTag`).
fn arch_tag(goarch: &str) -> Result<&'static str, Error> {
    match goarch {
        "amd64" => Ok("64-bit"),
        "386" => Ok("32-bit"),
        "arm64" => Ok("arm64"),
        _ => Err(Error::UnsupportedArch(goarch.to_string())),
    }
}

/// Pick the MinGit `.zip` asset matching `goarch`, preferring the standard build
/// over the busybox variant (Go `SelectMinGit`).
pub fn select_min_git(assets: &[Asset], goarch: &str) -> Result<Asset, Error> {
    let tag = arch_tag(goarch)?;
    let suffix = format!("-{}.zip", tag.to_lowercase());

    let mut busybox: Option<Asset> = None;

    for a in assets {
        let n = a.name.to_lowercase();
        if !n.starts_with("mingit-") || !n.ends_with(&suffix) {
            continue;
        }

        if n.contains("busybox") {
            busybox = Some(a.clone());
            continue;
        }

        return Ok(a.clone());
    }

    if let Some(b) = busybox {
        return Ok(b);
    }

    Err(Error::NoAsset {
        goarch: goarch.to_string(),
        tag: tag.to_string(),
    })
}

// ── zip / tar extraction ────────────────────────────────────────────────────

/// Extract the zip at `src` into `dest_dir`, guarding against path traversal
/// (Go `Unzip`).
pub fn unzip(src: &Path, dest_dir: &Path) -> Result<(), Error> {
    let file = fs::File::open(src)?;
    let mut zr = zip::ZipArchive::new(file).map_err(|e| Error::OpenZip(e.to_string()))?;

    let clean_dest = clean(&dest_dir.to_string_lossy());

    for i in 0..zr.len() {
        let mut zf = zr.by_index(i).map_err(|e| Error::OpenZip(e.to_string()))?;
        let name = zf.name().to_string();

        // Zip-slip guard: the target must stay within dest_dir.
        let target = join_guarded(&clean_dest, &name, "zip")?;

        if zf.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut out = fs::File::create(&target)?;
        std::io::copy(&mut zf, &mut out)?;
    }

    Ok(())
}

/// Extract a `.tar.bz2` archive into `dest_dir` using only format-decode crates
/// (bzip2 + tar) — no external tool and no executing a downloaded installer.
/// Entries are guarded against path traversal, and hard/symlinks are dereferenced
/// to real file copies (Windows can't reliably create links; git-for-windows
/// tarballs link e.g. `sh.exe` to `bash.exe`) (Go `ExtractTarBz2`).
pub fn extract_tar_bz2(src: &Path, dest_dir: &Path) -> Result<(), Error> {
    let f = fs::File::open(src)?;
    let dec = bzip2::read::BzDecoder::new(f);
    let mut archive = tar::Archive::new(dec);
    extract_tar(&mut archive, dest_dir)
}

/// Extract every entry of a tar stream into `dest_dir`, guarding against path
/// traversal and dereferencing links to real copies. Split from
/// [`extract_tar_bz2`] so the extraction + zip-slip logic is testable without a
/// bzip2 fixture (Go `extractTar`).
fn extract_tar<R: Read>(archive: &mut tar::Archive<R>, dest_dir: &Path) -> Result<(), Error> {
    let clean_dest = clean(&dest_dir.to_string_lossy());

    let entries = archive
        .entries()
        .map_err(|e| Error::ReadTar(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::ReadTar(e.to_string()))?;

        let name = entry
            .path()
            .map_err(|e| Error::ReadTar(e.to_string()))?
            .to_string_lossy()
            .into_owned();

        let target = safe_join(&clean_dest, &name)?;

        let et = entry.header().entry_type();
        let linkname = entry
            .link_name()
            .ok()
            .flatten()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        extract_entry(&mut entry, et, &linkname, &clean_dest, &target)?;
    }

    Ok(())
}

/// Write one tar entry, dereferencing links to real copies (Go `extractEntry`).
fn extract_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    et: tar::EntryType,
    linkname: &str,
    dest: &str,
    target: &Path,
) -> Result<(), Error> {
    if et.is_dir() {
        fs::create_dir_all(target)?;
        Ok(())
    } else if et.is_file() {
        write_regular(entry, target)
    } else if et.is_hard_link() || et.is_symlink() {
        // Dereference to a copy of the already-extracted referenced file.
        let link_src = safe_join(dest, linkname)?;
        // Best-effort: a missing link target is non-fatal (Go returns nil).
        let _ = copy_file(&link_src, target);
        Ok(())
    } else {
        // devices/fifos etc. — not present in the git tarball.
        Ok(())
    }
}

/// Stream a regular file entry to `target` (Go `writeRegular`).
fn write_regular<R: Read>(r: &mut R, target: &Path) -> Result<(), Error> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = fs::File::create(target)?;
    std::io::copy(r, &mut out)?;
    Ok(())
}

/// Copy `src` to `dst` (used to materialize links as real files) (Go `copyFile`).
fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut inp = fs::File::open(src)?;
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = fs::File::create(dst)?;
    std::io::copy(&mut inp, &mut out)?;
    Ok(())
}

// ── lexical path guard (ported filepath.Clean / safe-join) ──────────────────

/// Join `name` onto the already-clean `dest`, rejecting a path that would escape
/// `dest` (Go `safeJoin`; `kind` = `"archive"`).
fn safe_join(clean_dest: &str, name: &str) -> Result<PathBuf, Error> {
    join_guarded(clean_dest, name, "archive")
}

/// The shared zip-slip / traversal guard: `filepath.Join(clean_dest, name)` then
/// require the cleaned target to stay within `clean_dest`. `kind` names the
/// container (`"zip"` / `"archive"`) for the error message.
fn join_guarded(clean_dest: &str, name: &str, kind: &'static str) -> Result<PathBuf, Error> {
    let sep = std::path::MAIN_SEPARATOR;
    let target = clean(&format!("{clean_dest}{sep}{name}"));
    let prefix = format!("{clean_dest}{sep}");

    // Go: target != dest && !strings.HasPrefix(target, dest+sep).
    if target != clean_dest && !target.starts_with(&prefix) {
        return Err(Error::UnsafePath {
            kind,
            name: name.to_string(),
        });
    }

    Ok(PathBuf::from(target))
}

/// Whether `b` is a path separator for the current platform (Go `os.IsPathSeparator`).
#[inline]
fn is_sep(b: u8) -> bool {
    #[cfg(windows)]
    {
        b == b'/' || b == b'\\'
    }
    #[cfg(not(windows))]
    {
        b == b'/'
    }
}

/// Length of a leading volume name (Windows drive letter `C:`); 0 elsewhere
/// (a subset of Go's `filepath.VolumeName`, enough for real install paths).
fn volume_name_len(p: &[u8]) -> usize {
    #[cfg(windows)]
    {
        if p.len() >= 2 && p[1] == b':' && p[0].is_ascii_alphabetic() {
            return 2;
        }
        0
    }
    #[cfg(not(windows))]
    {
        let _ = p;
        0
    }
}

/// A faithful port of Go `path/filepath.Clean` (the lazybuf algorithm), operating
/// on the current platform's separator with a Windows drive-letter volume prefix.
/// This is what makes the traversal guard match Go exactly: `../` backtracks,
/// duplicate/leading separators collapse, and an absolute-looking entry is
/// contained rather than allowed to escape.
fn clean(path: &str) -> String {
    let bytes = path.as_bytes();
    let vol = volume_name_len(bytes);
    let vol_str = &path[..vol];
    let rest = &bytes[vol..];
    let sep = std::path::MAIN_SEPARATOR as u8;

    if rest.is_empty() {
        if vol > 0 {
            return format!("{vol_str}.");
        }
        return ".".to_string();
    }

    let rooted = is_sep(rest[0]);
    let n = rest.len();
    let mut out: Vec<u8> = Vec::with_capacity(n + 1);
    let mut r = 0usize;
    let mut dotdot = 0usize;

    if rooted {
        out.push(sep);
        r = 1;
        dotdot = 1;
    }

    while r < n {
        if is_sep(rest[r]) {
            // empty path element
            r += 1;
        } else if rest[r] == b'.' && (r + 1 == n || is_sep(rest[r + 1])) {
            // . element
            r += 1;
        } else if rest[r] == b'.' && rest[r + 1] == b'.' && (r + 2 == n || is_sep(rest[r + 2])) {
            // .. element: remove the last one written
            r += 2;
            if out.len() > dotdot {
                let mut w = out.len() - 1;
                while w > dotdot && !is_sep(out[w]) {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(sep);
                }
                out.push(b'.');
                out.push(b'.');
                dotdot = out.len();
            }
        } else {
            // real path element: add separator if needed
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(sep);
            }
            while r < n && !is_sep(rest[r]) {
                out.push(rest[r]);
                r += 1;
            }
        }
    }

    if out.is_empty() {
        out.push(b'.');
    }

    let mut s = String::from(vol_str);
    s.push_str(&String::from_utf8_lossy(&out));
    s
}

// ── provisioning (Ensure) ───────────────────────────────────────────────────

/// A best-effort remove-on-drop guard, mirroring Go's `defer os.Remove(tmp)`.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Download and unpack the MinGit build for `goarch` from `rel` into
/// `base_dir/<tag>/`, returning the path to the extracted git executable; if it
/// already exists there it is returned without re-downloading (Go `Ensure`).
pub fn ensure(
    http: &dyn HttpClient,
    rel: &Release,
    goarch: &str,
    base_dir: &Path,
) -> Result<PathBuf, Error> {
    let dest = base_dir.join(sanitize_tag(&rel.tag));

    let git_exe = dest.join("cmd").join("git.exe");
    if git_exe.exists() {
        return Ok(git_exe);
    }

    let asset = select_min_git(&rel.assets, goarch)?;

    let tmp = append_suffix(&dest, ".download.zip");
    download(http, &asset.url, &tmp)?;
    let _guard = RemoveOnDrop(tmp.clone());

    unzip(&tmp, &dest)?;

    if !git_exe.exists() {
        return Err(Error::Missing {
            path: git_exe.display().to_string(),
        });
    }

    Ok(git_exe)
}

/// Directory-name form of a release version/tag, matching the subdirectory
/// `ensure`/`ensure_pinned` unpack into (Go `VersionDir`).
pub fn version_dir(version: &str) -> String {
    sanitize_tag(version)
}

/// Make a release tag safe as a directory name (Go `sanitizeTag`). Trims, replaces
/// the reserved characters with `-`, and maps an empty result to `latest`.
fn sanitize_tag(tag: &str) -> String {
    let mut s = String::new();
    for c in tag.trim().chars() {
        match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => s.push('-'),
            _ => s.push(c),
        }
    }
    if s.is_empty() {
        return "latest".to_string();
    }
    s
}

/// Append a raw suffix to a path (Go's `dest + ".download"` string concat: the
/// temp file is a SIBLING of `dest`, not a child).
fn append_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut os = p.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

// ── manifest ────────────────────────────────────────────────────────────────

/// Decode `git_release.json` (Go `ParseManifest`).
pub fn parse_manifest(b: &[u8]) -> Result<Manifest, Error> {
    serde_json::from_slice(b).map_err(|e| Error::Decode(format!("parse git_release.json: {e}")))
}

impl Manifest {
    /// The pinned asset for the given `GOOS/GOARCH`, or `None` if absent
    /// (Go `Manifest.For` → `(ManifestAsset, bool)`).
    pub fn for_(&self, goos: &str, goarch: &str) -> Option<ManifestAsset> {
        self.assets.get(&format!("{goos}/{goarch}")).cloned()
    }

    /// Download the pinned asset into `base_dir/<version>/`, verify its sha256,
    /// unpack it, and return the git executable path; if it already exists there it
    /// is returned without re-downloading (Go `EnsurePinned`).
    ///
    /// The ordering — download, verify, extract — is a security invariant: an
    /// unverified backend is never installed.
    pub fn ensure_pinned(
        &self,
        http: &dyn HttpClient,
        a: &ManifestAsset,
        base_dir: &Path,
    ) -> Result<PathBuf, Error> {
        let dest = base_dir.join(sanitize_tag(&self.version));

        let git_exe = dest.join("cmd").join("git.exe");
        if git_exe.exists() {
            return Ok(git_exe);
        }

        let tmp = append_suffix(&dest, ".download");
        download(http, &a.url, &tmp)?;
        let _guard = RemoveOnDrop(tmp.clone());

        verify_sha256(&tmp, &a.sha256)?;

        extract_archive(&a.name, &tmp, &dest)?;

        if !git_exe.exists() {
            return Err(Error::Missing {
                path: git_exe.display().to_string(),
            });
        }

        prune_redundant(&dest);

        Ok(git_exe)
    }
}

/// Remove directories the git-for-windows tarball ships that gitc never uses
/// (top-level `bin/` launchers, empty `tmp/`, `dev/`). Best-effort: absent dirs
/// are ignored (Go `pruneRedundant`).
fn prune_redundant(dest: &Path) {
    for name in ["bin", "tmp", "dev"] {
        let _ = fs::remove_dir_all(dest.join(name));
    }
}

/// Unpack `src` into `dest_dir`, dispatching on the asset filename: a full-git
/// `.tar.bz2` tarball vs a MinGit `.zip` (Go `extractArchive`).
fn extract_archive(name: &str, src: &Path, dest_dir: &Path) -> Result<(), Error> {
    if name.to_lowercase().ends_with(".tar.bz2") {
        extract_tar_bz2(src, dest_dir)
    } else {
        unzip(src, dest_dir)
    }
}

/// Check that `file` hashes to the expected hex digest (Go `verifySHA256`). An
/// empty `want` is refused (never install an unpinned asset).
fn verify_sha256(file: &Path, want: &str) -> Result<(), Error> {
    if want.is_empty() {
        return Err(Error::NoSha256);
    }

    let mut f = fs::File::open(file)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let got = hex_lower(hasher.finalize().as_slice());
    // Go uses strings.EqualFold; for hex digests ASCII case-insensitivity matches.
    if !got.eq_ignore_ascii_case(want) {
        return Err(Error::Sha256Mismatch {
            got,
            want: want.to_string(),
        });
    }

    Ok(())
}

/// Lowercase-hex of `bytes` (Go `hex.EncodeToString`).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── pinned manifests ────────────────────────────────────────────────────────

/// The git-for-windows download URL prefix for the pinned version (Go `releaseBase`).
fn release_base() -> String {
    format!("https://github.com/git-for-windows/git/releases/download/{PINNED_VERSION}/")
}

/// The pinned release's page, recorded as a manifest `Source` (Go `tagURL`).
fn tag_url() -> String {
    format!("https://github.com/git-for-windows/git/releases/tag/{PINNED_VERSION}")
}

/// Build a `ManifestAsset` whose URL is `release_base()+name` (Go `winAsset`).
fn win_asset(name: &str, sha: &str, size: i64) -> ManifestAsset {
    ManifestAsset {
        name: name.to_string(),
        url: format!("{}{name}", release_base()),
        sha256: sha.to_string(),
        size,
    }
}

/// The compile-time-pinned MinGit manifest gitc installs by default (Go `Pinned`).
pub fn pinned() -> Manifest {
    let mut assets = HashMap::new();
    assets.insert(
        "windows/amd64".to_string(),
        win_asset(
            "MinGit-2.55.0.2-64-bit.zip",
            "e3ea2944cea4b3fabcd69c7c1669ef69b1b66c05ac7806d81224d0abad2dec31",
            38_839_825,
        ),
    );
    assets.insert(
        "windows/386".to_string(),
        win_asset(
            "MinGit-2.55.0.2-32-bit.zip",
            "04009f6150c1cec2d6779c51406c8c6a3f0133e57fa91c91eb8a030b93e68ccb",
            39_034_925,
        ),
    );
    assets.insert(
        "windows/arm64".to_string(),
        win_asset(
            "MinGit-2.55.0.2-arm64.zip",
            "0b2b81fdce284efd174cbb51b886ccea2fd271679c4b5c21f07d9e03bae51413",
            37_496_126,
        ),
    );
    Manifest {
        version: PINNED_VERSION.to_string(),
        source: tag_url(),
        flavor: "MinGit".to_string(),
        assets,
    }
}

/// The busybox MinGit variant — bundles a POSIX shell for hook execution; 64/32-bit
/// only, no arm64 build (Go `PinnedBusybox`).
pub fn pinned_busybox() -> Manifest {
    let mut assets = HashMap::new();
    assets.insert(
        "windows/amd64".to_string(),
        win_asset(
            "MinGit-2.55.0.2-busybox-64-bit.zip",
            "760e5a4d2ff5469adfc74f9f46901eee412de48dedaa6ef1785c0cf9a7f065fb",
            34_323_886,
        ),
    );
    assets.insert(
        "windows/386".to_string(),
        win_asset(
            "MinGit-2.55.0.2-busybox-32-bit.zip",
            "cc4ce341dae51eafb6c30e0701569338b7cb32c0621328fe43db2047e8a8d821",
            34_516_238,
        ),
    );
    Manifest {
        version: PINNED_VERSION.to_string(),
        source: tag_url(),
        flavor: "MinGit-busybox".to_string(),
        assets,
    }
}

/// The FULL git-for-windows build (a `.tar.bz2` with a complete MSYS2 env — real
/// bash AND sh); 64-bit and arm64 only, no 32-bit tarball (Go `PinnedFull`).
pub fn pinned_full() -> Manifest {
    let mut assets = HashMap::new();
    assets.insert(
        "windows/amd64".to_string(),
        win_asset(
            "Git-2.55.0.2-64-bit.tar.bz2",
            "5cfd35fadb11ac2f629c16f7be262f3f138cfe3f368331ad1e44f9abb5814882",
            116_921_702,
        ),
    );
    assets.insert(
        "windows/arm64".to_string(),
        win_asset(
            "Git-2.55.0.2-arm64.tar.bz2",
            "06c1c6c854628b9ac1081376bccc4a7b6ecd46ee14bb1bca10c57fa680234305",
            159_014_090,
        ),
    );
    Manifest {
        version: PINNED_VERSION.to_string(),
        source: tag_url(),
        flavor: "Git-full".to_string(),
        assets,
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfupdate::HttpError;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── HTTP fake (no real network) ─────────────────────────────────────────

    /// A closure-backed [`HttpClient`] so tests inject responses with NO real
    /// network (replaces Go's httptest servers).
    struct FnClient<F>(F);

    impl<F> HttpClient for FnClient<F>
    where
        F: Fn(&str, &str) -> Result<HttpResponse, HttpError>,
    {
        fn get(&self, url: &str, accept: &str) -> Result<HttpResponse, HttpError> {
            (self.0)(url, accept)
        }
    }

    fn ok_body(body: &[u8]) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: body.to_vec(),
        })
    }

    fn status_only(code: u16) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: code,
            body: Vec::new(),
        })
    }

    // ── temp-dir fixture (hand-rolled unique helper; no tempfile crate) ──────

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "gitc-gitwin-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&d).expect("create temp dir");
        d
    }

    // ── zip fixtures (use the zip crate to build, like Go's archive/zip) ─────

    fn zip_bytes(files: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            for (name, body) in files {
                zw.start_file(*name, opts).expect("start_file");
                zw.write_all(body.as_bytes()).expect("write zip entry");
            }
            zw.finish().expect("finish zip");
        }
        buf.into_inner()
    }

    fn write_zip(path: &Path, files: &[(&str, &str)]) {
        fs::write(path, zip_bytes(files)).expect("write zip file");
    }

    /// A zip shaped like a MinGit distribution: the `cmd/git.exe` gitc runs, a
    /// top-level `bin/` that `prune_redundant` removes, and a `usr/bin/sh.exe` it
    /// keeps (Go `buildMinGitZip`).
    fn build_min_git_zip() -> Vec<u8> {
        zip_bytes(&[
            ("cmd/git.exe", "GITBINARY"),
            ("bin/git.exe", "launcher-to-prune"),
            ("usr/bin/sh.exe", "sh"),
        ])
    }

    // ── tar fixtures (hand-rolled ustar writer for exact adversarial names) ──

    const TYPE_REG: u8 = b'0';
    const TYPE_LINK: u8 = b'1';

    struct TarEntry {
        name: &'static str,
        typeflag: u8,
        body: &'static str,
        linkname: &'static str,
    }

    fn put_str(buf: &mut [u8], s: &str) {
        let b = s.as_bytes();
        let n = b.len().min(buf.len());
        buf[..n].copy_from_slice(&b[..n]);
    }

    fn put_octal(buf: &mut [u8], val: u64) {
        let digits = buf.len() - 1;
        let s = format!("{val:0>digits$o}");
        let bytes = s.as_bytes();
        let start = bytes.len().saturating_sub(digits);
        buf[..digits].copy_from_slice(&bytes[start..]);
        buf[buf.len() - 1] = 0;
    }

    /// Build an in-memory ustar tar (the bzip2 layer is transparent, so testing the
    /// tar-extraction + zip-slip logic against a plain tar is equivalent to Go's
    /// `buildTar`). Hand-rolled so adversarial names (`../escape.txt`,
    /// `/etc/pwned`) survive verbatim.
    fn build_tar(entries: &[TarEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            let mut h = [0u8; 512];
            put_str(&mut h[0..100], e.name);
            put_octal(&mut h[100..108], 0o644); // mode
            put_octal(&mut h[108..116], 0); // uid
            put_octal(&mut h[116..124], 0); // gid
            let size = if e.typeflag == TYPE_REG {
                e.body.len() as u64
            } else {
                0
            };
            put_octal(&mut h[124..136], size);
            put_octal(&mut h[136..148], 0); // mtime
            for b in h[148..156].iter_mut() {
                *b = b' '; // checksum placeholder (spaces)
            }
            h[156] = e.typeflag;
            put_str(&mut h[157..257], e.linkname);
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");

            let sum: u32 = h.iter().map(|&b| b as u32).sum();
            let cksum = format!("{sum:06o}\0 ");
            h[148..156].copy_from_slice(&cksum.as_bytes()[..8]);

            out.extend_from_slice(&h);

            if e.typeflag == TYPE_REG {
                out.extend_from_slice(e.body.as_bytes());
                let pad = (512 - (e.body.len() % 512)) % 512;
                out.extend(std::iter::repeat(0u8).take(pad));
            }
        }
        // Two zero blocks terminate the archive.
        out.extend(std::iter::repeat(0u8).take(1024));
        out
    }

    // ── gitwin_test.go ──────────────────────────────────────────────────────

    // TestSelectMinGit — table: prefers non-busybox; unsupported arch errs.
    #[test]
    fn select_min_git_table() {
        let assets = vec![
            Asset {
                name: "Git-2.55.0.2-64-bit.exe".into(),
                ..Default::default()
            },
            Asset {
                name: "MinGit-2.55.0.2-64-bit.zip".into(),
                url: "u-amd64".into(),
                ..Default::default()
            },
            Asset {
                name: "MinGit-2.55.0.2-busybox-64-bit.zip".into(),
                url: "u-amd64-busybox".into(),
                ..Default::default()
            },
            Asset {
                name: "MinGit-2.55.0.2-32-bit.zip".into(),
                url: "u-386".into(),
                ..Default::default()
            },
            Asset {
                name: "MinGit-2.55.0.2-arm64.zip".into(),
                url: "u-arm64".into(),
                ..Default::default()
            },
            Asset {
                name: "PortableGit-2.55.0.2-64-bit.7z.exe".into(),
                ..Default::default()
            },
        ];

        let cases: [(&str, &str, bool); 4] = [
            ("amd64", "u-amd64", false), // prefers non-busybox
            ("386", "u-386", false),
            ("arm64", "u-arm64", false),
            ("mips", "", true), // unsupported arch
        ];

        for (arch, want_url, want_err) in cases {
            let got = select_min_git(&assets, arch);
            if want_err {
                assert!(got.is_err(), "expected error for {arch}");
                continue;
            }
            let got = got.unwrap_or_else(|e| panic!("unexpected error for {arch}: {e}"));
            assert_eq!(got.url, want_url, "URL for {arch}");
        }
    }

    // TestSelectMinGitBusyboxFallback — only busybox present → used as fallback.
    #[test]
    fn select_min_git_busybox_fallback() {
        let assets = vec![Asset {
            name: "MinGit-2.55.0.2-busybox-64-bit.zip".into(),
            url: "bb".into(),
            ..Default::default()
        }];

        let got = select_min_git(&assets, "amd64").expect("busybox fallback");
        assert_eq!(got.url, "bb", "busybox fallback URL");
    }

    // TestSanitizeTag — a clean tag passes through; empty → "latest".
    #[test]
    fn sanitize_tag_cases() {
        assert_eq!(sanitize_tag(PINNED_VERSION), PINNED_VERSION);
        assert_eq!(sanitize_tag(""), "latest", "empty tag");
    }

    // ── manifest_test.go ────────────────────────────────────────────────────

    // TestEnsurePinnedDownloadsVerifiesExtracts — download, verify, extract, prune;
    // second call short-circuits without downloading.
    #[test]
    fn ensure_pinned_downloads_verifies_extracts() {
        let zip = build_min_git_zip();
        let sum = hex_lower(Sha256::digest(&zip).as_slice());

        let m = {
            let mut assets = HashMap::new();
            assets.insert(
                "test/test".to_string(),
                ManifestAsset {
                    name: "MinGit.zip".into(),
                    url: "http://srv/MinGit.zip".into(),
                    sha256: sum,
                    size: zip.len() as i64,
                },
            );
            Manifest {
                version: "v9.9.9".into(),
                flavor: "MinGit".into(),
                assets,
                ..Default::default()
            }
        };

        let asset = m.for_("test", "test").expect("asset lookup");
        let base = temp_dir();

        let serve = {
            let zip = zip.clone();
            FnClient(move |_u: &str, _a: &str| ok_body(&zip))
        };

        let git_exe = m
            .ensure_pinned(&serve, &asset, &base)
            .expect("EnsurePinned");
        assert!(git_exe.exists(), "git.exe not extracted at {git_exe:?}");

        // <version>/cmd/git.exe -> <version>
        let root = git_exe.parent().unwrap().parent().unwrap().to_path_buf();
        assert!(
            !root.join("bin").exists(),
            "top-level bin/ should have been pruned"
        );
        assert!(
            root.join("usr").join("bin").join("sh.exe").exists(),
            "usr/bin/sh.exe should be kept"
        );

        // A second call short-circuits on the already-present git.exe. A client
        // that always errors proves no download happens (Go's srv.Close()).
        let closed = FnClient(|_u: &str, _a: &str| {
            Err(HttpError {
                message: "server closed".into(),
            })
        });
        m.ensure_pinned(&closed, &asset, &base)
            .expect("second EnsurePinned should short-circuit without downloading");

        let _ = fs::remove_dir_all(&base);
    }

    // TestEnsurePinnedRejectsShaMismatch — a sha256 mismatch must refuse.
    #[test]
    fn ensure_pinned_rejects_sha_mismatch() {
        let zip = build_min_git_zip();

        let m = {
            let mut assets = HashMap::new();
            assets.insert(
                "test/test".to_string(),
                ManifestAsset {
                    name: "MinGit.zip".into(),
                    url: "http://srv/MinGit.zip".into(),
                    sha256: "00deadbeef00".into(), // wrong
                    size: zip.len() as i64,
                },
            );
            Manifest {
                version: "v9.9.9".into(),
                assets,
                ..Default::default()
            }
        };

        let asset = m.for_("test", "test").expect("asset lookup");
        let base = temp_dir();
        let serve = FnClient(move |_u: &str, _a: &str| ok_body(&zip));

        assert!(
            m.ensure_pinned(&serve, &asset, &base).is_err(),
            "a sha256 mismatch must refuse (never install an unverified backend)"
        );

        let _ = fs::remove_dir_all(&base);
    }

    // ── net_test.go ─────────────────────────────────────────────────────────

    // TestHTTPDoRetriesThenSucceeds — transient 5xx retried, succeeds on the
    // MAX_ATTEMPTS-th try; exactly MAX_ATTEMPTS attempts made.
    #[test]
    fn http_do_retries_then_succeeds() {
        let calls = AtomicUsize::new(0);
        let client = FnClient(|_u: &str, _a: &str| {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            if (n as u32) < MAX_ATTEMPTS {
                status_only(502)
            } else {
                ok_body(b"ok")
            }
        });

        let resp = http_do(&client, "http://example/x").expect("httpDo after transient 5xx");
        assert_eq!(resp.status, 200, "final status");
        assert_eq!(
            calls.load(Ordering::SeqCst) as u32,
            MAX_ATTEMPTS,
            "expected MAX_ATTEMPTS attempts"
        );
    }

    // TestHTTPDoDoesNotRetry4xx — a 4xx returns the response (not an error), 1 call.
    #[test]
    fn http_do_does_not_retry_4xx() {
        let calls = AtomicUsize::new(0);
        let client = FnClient(|_u: &str, _a: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            status_only(404)
        });

        let resp = http_do(&client, "http://example/x")
            .expect("a 4xx should return the response, not an error");
        assert_eq!(resp.status, 404, "status");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "4xx must be handled in one call"
        );
    }

    // TestDownload — streams the body to a nested dest path (mkdir -p).
    #[test]
    fn download_writes_file() {
        let client = FnClient(|_u: &str, _a: &str| ok_body(b"zipbytes"));

        let dir = temp_dir();
        let dest = dir.join("sub").join("f.zip");
        download(&client, "http://srv/f.zip", &dest).expect("Download");

        assert_eq!(
            fs::read(&dest).expect("read dest"),
            b"zipbytes",
            "downloaded content"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── pinned_test.go ──────────────────────────────────────────────────────

    // TestArchTag — the three supported arches map; an unknown one errs.
    #[test]
    fn arch_tag_cases() {
        for (goarch, want) in [("amd64", "64-bit"), ("386", "32-bit"), ("arm64", "arm64")] {
            assert_eq!(arch_tag(goarch).unwrap(), want, "archTag({goarch})");
        }
        assert!(
            arch_tag("mips").is_err(),
            "archTag should reject an unknown architecture"
        );
    }

    // TestVersionDir — clean passes through; separators sanitized.
    #[test]
    fn version_dir_cases() {
        assert_eq!(
            version_dir(PINNED_VERSION),
            PINNED_VERSION,
            "a clean version passes through"
        );
        assert_eq!(
            version_dir("a/b:c"),
            "a-b-c",
            "VersionDir should sanitize separators"
        );
    }

    // TestPinnedManifestComplete — version set; every windows arch present + full.
    #[test]
    fn pinned_manifest_complete() {
        let m = pinned();
        assert!(!m.version.is_empty(), "pinned version is empty");
        for arch in ["amd64", "386", "arm64"] {
            let a = m
                .for_("windows", arch)
                .unwrap_or_else(|| panic!("pinned windows/{arch} missing"));
            assert!(
                !a.sha256.is_empty() && !a.url.is_empty() && !a.name.is_empty(),
                "pinned windows/{arch} incomplete: {a:?}"
            );
        }
    }

    // TestPinnedBusyboxComplete — 64/32-bit present, no arm64.
    #[test]
    fn pinned_busybox_complete() {
        let m = pinned_busybox();
        assert_eq!(m.version, PINNED_VERSION, "busybox version");
        assert_eq!(m.flavor, "MinGit-busybox", "busybox flavor");
        for arch in ["amd64", "386"] {
            let a = m
                .for_("windows", arch)
                .unwrap_or_else(|| panic!("busybox windows/{arch} missing"));
            assert!(
                !a.sha256.is_empty() && !a.url.is_empty(),
                "busybox windows/{arch} incomplete"
            );
        }
        assert!(
            m.for_("windows", "arm64").is_none(),
            "there is no arm64 busybox build"
        );
    }

    // TestPinnedFullComplete — 64-bit + arm64 present as .tar.bz2, no 32-bit.
    #[test]
    fn pinned_full_complete() {
        let m = pinned_full();
        assert_eq!(m.version, PINNED_VERSION, "full version");
        assert_eq!(m.flavor, "Git-full", "full flavor");
        for arch in ["amd64", "arm64"] {
            let a = m
                .for_("windows", arch)
                .unwrap_or_else(|| panic!("full windows/{arch} missing"));
            assert!(
                !a.sha256.is_empty() && a.name.ends_with(".tar.bz2"),
                "full windows/{arch} incomplete: {a:?}"
            );
        }
        assert!(
            m.for_("windows", "386").is_none(),
            "there is no 32-bit full tarball"
        );
    }

    // TestParseManifestAndFor — decode + platform lookup hit/miss.
    #[test]
    fn parse_manifest_and_for() {
        let js = br#"{"version":"v1","assets":{"windows/amd64":{"name":"g.zip","url":"http://x","sha256":"abc","size":1}}}"#;

        let m = parse_manifest(js).expect("ParseManifest");
        let a = m.for_("windows", "amd64").expect("For(windows/amd64)");
        assert_eq!(a.name, "g.zip", "For(windows/amd64) name");
        assert!(
            m.for_("linux", "amd64").is_none(),
            "For should miss on an absent platform"
        );
    }

    // TestVerifySHA256 — a valid digest passes; a wrong one is rejected.
    #[test]
    fn verify_sha256_cases() {
        let dir = temp_dir();
        let f = dir.join("blob");
        let data = b"hello gitc";
        fs::write(&f, data).expect("write blob");

        let sum = hex_lower(Sha256::digest(data).as_slice());
        verify_sha256(&f, &sum).expect("verifySHA256 on a valid digest");
        assert!(
            verify_sha256(&f, "deadbeef").is_err(),
            "verifySHA256 must reject a wrong digest"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // TestUnzipHappyAndZipSlip — a good zip extracts; a zip-slip path is rejected.
    #[test]
    fn unzip_happy_and_zip_slip() {
        let dir = temp_dir();

        let good = dir.join("good.zip");
        write_zip(&good, &[("cmd/git.exe", "binary"), ("README", "hi")]);

        let dest = dir.join("out");
        unzip(&good, &dest).expect("Unzip good");
        assert!(
            dest.join("cmd").join("git.exe").exists(),
            "expected extracted file"
        );

        let evil = dir.join("evil.zip");
        write_zip(&evil, &[("../escape.txt", "pwned")]);
        assert!(
            unzip(&evil, &dir.join("out2")).is_err(),
            "Unzip must reject a zip-slip path"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── prune_test.go ───────────────────────────────────────────────────────

    // TestPruneRedundant — the used dirs stay; bin/tmp/dev are removed.
    #[test]
    fn prune_redundant_removes_only_redundant() {
        let dest = temp_dir();

        let keep = ["cmd/git.exe", "usr/bin/sh.exe", "mingw64/bin/git.exe"];
        let drop = ["bin/git.exe", "tmp/placeholder", "dev/null"];

        for rel in keep.iter().chain(drop.iter()) {
            let p = dest.join(rel);
            fs::create_dir_all(p.parent().unwrap()).expect("mkdir");
            fs::write(&p, b"x").expect("write");
        }

        prune_redundant(&dest);

        for rel in keep {
            assert!(dest.join(rel).exists(), "{rel} must be kept");
        }
        for d in ["bin", "tmp", "dev"] {
            assert!(!dest.join(d).exists(), "{d}/ should have been pruned");
        }

        let _ = fs::remove_dir_all(&dest);
    }

    // TestPruneRedundantIgnoresAbsentDirs — no bin/tmp/dev → no-op, no panic.
    #[test]
    fn prune_redundant_ignores_absent_dirs() {
        let dest = temp_dir();
        prune_redundant(&dest); // must be a no-op
        let _ = fs::remove_dir_all(&dest);
    }

    // ── tarbz2_test.go ──────────────────────────────────────────────────────

    fn extract_tar_bytes(bytes: &[u8], dest: &Path) -> Result<(), Error> {
        let mut ar = tar::Archive::new(bytes);
        extract_tar(&mut ar, dest)
    }

    // TestExtractTarNormalFile — a regular file extracts to its path.
    #[test]
    fn extract_tar_normal_file() {
        let dest = temp_dir();
        let bytes = build_tar(&[TarEntry {
            name: "cmd/git.exe",
            typeflag: TYPE_REG,
            body: "binary",
            linkname: "",
        }]);
        extract_tar_bytes(&bytes, &dest).expect("extractTar");

        let got = fs::read(dest.join("cmd").join("git.exe")).expect("read");
        assert_eq!(got, b"binary", "extracted file");

        let _ = fs::remove_dir_all(&dest);
    }

    // TestExtractTarRejectsTraversal — a ../ entry is rejected; nothing escapes.
    #[test]
    fn extract_tar_rejects_traversal() {
        let dest = temp_dir();
        let bytes = build_tar(&[TarEntry {
            name: "../escape.txt",
            typeflag: TYPE_REG,
            body: "pwned",
            linkname: "",
        }]);
        assert!(
            extract_tar_bytes(&bytes, &dest).is_err(),
            "a ../ traversal entry must be rejected"
        );

        let outside = dest.parent().unwrap().join("escape.txt");
        assert!(
            !outside.exists(),
            "traversal wrote a file outside the destination"
        );

        let _ = fs::remove_dir_all(&dest);
    }

    // TestExtractTarRejectsAbsolute — an absolute-looking entry must not escape.
    #[test]
    fn extract_tar_rejects_absolute() {
        let dest = temp_dir();
        let bytes = build_tar(&[TarEntry {
            name: "/etc/pwned",
            typeflag: TYPE_REG,
            body: "x",
            linkname: "",
        }]);
        // Go: on error, assert nothing escaped; on success the entry was contained.
        if extract_tar_bytes(&bytes, &dest).is_err() {
            assert!(
                !Path::new("/etc/pwned").exists(),
                "absolute path escaped the destination"
            );
        }

        let _ = fs::remove_dir_all(&dest);
    }

    // TestExtractTarDerefsHardlink — a hard link is materialized as a real copy.
    #[test]
    fn extract_tar_derefs_hardlink() {
        let dest = temp_dir();
        let bytes = build_tar(&[
            TarEntry {
                name: "usr/bin/bash.exe",
                typeflag: TYPE_REG,
                body: "shell",
                linkname: "",
            },
            TarEntry {
                name: "usr/bin/sh.exe",
                typeflag: TYPE_LINK,
                body: "",
                linkname: "usr/bin/bash.exe",
            },
        ]);
        extract_tar_bytes(&bytes, &dest).expect("extractTar");

        let got = fs::read(dest.join("usr").join("bin").join("sh.exe")).expect("read link");
        assert_eq!(
            got, b"shell",
            "dereferenced link should be a copy of bash.exe"
        );

        let _ = fs::remove_dir_all(&dest);
    }

    // TestSafeJoin — a normal path is accepted; escaping paths are rejected.
    #[test]
    fn safe_join_guard() {
        let raw = temp_dir();
        let dest = clean(&raw.to_string_lossy());

        assert!(
            safe_join(&dest, "cmd/git.exe").is_ok(),
            "a normal path must be accepted"
        );

        // "../escape", "../../x", and filepath.Join("a","..","..","b") == "../b".
        for bad in ["../escape", "../../x", "../b"] {
            assert!(
                safe_join(&dest, bad).is_err(),
                "safeJoin must reject escaping path {bad:?}"
            );
        }

        let _ = fs::remove_dir_all(&raw);
    }
}
