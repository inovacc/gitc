//! Port of Go `internal/provision` — owns the git-backend lifecycle: resolving the
//! managed git, auto-provisioning the pinned MinGit on a git-less machine,
//! downloading and verifying backend flavors (`git fetch-git`), activating an
//! install in `settings.json`, and garbage-collecting superseded installs. It also
//! resolves the env-overridable managed-git and audit-DB paths.
//!
//! # Faithfulness notes (preserved quirks / deviations)
//!
//! * **App-UUID naming** — each new managed-git install lives under a fresh
//!   time-ordered UUIDv7 directory (`app/<uuidv7>/<version>/`), so a download never
//!   touches the in-use install ([`new_install_base`]).
//! * **GC keep-set** — [`gc_installs`] reloads `settings.json` *under the advisory
//!   lock* and retains only the `active` + `previous` app installs; every other
//!   `app/<uuid>` dir is swept. Reloading under the lock is a TOCTOU guard so a
//!   concurrent activation cannot have its freshly-activated install swept.
//! * **Resolution/provision order** — [`resolve_or_provision`] resolves first;
//!   only a `NoBackend` error on a Windows machine (pinned available) and NOT a
//!   background child triggers self-provisioning, then a single retry.
//! * **HTTP injection** — Go used `net/http`; here the [`crate::selfupdate::HttpClient`]
//!   trait is injected so tests supply a fake and NO real network is touched. Go's
//!   `context.Context` is dropped per the pair pack.
//! * **`filepath.Rel` deviation** — [`install_rel`] uses `strip_prefix` (managed
//!   installs are always under `DataDir`), rather than a full `filepath.Rel` port.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::selfupdate::HttpClient;
use crate::{backend, gitwin, paths, settings, uuidv7};

/// The backend flavor used when `settings.json` records none — the full git build,
/// so every machine gets a bash-capable git out of the box (Go `defaultFlavor`).
const DEFAULT_FLAVOR: &str = "full";

/// An error from the provisioning flow (Go returned a generic `error`).
#[derive(Debug)]
pub enum Error {
    /// A backend resolution/exec error surfaced unchanged (Go returns `err`).
    Backend(backend::Error),
    /// A download/verify/extract failure from the gitwin layer.
    Gitwin(gitwin::Error),
    /// `generate install id: <err>` — a UUIDv7 could not be generated.
    InstallId(String),
    /// `no pinned git for <goos>/<goarch>` — no pinned asset for this platform.
    NoPinned {
        /// Go `runtime.GOOS`.
        goos: String,
        /// Go `runtime.GOARCH`.
        goarch: String,
    },
    /// `<source> (auto-provision failed: <detail>)` — the original `NoBackend`
    /// error wrapped with the provisioning failure (Go's `%w` wrap keeps the
    /// original error inspectable via [`std::error::Error::source`]).
    AutoProvision {
        /// The original backend error (typically `NoBackend`).
        source: backend::Error,
        /// The provisioning failure detail.
        detail: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Backend(e) => write!(f, "{e}"),
            Error::Gitwin(e) => write!(f, "{e}"),
            Error::InstallId(m) => write!(f, "generate install id: {m}"),
            Error::NoPinned { goos, goarch } => write!(f, "no pinned git for {goos}/{goarch}"),
            Error::AutoProvision { source, detail } => {
                write!(f, "{source} (auto-provision failed: {detail})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Backend(e) => Some(e),
            Error::Gitwin(e) => Some(e),
            Error::AutoProvision { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ── env-overridable paths ─────────────────────────────────────────────────────

/// Returns the managed git.exe path, honoring the `GITC_GIT_BACKEND` override, else
/// the active install recorded in `settings.json`. Go `ManagedGitPath` returned a
/// string with `""` for "none"; here `None` (an empty override is treated as
/// absent, matching Go's `v != ""`).
pub fn managed_git_path() -> Option<PathBuf> {
    if let Some(v) = env_nonempty("GITC_GIT_BACKEND") {
        return Some(v);
    }
    resolve_managed_git()
}

/// Returns the audit DB path, honoring the `GITC_AUDIT_DB` override. Go `AuditDBPath`.
pub fn audit_db_path() -> PathBuf {
    if let Some(v) = env_nonempty("GITC_AUDIT_DB") {
        return v;
    }
    paths::audit_db_path()
}

/// Returns the active managed git.exe recorded in `settings.json`. On first run (or
/// a stale pointer) it lazily adopts a legacy `git/<tag>` install by recording it in
/// settings in place. Returns `None` when no managed git is available. Go
/// `resolveManagedGit`.
fn resolve_managed_git() -> Option<PathBuf> {
    let sp = paths::settings_path();

    let s = match settings::load_or_init(&sp) {
        Ok(s) => s,
        // Settings unavailable: fall back to the legacy newest-on-disk scan.
        Err(_) => return paths::managed_git_path(),
    };

    if !s.backend.active.is_empty() {
        let git_exe = data_join_rel(&s.backend.active).join("cmd").join("git.exe");
        if git_exe.exists() {
            return Some(git_exe);
        }
    }

    // First run / stale pointer: adopt the legacy install if one exists.
    let legacy = paths::managed_git_path()?;

    if let Ok(rel) = install_rel(&legacy) {
        // Adopt the legacy install under the lock, but only if nothing else has set
        // an active backend in the meantime (best-effort; resolution already
        // succeeded regardless).
        let _ = settings::mutate(&sp, move |s| {
            if s.backend.active.is_empty() {
                s.backend.active = rel;
            }
        });
    }

    Some(legacy)
}

// ── install-path helpers ──────────────────────────────────────────────────────

/// Returns a git.exe's install root (its `<version>` dir) relative to `DataDir`,
/// slash-separated as stored in `settings.json`. Go `installRel`.
///
/// Deviation from Go `filepath.Rel`: uses `strip_prefix` (managed installs are
/// always under `DataDir`).
fn install_rel(git_exe: &Path) -> Result<String, ()> {
    // .../<version>/cmd/git.exe -> .../<version>
    let version_dir = git_exe.parent().and_then(|p| p.parent()).ok_or(())?;
    let rel = version_dir
        .strip_prefix(paths::data_dir())
        .map_err(|_| ())?;
    Ok(to_slash(rel))
}

/// Reserves a fresh UUIDv7-namespaced directory (`app/<uuid>`) for a new
/// managed-git install, so a download never touches the in-use install. Go
/// `newInstallBase`.
fn new_install_base() -> Result<PathBuf, Error> {
    let id = uuidv7::new().map_err(|e| Error::InstallId(e.to_string()))?;
    Ok(paths::app_dir().join(id))
}

/// Records `git_exe`'s install as the active backend in `settings.json` (demoting
/// the prior active to previous). Runs under the settings advisory lock so it never
/// clobbers a concurrent update. Go `activate`.
fn activate(git_exe: &Path) {
    let rel = match install_rel(git_exe) {
        Ok(r) => r,
        Err(_) => return,
    };

    let _ = settings::mutate(&paths::settings_path(), move |s| {
        if s.backend.active != rel {
            // previous <- old active; active <- rel.
            s.backend.previous = std::mem::replace(&mut s.backend.active, rel);
        }
    });
}

// ── resolve / provision ───────────────────────────────────────────────────────

/// Resolves the git backend, and on a git-less machine where the pinned MinGit is
/// available (Windows) it self-provisions on first run — downloading and
/// sha256-verifying the pinned git, activating it, then retrying. Other platforms
/// and background children surface `NoBackend` unchanged. Progress is written to
/// `w`. Go `ResolveOrProvision`.
pub fn resolve_or_provision(
    http: &dyn HttpClient,
    self_path: &Path,
    w: &mut dyn Write,
) -> Result<backend::Backend, Error> {
    let err = match backend::resolve(managed_git_path().as_deref(), self_path) {
        Ok(b) => return Ok(b),
        Err(e) => e,
    };

    if !matches!(err, backend::Error::NoBackend)
        || !pinned_available()
        || env_set("GITC_BACKGROUND")
    {
        return Err(Error::Backend(err));
    }

    let _ = writeln!(
        w,
        "gitc: no git backend found; provisioning pinned git {} (first run)...",
        gitwin::pinned().version
    );

    let git_exe = match install_pinned(http) {
        Ok(p) => p,
        Err(perr) => {
            return Err(Error::AutoProvision {
                source: err,
                detail: perr.to_string(),
            });
        }
    };

    activate(&git_exe);

    backend::resolve(managed_git_path().as_deref(), self_path).map_err(Error::Backend)
}

/// Maps a backend flavor to its in-code pinned manifest. An empty flavor uses
/// [`DEFAULT_FLAVOR`]. `"minimal"` (and any unknown) forces the shell-less MinGit.
/// Go `manifestForFlavor`.
fn manifest_for_flavor(flavor: &str) -> gitwin::Manifest {
    let flavor = if flavor.is_empty() {
        DEFAULT_FLAVOR
    } else {
        flavor
    };

    match flavor {
        "busybox" => gitwin::pinned_busybox(),
        "full" => gitwin::pinned_full(),
        _ => gitwin::pinned(),
    }
}

/// Picks the manifest to install for `flavor`, falling back when the chosen flavor
/// has no build for this platform — the full git has no 32-bit build, so
/// windows/386 falls back to busybox (still a shell) then to the minimal MinGit.
/// Go `resolveInstallManifest`.
fn resolve_install_manifest(flavor: &str) -> gitwin::Manifest {
    let m = manifest_for_flavor(flavor);
    if manifest_has_arch(&m) {
        return m;
    }

    let bb = gitwin::pinned_busybox();
    if manifest_has_arch(&bb) {
        return bb;
    }

    gitwin::pinned()
}

fn manifest_has_arch(m: &gitwin::Manifest) -> bool {
    m.for_(go_os(), go_arch()).is_some()
}

/// Returns the persisted backend flavor (`""` when unset = minimal). Go `currentFlavor`.
fn current_flavor() -> String {
    match settings::load(&paths::settings_path()) {
        Ok(s) => s.backend.flavor,
        Err(_) => String::new(),
    }
}

/// Records the chosen backend flavor in `settings.json` under the advisory lock.
/// Go `persistFlavor`.
fn persist_flavor(flavor: &str) {
    let f = flavor.to_string();
    let _ = settings::mutate(&paths::settings_path(), move |s| {
        s.backend.flavor = f;
    });
}

/// Reports whether the in-code pinned manifest has a git build for this platform
/// (git-for-windows MinGit is Windows-only). Go `pinnedAvailable`.
pub fn pinned_available() -> bool {
    gitwin::pinned().for_(go_os(), go_arch()).is_some()
}

/// Downloads and sha256-verifies the in-code pinned MinGit into a fresh
/// `app/<uuid>/` install and returns the git.exe path (not yet activated). Go
/// `installPinned`.
fn install_pinned(http: &dyn HttpClient) -> Result<PathBuf, Error> {
    let m = resolve_install_manifest(&current_flavor());

    let asset = m.for_(go_os(), go_arch()).ok_or_else(|| Error::NoPinned {
        goos: go_os().to_string(),
        goarch: go_arch().to_string(),
    })?;

    let base = new_install_base()?;

    m.ensure_pinned(http, &asset, &base).map_err(Error::Gitwin)
}

// ── fetch-git command ─────────────────────────────────────────────────────────

/// Downloads a git backend into a fresh `app/<uuid>/` install and activates it via
/// `settings.json`. By default uses the in-code hash-pinned manifest; `--latest`
/// queries the git-for-windows releases API (no pinned hash); `--list` shows recent
/// releases. Returns the process exit code. Go `FetchGit`.
pub fn fetch_git(http: &dyn HttpClient, args: &[String]) -> i32 {
    let mut list = false;
    let mut latest = false;
    let mut accept_unverified = false;
    let mut busybox = false;
    let mut full = false;
    let mut minimal = false;

    for a in args {
        match a.as_str() {
            "--list" => list = true,
            "--latest" => latest = true,
            "--i-accept-unverified" => accept_unverified = true,
            "--busybox" => busybox = true,
            "--full" => full = true,
            "--minimal" => minimal = true,
            other => {
                eprintln!("gitc gitc fetch-git: unknown flag {other:?}");
                return 2;
            }
        }
    }

    if list {
        return fetch_git_list(http);
    }
    if latest {
        return fetch_git_latest(http, accept_unverified);
    }
    if busybox {
        return fetch_git_flavor(http, "busybox");
    }
    if full {
        return fetch_git_flavor(http, "full");
    }
    if minimal {
        return fetch_git_flavor(http, "minimal");
    }
    fetch_git_flavor(http, &current_flavor())
}

/// Provisions the pinned backend for `flavor` and, on success, persists the flavor
/// so updates and auto-provision on this machine keep it. Go `fetchGitFlavor`.
fn fetch_git_flavor(http: &dyn HttpClient, flavor: &str) -> i32 {
    let code = fetch_git_pinned_manifest(http, resolve_install_manifest(flavor));
    if code == 0 {
        persist_flavor(flavor);
    }
    code
}

/// Prints the recent git-for-windows release tags. Go `fetchGitList`.
fn fetch_git_list(http: &dyn HttpClient) -> i32 {
    match gitwin::list(http, 10) {
        Ok(rels) => {
            for r in rels {
                println!("{}", r.tag);
            }
            0
        }
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            1
        }
    }
}

/// Downloads the newest git-for-windows release. It is UNPINNED (no sha256), so it
/// refuses unless the operator opted in with `--i-accept-unverified`. Go
/// `fetchGitLatest`.
fn fetch_git_latest(http: &dyn HttpClient, accept_unverified: bool) -> i32 {
    if !accept_unverified {
        eprintln!("gitc fetch-git --latest downloads an UNPINNED git with no sha256 verification.");
        eprintln!("Prefer `git fetch-git` (in-code hash-pinned + verified).");
        eprintln!(
            "To override and accept an unverified binary, re-run with --i-accept-unverified."
        );
        return 1;
    }

    let rel = match gitwin::latest(http) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            return 1;
        }
    };

    let base = match new_install_base() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            return 1;
        }
    };

    eprintln!(
        "warning: installing UNVERIFIED git-for-windows {} ({})",
        rel.tag,
        go_arch()
    );

    let git_exe = match gitwin::ensure(http, &rel, go_arch(), &base) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            return 1;
        }
    };

    activate(&git_exe);
    println!(
        "installed (UNVERIFIED, --i-accept-unverified) and activated: {}",
        git_exe.display()
    );
    0
}

/// Downloads an in-code hash-pinned manifest, verifies its sha256, installs it under
/// `app/<uuid>/`, and activates it. Go `fetchGitPinnedManifest`.
fn fetch_git_pinned_manifest(http: &dyn HttpClient, m: gitwin::Manifest) -> i32 {
    let asset = match m.for_(go_os(), go_arch()) {
        Some(a) => a,
        None => {
            eprintln!(
                "gitc gitc fetch-git: no pinned {} for {}/{}; try --latest",
                m.flavor,
                go_os(),
                go_arch()
            );
            return 1;
        }
    };

    println!(
        "fetching pinned {} {} ({})...",
        m.flavor, m.version, asset.name
    );

    let base = match new_install_base() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            return 1;
        }
    };

    let git_exe = match m.ensure_pinned(http, &asset, &base) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("gitc gitc fetch-git: {e}");
            return 1;
        }
    };

    activate(&git_exe);
    println!(
        "installed, sha256-verified and activated: {}",
        git_exe.display()
    );
    0
}

// ── background update ─────────────────────────────────────────────────────────

/// Installs and activates the in-code pinned git version when the active backend is
/// a different version. Only the verified pinned channel is auto-applied; the
/// unverified `latest` channel never is. Go `UpdateBackendIfStale`.
pub fn update_backend_if_stale(http: &dyn HttpClient, sp: &Path, s: &mut settings::Settings) {
    if s.update.channel != settings::CHANNEL_PINNED {
        return;
    }

    let pinned = gitwin::pinned();
    if base_name(&s.backend.active) == gitwin::version_dir(&pinned.version) && active_git_exists(s)
    {
        return; // already on the pinned version
    }

    let asset = match pinned.for_(go_os(), go_arch()) {
        Some(a) => a,
        None => return,
    };

    let base = match new_install_base() {
        Ok(b) => b,
        Err(_) => return,
    };

    let git_exe = match pinned.ensure_pinned(http, &asset, &base) {
        Ok(g) => g,
        Err(_) => return,
    };

    activate(&git_exe);

    if let Ok(reloaded) = settings::load(sp) {
        *s = reloaded;
    }
}

/// Reports whether the settings-active backend's git.exe is present. Go
/// `activeGitExists`.
fn active_git_exists(s: &settings::Settings) -> bool {
    if s.backend.active.is_empty() {
        return false;
    }

    let git_exe = data_join_rel(&s.backend.active).join("cmd").join("git.exe");
    git_exe.exists()
}

// ── garbage collection ────────────────────────────────────────────────────────

/// Returns the `app/<uuid>` directory names to retain: the active and previous
/// installs. Legacy (`git/<version>`) installs contribute no app uuid. Go
/// `activeKeepSet` (Go returned a `map[string]bool`; here a `HashSet`).
fn active_keep_set(s: &settings::Settings) -> HashSet<String> {
    let mut keep = HashSet::new();
    for rel in [&s.backend.active, &s.backend.previous] {
        let id = app_uuid(rel);
        if !id.is_empty() {
            keep.insert(id);
        }
    }
    keep
}

/// Removes superseded `app/<uuid>` installs, bounding disk usage to the active +
/// previous installs. Reloads settings and sweeps under the settings advisory lock,
/// so a backend activation cannot interleave and have its freshly-activated install
/// swept (TOCTOU). Go `GcInstalls`.
pub fn gc_installs() {
    let sp = paths::settings_path();
    let _ = settings::with_lock(&sp, || {
        let s = match settings::load(&sp) {
            Ok(s) => s,
            Err(_) => return,
        };
        gc_sweep(&active_keep_set(&s));
    });
}

/// Returns the `<uuid>` segment of an app-relative install path
/// (`app/<uuid>/<version>`), or `""` for a non-app (legacy) install. Go `appUUID`.
fn app_uuid(rel: &str) -> String {
    let slashed = to_slash_str(rel);
    let parts: Vec<&str> = slashed.split('/').collect();
    if parts.len() >= 2 && parts[0] == "app" {
        return parts[1].to_string();
    }
    String::new()
}

/// Removes `app/<uuid>` install dirs whose uuid is not in `keep`. Go `gcSweep`.
fn gc_sweep(keep: &HashSet<String>) {
    let app = paths::app_dir();
    let entries = match std::fs::read_dir(&app) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !is_dir || keep.contains(name_str.as_ref()) {
            continue;
        }
        let _ = std::fs::remove_dir_all(app.join(&name));
    }
}

// ── small helpers (Go stdlib equivalents) ─────────────────────────────────────

/// Go `runtime.GOOS` token for the current platform.
fn go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Go `runtime.GOARCH` token for the current platform.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

/// `os.Getenv(key) != ""` as a `PathBuf`.
fn env_nonempty(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `os.Getenv(key) != ""` as a bool.
fn env_set(key: &str) -> bool {
    std::env::var_os(key)
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// `filepath.Join(DataDir, FromSlash(rel))` — joins a slash-separated relative
/// install path onto `DataDir`, splitting to the OS separator.
fn data_join_rel(rel: &str) -> PathBuf {
    let mut p = paths::data_dir();
    for seg in to_slash_str(rel).split('/') {
        if seg.is_empty() {
            continue;
        }
        p.push(seg);
    }
    p
}

/// `filepath.ToSlash` over a `Path` (Windows `\\` -> `/`; no-op elsewhere).
fn to_slash(p: &Path) -> String {
    #[cfg(windows)]
    {
        p.to_string_lossy().replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        p.to_string_lossy().into_owned()
    }
}

/// `filepath.ToSlash` over a `&str`.
fn to_slash_str(p: &str) -> String {
    #[cfg(windows)]
    {
        p.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        p.to_string()
    }
}

/// `filepath.Base` over the stored (slash-separated) install pointer.
fn base_name(p: &str) -> String {
    let slashed = to_slash_str(p);
    let trimmed = slashed.trim_end_matches('/');
    if trimmed.is_empty() {
        return if slashed.is_empty() {
            ".".to_string()
        } else {
            "/".to_string()
        };
    }
    match trimmed.rfind('/') {
        Some(i) => trimmed[i + 1..].to_string(),
        None => trimmed.to_string(),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // These tests mutate process-global env (LOCALAPPDATA/XDG_DATA_HOME, read by
    // paths::app_dir) and the on-disk settings under those roots; serialize +
    // restore around them on the crate-shared lock (Go isolated via t.Setenv +
    // t.TempDir). installer/paths/backendupdate mutate the same vars.

    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl EnvGuard {
        fn set(pairs: &[(&'static str, &Path)]) -> Self {
            let saved = pairs
                .iter()
                .map(|(k, _)| (*k, std::env::var_os(k)))
                .collect();
            for (k, v) in pairs {
                std::env::set_var(k, v);
            }
            EnvGuard { saved }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "gitc-provision-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // TestPinnedAvailableMatchesPlatform — pinned MinGit is Windows-only.
    #[test]
    fn pinned_available_matches_platform() {
        assert_eq!(
            pinned_available(),
            cfg!(windows),
            "pinned_available() on this platform"
        );
    }

    // TestManifestForFlavor — flavor -> manifest.flavor mapping.
    #[test]
    fn manifest_for_flavor_cases() {
        let cases: [(&str, &str); 5] = [
            ("", "Git-full"), // default
            ("full", "Git-full"),
            ("busybox", "MinGit-busybox"),
            ("minimal", "MinGit"),
            ("unknown", "MinGit"),
        ];
        for (flavor, want) in cases {
            assert_eq!(
                manifest_for_flavor(flavor).flavor,
                want,
                "manifest_for_flavor({flavor:?}).flavor"
            );
        }
    }

    // TestAppUUID — the uuid is the second segment of an app path.
    #[test]
    fn app_uuid_cases() {
        assert_eq!(
            app_uuid("app/abc/v1"),
            "abc",
            "app install uuid should be the second path segment"
        );
        assert_eq!(app_uuid("git/v1"), "", "a legacy install has no app uuid");
        assert_eq!(app_uuid(""), "", "empty path has no uuid");
    }

    // TestActiveKeepSet — keep set is {active-uuid, previous-uuid}.
    #[test]
    fn active_keep_set_keeps_active_and_previous() {
        let mut s = settings::Settings::default();
        s.backend.active = "app/aaa/v1".to_string();
        s.backend.previous = "app/bbb/v0".to_string();

        let keep = active_keep_set(&s);
        assert!(
            keep.len() == 2 && keep.contains("aaa") && keep.contains("bbb"),
            "keep set = {keep:?}, want {{aaa, bbb}}"
        );
    }

    // TestGcInstalls — gc_sweep keeps the keep-set, removes the rest.
    #[test]
    fn gc_sweep_removes_superseded() {
        let _lock = crate::test_env::guard();
        let base = temp_dir();
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &base), ("XDG_DATA_HOME", &base)]);

        let app = paths::app_dir();
        for id in ["keep", "drop1", "drop2"] {
            std::fs::create_dir_all(app.join(id).join("v")).unwrap();
        }

        let mut keep = HashSet::new();
        keep.insert("keep".to_string());
        gc_sweep(&keep);

        assert!(
            app.join("keep").exists(),
            "kept install was removed: {:?}",
            app.join("keep")
        );
        for gone in ["drop1", "drop2"] {
            assert!(
                !app.join(gone).exists(),
                "install {gone:?} should have been GC'd"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    // TestGcInstallsReloadsActive — gc_installs re-reads the active pointer from
    // settings under the lock, so the active install is never swept.
    #[test]
    fn gc_installs_reloads_active() {
        let _lock = crate::test_env::guard();
        let base = temp_dir();
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &base), ("XDG_DATA_HOME", &base)]);

        // Persist the active-install pointer that gc_installs must re-read (Go used
        // the zero-value Settings, NOT settings::default()).
        let mut s = settings::Settings::default();
        s.backend.active = "app/keepid/v1".to_string();
        settings::save(&paths::settings_path(), &s).unwrap();

        let app = paths::app_dir();
        for id in ["keepid", "dropid"] {
            std::fs::create_dir_all(app.join(id).join("v1")).unwrap();
        }

        gc_installs();

        assert!(
            app.join("keepid").exists(),
            "active install was GC'd despite being in settings"
        );
        assert!(
            !app.join("dropid").exists(),
            "superseded install should have been swept"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
