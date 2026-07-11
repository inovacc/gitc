// Package provision owns the git-backend lifecycle: resolving the managed git,
// auto-provisioning the pinned MinGit on a git-less machine, downloading and
// verifying backend flavors (`git fetch-git`), activating an install in
// settings.json, and garbage-collecting superseded installs. It also resolves
// the env-overridable managed-git and audit-DB paths. Keeping this out of
// package main leaves the command layer as thin dispatch.
package provision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/gitwin"
	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/settings"
	"github.com/inovacc/gitc/internal/uuidv7"
)

// defaultFlavor is the backend flavor used when settings.json records none — the
// full git build, so every machine gets a bash-capable git (working `#!/bin/sh`
// and `#!/bin/bash` hooks) out of the box with no per-machine step.
const defaultFlavor = "full"

// ManagedGitPath returns the managed git.exe path, honoring the GITC_GIT_BACKEND
// override, else the active install recorded in settings.json.
func ManagedGitPath() string {
	if v := os.Getenv("GITC_GIT_BACKEND"); v != "" {
		return v
	}

	return resolveManagedGit()
}

// AuditDBPath returns the audit DB path, honoring the GITC_AUDIT_DB override.
func AuditDBPath() string {
	if v := os.Getenv("GITC_AUDIT_DB"); v != "" {
		return v
	}

	return paths.AuditDBPath()
}

// resolveManagedGit returns the active managed git.exe recorded in settings.json.
// On first run (or when settings has no active backend) it lazily adopts a legacy
// git\<tag> install by recording it in settings in place — no bulk move of a
// possibly in-use install. Returns "" when no managed git is available.
func resolveManagedGit() string {
	sp := paths.SettingsPath()

	s, err := settings.LoadOrInit(sp)
	if err != nil {
		// Settings unavailable: fall back to the legacy newest-on-disk scan so
		// git still resolves.
		return paths.ManagedGitPath()
	}

	if s.Backend.Active != "" {
		gitExe := filepath.Join(paths.DataDir(), filepath.FromSlash(s.Backend.Active), "cmd", "git.exe")
		if _, statErr := os.Stat(gitExe); statErr == nil {
			return gitExe
		}
	}

	// First run / stale pointer: adopt the legacy install if one exists.
	legacy := paths.ManagedGitPath()
	if legacy == "" {
		return ""
	}

	if rel, relErr := installRel(legacy); relErr == nil {
		// Adopt the legacy install under the lock, but only if nothing else has
		// set an active backend in the meantime (best-effort; resolution already
		// succeeded regardless).
		_ = settings.Mutate(sp, func(s *settings.Settings) {
			if s.Backend.Active == "" {
				s.Backend.Active = rel
			}
		})
	}

	return legacy
}

// installRel returns a git.exe's install root (its <version> dir) relative to
// DataDir, slash-separated as stored in settings.json.
func installRel(gitExe string) (string, error) {
	versionDir := filepath.Dir(filepath.Dir(gitExe)) // .../<version>/cmd/git.exe -> .../<version>

	rel, err := filepath.Rel(paths.DataDir(), versionDir)
	if err != nil {
		return "", err
	}

	return filepath.ToSlash(rel), nil
}

// newInstallBase reserves a fresh UUIDv7-namespaced directory (app/<uuid>) for a
// new managed-git install, so a download never touches the in-use install.
func newInstallBase() (string, error) {
	id, err := uuidv7.New()
	if err != nil {
		return "", fmt.Errorf("generate install id: %w", err)
	}

	return filepath.Join(paths.AppDir(), id), nil
}

// activate records gitExe's install as the active backend in settings.json
// (demoting the prior active to previous), so the next invocation resolves the
// new install. The read-modify-write runs under settings.Mutate's advisory lock
// so it never clobbers a concurrent update (e.g. a background check stamp).
func activate(gitExe string) {
	rel, err := installRel(gitExe)
	if err != nil {
		return
	}

	_ = settings.Mutate(paths.SettingsPath(), func(s *settings.Settings) {
		if s.Backend.Active != rel {
			s.Backend.Previous = s.Backend.Active
			s.Backend.Active = rel
		}
	})
}

// ResolveOrProvision resolves the git backend, and on a git-less machine where
// the pinned MinGit is available (Windows) it self-provisions on first run —
// downloading and sha256-verifying the pinned git, activating it, then retrying.
// Other platforms and background children surface ErrNoBackend unchanged (they
// rely on a system git or an explicit `git fetch-git`). Progress is written to w.
func ResolveOrProvision(ctx context.Context, self string, w io.Writer) (backend.Backend, error) {
	b, err := backend.Resolve(ManagedGitPath(), self)
	if err == nil {
		return b, nil
	}

	if !errors.Is(err, backend.ErrNoBackend) || !pinnedAvailable() || os.Getenv("GITC_BACKGROUND") != "" {
		return b, err
	}

	fmt.Fprintf(w, "gitc: no git backend found; provisioning pinned git %s (first run)...\n",
		gitwin.Pinned().Version)

	gitExe, perr := installPinned(ctx)
	if perr != nil {
		return backend.Backend{}, fmt.Errorf("%w (auto-provision failed: %v)", err, perr)
	}

	activate(gitExe)

	return backend.Resolve(ManagedGitPath(), self)
}

// manifestForFlavor maps a backend flavor to its in-code pinned manifest.
// An empty flavor uses defaultFlavor. "minimal" forces the shell-less MinGit.
func manifestForFlavor(flavor string) gitwin.Manifest {
	if flavor == "" {
		flavor = defaultFlavor
	}

	switch flavor {
	case "busybox":
		return gitwin.PinnedBusybox()
	case "full":
		return gitwin.PinnedFull()
	default:
		return gitwin.Pinned()
	}
}

// resolveInstallManifest picks the manifest to install for flavor, falling back
// when the chosen flavor has no build for this platform — the full git has no
// 32-bit build, so windows/386 falls back to busybox (still a shell) then to the
// minimal MinGit.
func resolveInstallManifest(flavor string) gitwin.Manifest {
	if m := manifestForFlavor(flavor); manifestHasArch(m) {
		return m
	}

	if bb := gitwin.PinnedBusybox(); manifestHasArch(bb) {
		return bb
	}

	return gitwin.Pinned()
}

func manifestHasArch(m gitwin.Manifest) bool {
	_, ok := m.For(runtime.GOOS, runtime.GOARCH)
	return ok
}

// currentFlavor returns the persisted backend flavor ("" when unset = minimal).
func currentFlavor() string {
	s, err := settings.Load(paths.SettingsPath())
	if err != nil {
		return ""
	}

	return s.Backend.Flavor
}

// persistFlavor records the chosen backend flavor in settings.json under the
// advisory lock so it never clobbers a concurrent settings update.
func persistFlavor(flavor string) {
	_ = settings.Mutate(paths.SettingsPath(), func(s *settings.Settings) {
		s.Backend.Flavor = flavor
	})
}

// pinnedAvailable reports whether the in-code pinned manifest has a git build
// for this platform (git-for-windows MinGit is Windows-only).
func pinnedAvailable() bool {
	_, ok := gitwin.Pinned().For(runtime.GOOS, runtime.GOARCH)
	return ok
}

// installPinned downloads and sha256-verifies the in-code pinned MinGit into a
// fresh app/<uuid>/ install and returns the git.exe path (not yet activated).
func installPinned(ctx context.Context) (string, error) {
	m := resolveInstallManifest(currentFlavor())

	asset, ok := m.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return "", fmt.Errorf("no pinned git for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	base, err := newInstallBase()
	if err != nil {
		return "", err
	}

	return m.EnsurePinned(ctx, asset, base)
}

// FetchGit downloads a git backend (git-for-windows MinGit) into a fresh
// app/<uuid>/ install and activates it via settings.json. By default it uses the
// in-code hash-pinned manifest (gitwin.Pinned); --latest queries the
// git-for-windows releases API for the newest version (no pinned hash); --list
// shows recent releases.
func FetchGit(ctx context.Context, args []string) int {
	var list, latest, acceptUnverified, busybox, full, minimal bool

	for _, a := range args {
		switch a {
		case "--list":
			list = true
		case "--latest":
			latest = true
		case "--i-accept-unverified":
			acceptUnverified = true
		case "--busybox":
			busybox = true
		case "--full":
			full = true
		case "--minimal":
			minimal = true
		default:
			fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: unknown flag %q\n", a)
			return 2
		}
	}

	switch {
	case list:
		return fetchGitList(ctx)
	case latest:
		return fetchGitLatest(ctx, acceptUnverified)
	case busybox:
		return fetchGitFlavor(ctx, "busybox")
	case full:
		return fetchGitFlavor(ctx, "full")
	case minimal:
		return fetchGitFlavor(ctx, "minimal")
	default:
		return fetchGitFlavor(ctx, currentFlavor())
	}
}

// fetchGitFlavor provisions the pinned backend for flavor and, on success,
// persists the flavor so updates and auto-provision on this machine keep it.
func fetchGitFlavor(ctx context.Context, flavor string) int {
	code := fetchGitPinnedManifest(ctx, resolveInstallManifest(flavor))
	if code == 0 {
		persistFlavor(flavor)
	}

	return code
}

// fetchGitList prints the recent git-for-windows release tags.
func fetchGitList(ctx context.Context) int {
	rels, err := gitwin.List(ctx, 10)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	for _, r := range rels {
		fmt.Println(r.Tag)
	}

	return 0
}

// fetchGitLatest downloads the newest git-for-windows release. It is UNPINNED
// (no sha256 to verify against), so it refuses unless the operator opted in with
// --i-accept-unverified.
func fetchGitLatest(ctx context.Context, acceptUnverified bool) int {
	if !acceptUnverified {
		fmt.Fprintln(os.Stderr, "gitc fetch-git --latest downloads an UNPINNED git with no sha256 verification.")
		fmt.Fprintln(os.Stderr, "Prefer `git fetch-git` (in-code hash-pinned + verified).")
		fmt.Fprintln(os.Stderr, "To override and accept an unverified binary, re-run with --i-accept-unverified.")

		return 1
	}

	rel, err := gitwin.Latest(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	base, err := newInstallBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "warning: installing UNVERIFIED git-for-windows %s (%s)\n", rel.Tag, runtime.GOARCH)

	gitExe, err := gitwin.Ensure(ctx, rel, runtime.GOARCH, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	activate(gitExe)
	fmt.Printf("installed (UNVERIFIED, --i-accept-unverified) and activated: %s\n", gitExe)

	return 0
}

// fetchGitPinnedManifest downloads an in-code hash-pinned manifest (standard or
// busybox MinGit), verifies its sha256, installs it under app/<uuid>/, and
// activates it.
func fetchGitPinnedManifest(ctx context.Context, m gitwin.Manifest) int {
	asset, ok := m.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: no pinned %s for %s/%s; try --latest\n",
			m.Flavor, runtime.GOOS, runtime.GOARCH)

		return 1
	}

	fmt.Printf("fetching pinned %s %s (%s)...\n", m.Flavor, m.Version, asset.Name)

	base, err := newInstallBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	gitExe, err := m.EnsurePinned(ctx, asset, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	activate(gitExe)
	fmt.Printf("installed, sha256-verified and activated: %s\n", gitExe)

	return 0
}

// UpdateBackendIfStale installs and activates the in-code pinned git version
// when the active backend is a different version. Only the verified pinned
// channel is auto-applied; the unverified `latest` channel never is.
func UpdateBackendIfStale(ctx context.Context, sp string, s *settings.Settings) {
	if s.Update.Channel != settings.ChannelPinned {
		return
	}

	pinned := gitwin.Pinned()
	if filepath.Base(s.Backend.Active) == gitwin.VersionDir(pinned.Version) && activeGitExists(*s) {
		return // already on the pinned version
	}

	asset, ok := pinned.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return
	}

	base, err := newInstallBase()
	if err != nil {
		return
	}

	gitExe, err := pinned.EnsurePinned(ctx, asset, base)
	if err != nil {
		return
	}

	activate(gitExe)

	if reloaded, rerr := settings.Load(sp); rerr == nil {
		*s = reloaded
	}
}

// activeGitExists reports whether the settings-active backend's git.exe is present.
func activeGitExists(s settings.Settings) bool {
	if s.Backend.Active == "" {
		return false
	}

	gitExe := filepath.Join(paths.DataDir(), filepath.FromSlash(s.Backend.Active), "cmd", "git.exe")
	_, err := os.Stat(gitExe)

	return err == nil
}

// activeKeepSet returns the app/<uuid> directory names to retain: the active and
// previous installs. Legacy (git/<version>) installs contribute no app uuid.
func activeKeepSet(s settings.Settings) map[string]bool {
	keep := map[string]bool{}

	for _, rel := range []string{s.Backend.Active, s.Backend.Previous} {
		if id := appUUID(rel); id != "" {
			keep[id] = true
		}
	}

	return keep
}

// GcInstalls removes superseded app/<uuid> installs, bounding disk usage to the
// active + previous installs. It reloads settings and sweeps under the settings
// advisory lock, so a backend activation cannot interleave and have its freshly
// activated install swept (TOCTOU).
func GcInstalls() {
	_ = settings.WithLock(paths.SettingsPath(), func() {
		s, err := settings.Load(paths.SettingsPath())
		if err != nil {
			return
		}

		gcSweep(activeKeepSet(s))
	})
}

// appUUID returns the <uuid> segment of an app-relative install path
// (app/<uuid>/<version>), or "" for a non-app (legacy) install.
func appUUID(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) >= 2 && parts[0] == "app" {
		return parts[1]
	}

	return ""
}

// gcSweep removes app/<uuid> install dirs whose uuid is not in keep.
func gcSweep(keep map[string]bool) {
	entries, err := os.ReadDir(paths.AppDir())
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() || keep[e.Name()] {
			continue
		}

		_ = os.RemoveAll(filepath.Join(paths.AppDir(), e.Name()))
	}
}
