package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/provision"
	"github.com/inovacc/gitc/internal/selfupdate"
	"github.com/inovacc/gitc/internal/settings"
)

// updateLockStale bounds how long an update.lock is honored before a crashed
// checker's lock is reclaimed.
const updateLockStale = time.Hour

func lockPath() string   { return filepath.Join(paths.DataDir(), "update.lock") }
func noticePath() string { return filepath.Join(paths.DataDir(), "update-notice.txt") }

// maybeSpawnBackgroundUpdate lazily starts a background update check when one is
// due, without blocking the foreground git command. It is single-flight (a
// lockfile) and stamps the check time optimistically, so a burst of invocations
// spawns at most one checker and the interval is respected even if the check
// fails. It is a no-op inside a background child (GITC_BACKGROUND) or when
// updates are disabled / not yet due.
func maybeSpawnBackgroundUpdate() {
	if os.Getenv("GITC_BACKGROUND") != "" {
		return
	}

	sp := paths.SettingsPath()

	s, err := settings.Load(sp)
	if err != nil || !s.Update.Enabled {
		return
	}

	now := time.Now().UTC()
	if !s.Update.DueSince(s.Update.BackendLastCheck, now) && !s.Update.DueSince(s.Update.GitcLastCheck, now) {
		return
	}

	release, ok := tryUpdateLock(lockPath())
	if !ok {
		return
	}

	defer release()

	// Optimistic stamp: later invocations see "not due" for the interval.
	stamp := now.Format(time.RFC3339)
	s.Update.BackendLastCheck = stamp
	s.Update.GitcLastCheck = stamp

	if err := settings.Save(sp, s); err != nil {
		return
	}

	_ = spawnDetached("gitc", "backend-update")
}

// tryUpdateLock creates an exclusive lockfile, reclaiming a stale one. ok is
// false when another checker already holds a fresh lock.
func tryUpdateLock(path string) (func(), bool) {
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > updateLockStale {
		_ = os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, false
	}

	_ = f.Close()

	return func() { _ = os.Remove(path) }, true
}

// spawnDetached re-execs gitc, detached, with the given args and returns at once
// (the child outlives this process). GITC_BACKGROUND marks the child so it never
// spawns further checkers.
func spawnDetached(args ...string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(context.Background(), self, args...) //nolint:gosec // self re-exec, fixed args

	cmd.Env = append(os.Environ(), "GITC_BACKGROUND=1")
	configureDetached(cmd)

	if err := cmd.Start(); err != nil {
		return err
	}

	return cmd.Process.Release()
}

// printAndClearNotice prints and removes a pending background-update notice, so
// the user learns of a new gitc release without the check ever blocking a command.
func printAndClearNotice() {
	data, err := os.ReadFile(noticePath())
	if err != nil {
		return
	}

	fmt.Fprint(os.Stderr, "gitc: "+string(data))

	_ = os.Remove(noticePath())
}

// runBackendUpdate is the detached worker (`gitc gitc backend-update`): it brings
// the managed git backend up to the pinned version (verified) when needed,
// records whether a newer gitc release exists, and garbage-collects superseded
// installs. Best-effort; it prints nothing to the foreground.
func runBackendUpdate(ctx context.Context) int {
	sp := paths.SettingsPath()

	s, err := settings.LoadOrInit(sp)
	if err != nil {
		return 1
	}

	provision.UpdateBackendIfStale(ctx, sp, &s)
	recordGitcNotice(ctx)
	provision.GcInstalls(provision.ActiveKeepSet(s))

	return 0
}

// recordGitcNotice writes a one-line notice when a newer gitc release exists;
// the foreground prints it once on the next invocation.
func recordGitcNotice(ctx context.Context) {
	info, err := selfupdate.Check(ctx, version)
	if err != nil || !info.HasUpdate {
		return
	}

	msg := fmt.Sprintf("a newer gitc is available: %s (run `git update --apply`)\n", info.Latest)
	_ = os.WriteFile(noticePath(), []byte(msg), 0o600)
}
