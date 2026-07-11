package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Settings mutation is a read-modify-write across multiple gitc processes (a
// foreground command activating a backend while a detached background updater
// stamps a check time, say). The atomic temp-file+rename in Save protects a
// single write from tearing, but two overlapping RMW cycles would still clobber
// each other — whoever saves last wins and drops the other's change. An advisory
// lockfile around the whole RMW (Mutate) serializes them.

const (
	lockSuffix     = ".lock"
	lockStale      = 10 * time.Second
	lockAcquireMax = 5 * time.Second
	lockSpin       = 2 * time.Millisecond
)

// acquireLock takes an advisory lock for the settings file at path, spinning
// until it wins, a stale lock is reclaimed, or lockAcquireMax elapses. The
// returned release func removes the lockfile.
func acquireLock(path string) (release func(), err error) {
	lp := path + lockSuffix

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create settings dir: %w", err)
	}

	start := time.Now()

	for {
		f, openErr := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lp) }, nil
		}

		// Reclaim a lock abandoned by a crashed holder.
		if info, statErr := os.Stat(lp); statErr == nil && time.Since(info.ModTime()) > lockStale {
			_ = os.Remove(lp)
			continue
		}

		if time.Since(start) > lockAcquireMax {
			return nil, fmt.Errorf("acquire settings lock %s: timed out after %s", lp, lockAcquireMax)
		}

		time.Sleep(lockSpin)
	}
}

// Mutate applies fn to the settings at path under the advisory lock, so
// concurrent read-modify-write cycles from multiple gitc processes cannot
// clobber one another. It loads the current settings (starting from Default when
// the file does not exist yet), applies fn, and atomically saves the result —
// all while holding the lock.
func Mutate(path string, fn func(*Settings)) error {
	release, err := acquireLock(path)
	if err != nil {
		return err
	}

	defer release()

	s, err := Load(path)
	if os.IsNotExist(err) {
		s = Default()
	} else if err != nil {
		return err
	}

	fn(&s)

	return Save(path, s)
}
