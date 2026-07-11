package settings

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMutateSerializesConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	const n = 50

	var wg sync.WaitGroup

	wg.Add(n)

	for range n {
		go func() {
			defer wg.Done()

			_ = Mutate(path, func(s *Settings) { s.Version++ })
		}()
	}

	wg.Wait()

	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// The first Mutate starts from Default (Version=1) and increments to 2; each
	// subsequent one adds 1. Under the advisory lock there are no lost updates.
	if want := 1 + n; s.Version != want {
		t.Errorf("Version = %d after %d concurrent Mutate, want %d (lost updates?)", s.Version, n, want)
	}
}

func TestAcquireLockExclusiveThenRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	release, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path + lockSuffix); err != nil {
		t.Errorf("lockfile should exist while held: %v", err)
	}

	release()

	if _, err := os.Stat(path + lockSuffix); !os.IsNotExist(err) {
		t.Error("lockfile should be removed after release")
	}

	release2, err := acquireLock(path)
	if err != nil {
		t.Fatalf("re-acquire after release should succeed: %v", err)
	}

	release2()
}
