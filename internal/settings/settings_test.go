package settings

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	d := Default()
	if d.Version != schemaVersion {
		t.Errorf("version = %d, want %d", d.Version, schemaVersion)
	}

	if !d.Update.Enabled || d.Update.Channel != ChannelPinned {
		t.Errorf("default update policy = %+v, want enabled pinned", d.Update)
	}

	if d.Update.IntervalDuration() != DefaultInterval {
		t.Errorf("default interval = %s, want %s", d.Update.IntervalDuration(), DefaultInterval)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sub", "settings.json")

	in := Default()
	in.Backend.Active = "app/abc/v2.55.0.windows.2"
	in.Backend.Previous = "app/xyz/v2.54.0.windows.1"

	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Backend.Active != in.Backend.Active || got.Backend.Previous != in.Backend.Previous {
		t.Errorf("round trip mismatch: %+v vs %+v", got.Backend, in.Backend)
	}
}

func TestLoadOrInitCreates(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")

	s, err := LoadOrInit(path)
	if err != nil {
		t.Fatalf("LoadOrInit: %v", err)
	}

	if !s.Update.Enabled {
		t.Error("initialized settings should have update enabled")
	}

	// The file must now exist and reload identically.
	if _, err := Load(path); err != nil {
		t.Fatalf("settings file not created: %v", err)
	}
}

func TestIntervalDurationFallback(t *testing.T) {
	t.Parallel()

	if (Update{Interval: "nonsense"}).IntervalDuration() != DefaultInterval {
		t.Error("invalid interval should fall back to default")
	}

	if (Update{Interval: "1h"}).IntervalDuration() != time.Hour {
		t.Error("valid interval should parse")
	}
}

func TestDueSince(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	u := Update{Enabled: true, Interval: "336h"}

	if !u.DueSince("", now) {
		t.Error("empty last-check should be due")
	}

	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	if u.DueSince(recent, now) {
		t.Error("a check 1h ago should not be due within a 2-week interval")
	}

	old := now.Add(-15 * 24 * time.Hour).Format(time.RFC3339)
	if !u.DueSince(old, now) {
		t.Error("a check 15 days ago should be due")
	}

	if (Update{Enabled: false, Interval: "336h"}).DueSince("", now) {
		t.Error("disabled updates are never due")
	}
}
