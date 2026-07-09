// Package settings persists gitc's on-disk configuration (settings.json): the
// active managed-git backend pointer and the background-update policy. It is the
// single source of truth for backend resolution and update throttling (ADR
// 0005). Writes are atomic (temp file + rename) so a crash mid-write can never
// leave a partially-written settings file.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// schemaVersion is the settings.json format version; bumped when the shape
// changes (migrations follow the deprecation policy).
const schemaVersion = 1

// DefaultInterval is the fallback background-update check cadence (2 weeks).
const DefaultInterval = 14 * 24 * time.Hour

// Channel selects how an update is sourced and verified.
const (
	// ChannelPinned only activates a sha256-verified install.
	ChannelPinned = "pinned"
	// ChannelLatest allows the newest upstream release without a pinned digest
	// (unverified) — opt-in only.
	ChannelLatest = "latest"
)

// Settings is the full settings.json document.
type Settings struct {
	Version int     `json:"version"`
	Backend Backend `json:"backend"`
	Update  Update  `json:"update"`
}

// Backend points at the active managed-git install (and a rollback target),
// as paths relative to the gitc root.
type Backend struct {
	Active   string `json:"active"`
	Previous string `json:"previous,omitempty"`
}

// Update is the background-update policy and throttle state.
type Update struct {
	Enabled          bool   `json:"enabled"`
	Channel          string `json:"channel"`
	Interval         string `json:"interval"`
	BackendLastCheck string `json:"backendLastCheck,omitempty"`
	GitcLastCheck    string `json:"gitcLastCheck,omitempty"`
}

// Default returns the out-of-the-box settings: background checks enabled every
// two weeks on the verified (pinned) channel, with no backend selected yet.
func Default() Settings {
	return Settings{
		Version: schemaVersion,
		Update: Update{
			Enabled:  true,
			Channel:  ChannelPinned,
			Interval: DefaultInterval.String(),
		},
	}
}

// Load reads and parses settings.json. A missing file is reported as
// os.ErrNotExist so callers can distinguish "no config yet" from a parse error.
func Load(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, err
	}

	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, fmt.Errorf("parse settings %s: %w", path, err)
	}

	return s, nil
}

// LoadOrInit loads settings.json, creating it with Default() when it does not
// exist yet.
func LoadOrInit(path string) (Settings, error) {
	s, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		s = Default()
		if serr := Save(path, s); serr != nil {
			return s, serr
		}

		return s, nil
	}

	return s, err
}

// Save writes settings atomically (temp file in the same dir + rename), with
// owner-only permissions.
func Save(path string, s Settings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.json")
	if err != nil {
		return fmt.Errorf("create temp settings: %w", err)
	}

	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return fmt.Errorf("write temp settings: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp settings: %w", err)
	}

	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp settings: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace settings: %w", err)
	}

	return nil
}

// IntervalDuration parses Update.Interval, falling back to DefaultInterval on an
// empty or invalid value.
func (u Update) IntervalDuration() time.Duration {
	d, err := time.ParseDuration(u.Interval)
	if err != nil || d <= 0 {
		return DefaultInterval
	}

	return d
}

// DueSince reports whether at least IntervalDuration has elapsed since the RFC
// 3339 timestamp last (an empty/invalid last is always due).
func (u Update) DueSince(last string, now time.Time) bool {
	if !u.Enabled {
		return false
	}

	t, err := time.Parse(time.RFC3339, last)
	if err != nil {
		return true
	}

	return now.Sub(t) >= u.IntervalDuration()
}
