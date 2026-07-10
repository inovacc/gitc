// Package shim embeds the tiny Windows launcher (built from shim.c, vendored
// from scoop-better-shimexe) that gitc installs as git/sh/bash.exe. Each such
// launcher reads a sibling `<name>.shim` file and execs the one canonical
// gitc.exe with the recorded args plus its own forwarded argv — so every shim
// name is a ~15-75 KB launcher into a single real binary, instead of a ~15 MB
// copy per name.
//
// The .exe files are prebuilt and committed; regenerate them from shim.c with
// `task shims` (cross-compiled via `zig cc` for both Windows arches) whenever
// shim.c changes.
package shim

import _ "embed"

//go:embed shim_amd64.exe
var amd64 []byte

//go:embed shim_arm64.exe
var arm64 []byte

// Binary returns the launcher bytes for the given GOARCH, or nil when no
// prebuilt launcher exists for it (the caller then falls back to a full copy).
func Binary(goarch string) []byte {
	switch goarch {
	case "amd64":
		return amd64
	case "arm64":
		return arm64
	default:
		return nil
	}
}
