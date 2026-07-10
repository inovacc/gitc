package gitwin

// pinnedVersion is the git-for-windows release gitc pins by default.
const pinnedVersion = "v2.55.0.windows.2"

// releaseBase is the git-for-windows download URL prefix for the pinned version;
// tagURL is that release's page (recorded as a manifest Source).
const (
	releaseBase = "https://github.com/git-for-windows/git/releases/download/" + pinnedVersion + "/"
	tagURL      = "https://github.com/git-for-windows/git/releases/tag/" + pinnedVersion
)

// winAsset builds a ManifestAsset whose download URL is releaseBase+name, so the
// asset filename appears exactly once.
func winAsset(name, sha string, size int64) ManifestAsset {
	return ManifestAsset{Name: name, URL: releaseBase + name, SHA256: sha, Size: size}
}

// pinnedManifest is the compile-time-pinned git-for-windows MinGit release gitc
// installs by default: per-platform asset URLs + sha256 digests for a fixed
// version.
//
// It lives in Go source rather than an embedded git_release.json so the pinned
// set cannot be swapped by replacing a data file that ships next to the binary —
// changing it requires editing source and rebuilding. Each asset is still
// sha256-verified at download time (see EnsurePinned), so a tampered URL or a
// corrupt download is rejected regardless.
var pinnedManifest = Manifest{
	Version: pinnedVersion,
	Source:  tagURL,
	Flavor:  "MinGit",
	Assets: map[string]ManifestAsset{
		"windows/amd64": winAsset("MinGit-2.55.0.2-64-bit.zip",
			"e3ea2944cea4b3fabcd69c7c1669ef69b1b66c05ac7806d81224d0abad2dec31", 38839825),
		"windows/386": winAsset("MinGit-2.55.0.2-32-bit.zip",
			"04009f6150c1cec2d6779c51406c8c6a3f0133e57fa91c91eb8a030b93e68ccb", 39034925),
		"windows/arm64": winAsset("MinGit-2.55.0.2-arm64.zip",
			"0b2b81fdce284efd174cbb51b886ccea2fd271679c4b5c21f07d9e03bae51413", 37496126),
	},
}

// Pinned returns the compile-time-pinned MinGit manifest.
func Pinned() Manifest {
	return pinnedManifest
}

// pinnedBusyboxManifest is the busybox MinGit variant. Unlike the standard
// MinGit it bundles busybox, which provides a POSIX shell (`sh`), so git hooks
// (`#!/bin/sh`) run without a separately-installed shell. git-for-windows builds
// it for 64/32-bit only — there is no arm64 busybox MinGit.
var pinnedBusyboxManifest = Manifest{
	Version: pinnedVersion,
	Source:  tagURL,
	Flavor:  "MinGit-busybox",
	Assets: map[string]ManifestAsset{
		"windows/amd64": winAsset("MinGit-2.55.0.2-busybox-64-bit.zip",
			"760e5a4d2ff5469adfc74f9f46901eee412de48dedaa6ef1785c0cf9a7f065fb", 34323886),
		"windows/386": winAsset("MinGit-2.55.0.2-busybox-32-bit.zip",
			"cc4ce341dae51eafb6c30e0701569338b7cb32c0621328fe43db2047e8a8d821", 34516238),
	},
}

// PinnedBusybox returns the busybox MinGit manifest — a MinGit that bundles a
// POSIX shell for hook execution. No arm64 build exists.
func PinnedBusybox() Manifest {
	return pinnedBusyboxManifest
}

// pinnedFullManifest is the FULL git-for-windows build (a .tar.bz2), which
// bundles a complete MSYS2 environment — real bash AND sh — so both `#!/bin/sh`
// and `#!/bin/bash` git hooks run. Larger than MinGit; git-for-windows ships it
// for 64-bit and arm64 only (no 32-bit tarball).
var pinnedFullManifest = Manifest{
	Version: pinnedVersion,
	Source:  tagURL,
	Flavor:  "Git-full",
	Assets: map[string]ManifestAsset{
		"windows/amd64": winAsset("Git-2.55.0.2-64-bit.tar.bz2",
			"5cfd35fadb11ac2f629c16f7be262f3f138cfe3f368331ad1e44f9abb5814882", 116921702),
		"windows/arm64": winAsset("Git-2.55.0.2-arm64.tar.bz2",
			"06c1c6c854628b9ac1081376bccc4a7b6ecd46ee14bb1bca10c57fa680234305", 159014090),
	},
}

// PinnedFull returns the full git-for-windows manifest — a complete build with
// real bash + sh for hook execution. 64-bit and arm64 only.
func PinnedFull() Manifest {
	return pinnedFullManifest
}
