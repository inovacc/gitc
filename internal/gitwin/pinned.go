package gitwin

// pinnedManifest is the compile-time-pinned git-for-windows MinGit release gitc
// installs by default: per-platform asset URLs + sha256 digests for a fixed
// version.
//
// It lives in Go source rather than an embedded git_release.json so the pinned
// set cannot be swapped by replacing a data file that ships next to the binary —
// changing it requires editing source and rebuilding. Each asset is still
// sha256-verified at download time (see EnsurePinned), so a tampered URL or a
// corrupt download is rejected regardless.
// pinnedVersion is the git-for-windows release gitc pins by default.
const pinnedVersion = "v2.55.0.windows.2"

var pinnedManifest = Manifest{
	Version: pinnedVersion,
	Source:  "https://github.com/git-for-windows/git/releases/tag/v2.55.0.windows.2",
	Flavor:  "MinGit",
	Assets: map[string]ManifestAsset{
		"windows/amd64": {
			Name:   "MinGit-2.55.0.2-64-bit.zip",
			URL:    "https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.2/MinGit-2.55.0.2-64-bit.zip",
			SHA256: "e3ea2944cea4b3fabcd69c7c1669ef69b1b66c05ac7806d81224d0abad2dec31",
			Size:   38839825,
		},
		"windows/386": {
			Name:   "MinGit-2.55.0.2-32-bit.zip",
			URL:    "https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.2/MinGit-2.55.0.2-32-bit.zip",
			SHA256: "04009f6150c1cec2d6779c51406c8c6a3f0133e57fa91c91eb8a030b93e68ccb",
			Size:   39034925,
		},
		"windows/arm64": {
			Name:   "MinGit-2.55.0.2-arm64.zip",
			URL:    "https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.2/MinGit-2.55.0.2-arm64.zip",
			SHA256: "0b2b81fdce284efd174cbb51b886ccea2fd271679c4b5c21f07d9e03bae51413",
			Size:   37496126,
		},
	},
}

// Pinned returns the compile-time-pinned MinGit manifest.
func Pinned() Manifest {
	return pinnedManifest
}
