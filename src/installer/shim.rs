//! Port of Go `internal/installer/shim` — embed the tiny Windows launcher (built
//! from `shim.c`, vendored from scoop-better-shimexe) that gitc installs as
//! git/sh/bash.exe. Each launcher reads a sibling `<name>.shim` file and execs the
//! one canonical gitc.exe with the recorded args plus its own forwarded argv — so
//! every shim name is a ~15-75 KB launcher into a single real binary, instead of a
//! ~15 MB copy per name.
//!
//! The `.exe` files are prebuilt, committed assets (regenerated out-of-band from
//! `shim.c` via `zig cc`, never by cargo).

/// amd64 launcher bytes (Go `//go:embed shim_amd64.exe`).
static AMD64: &[u8] = include_bytes!("shim_amd64.exe");
/// arm64 launcher bytes (Go `//go:embed shim_arm64.exe`).
static ARM64: &[u8] = include_bytes!("shim_arm64.exe");

/// Go `Binary` — the launcher bytes for the given GOARCH, or `None` when no
/// prebuilt launcher exists (the caller then falls back to a full copy). The arch
/// strings are Go's `GOARCH` values, kept verbatim since they are a parameter.
pub fn binary(goarch: &str) -> Option<&'static [u8]> {
    match goarch {
        "amd64" => Some(AMD64),
        "arm64" => Some(ARM64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_for_arch() {
        for arch in ["amd64", "arm64"] {
            let b = binary(arch).unwrap_or_else(|| panic!("Binary({arch}) must be embedded"));
            assert!(!b.is_empty(), "Binary({arch}) is empty");
            // The vendored shim is a PE executable — MZ magic catches a truncated
            // or wrong-format embed.
            assert!(
                b.starts_with(b"MZ"),
                "Binary({arch}) is not a PE executable (missing MZ header)"
            );
        }
        assert!(
            binary("mips").is_none(),
            "Binary should return None for an arch with no prebuilt launcher"
        );
    }
}
