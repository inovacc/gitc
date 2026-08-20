//! Port of Go `internal/installer`. The embedded launcher shim (submodule
//! [`shim`]) plus the shadow-installer (submodule [`installer`]) that places the
//! git/sh/bash shims and manages the user PATH.

// The submodule mirrors Go's `internal/installer/installer.go` name — the
// same-name-as-parent is an intentional 1:1 structure map.
#[allow(clippy::module_inception)]
pub mod installer;
pub mod shim;
