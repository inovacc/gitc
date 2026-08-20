# ADR 0007 — Tiny launcher shims + canonical binary

Status: Accepted
Date: 2026-07-10

## Context

`git install` shadows git by placing a `git.exe` (and, for hooks, `sh.exe` /
`bash.exe`) earlier on PATH than the real git. The first implementation made
those shims a full copy of the gitc binary — one ~15 MB executable per name,
deduplicated to a single inode via hard links (so ~15 MB on disk, not ×3).

Two problems motivated a change:

- **Size / optics.** A 15 MB `git.exe` is jarring next to git-for-windows' own
  46 KB `bin/git.exe` launchers, and every self-update rewrites that 15 MB shim.
- **Update churn.** Because the shim *was* the gitc binary, `git update` swapped
  the on-PATH shim in place, leaving a locked `git.exe.old` behind each time.

git-for-windows itself solves this with a thin launcher (`bin/git.exe`) that
re-execs into a shared install tree. scoop uses the same idea via
[`scoop-better-shimexe`](https://github.com/71/scoop-better-shimexe): a ~15 KB
C launcher that reads a sibling `<name>.shim` (`path = …` + optional `args = …`)
and execs the target with those args plus its own forwarded argv, under a
kill-on-close job object with Ctrl+C forwarded to the child.

## Decision

Adopt the launcher model on **Windows**, vendoring `shim.c` verbatim (SPDX:
`MIT OR Unlicense`):

- One **canonical `gitc.exe`** lives under `%LOCALAPPDATA%\gitc\bin\`
  (`paths.CanonicalPath`). It is the only full copy and the target `git update`
  replaces in place.
- The shim dir holds three **tiny launchers** — `git.exe`, `sh.exe`, `bash.exe`
  — each the embedded `shim.c` build (~19–75 KB), hard-linked to one inode, plus
  a sibling `.shim` file. The sh/bash **persona rides in `.shim` `args`** via
  gitc's existing meta commands (`git gitc sh|bash`), so no argv[0] self-detection
  is needed: `git.shim` has no args (pure passthrough); `sh.shim`/`bash.shim`
  carry `args = gitc sh` / `gitc bash`.

`shim.c` is cross-compiled for both Windows arches with `zig cc` (`task shims`),
and the resulting `shim_<arch>.exe` are committed and embedded via `go:embed`.
A `//go:build ignore` on `shim.c` keeps the Go toolchain from treating a stray
`.c` in the package as a (CGO-disabled) build error.

Non-Windows keeps the copy-the-binary shim: Unix has a system `/bin/sh`, and the
size concern is Windows-specific.

Because the shim now delegates to `bin\gitc.exe`, `git update` swaps
`os.Executable()` = the canonical (not the on-PATH launcher). The launchers are
immutable; only the canonical changes. `.old` leftovers now land in `bin\`, so
the startup sweep clears both the shim and bin dirs.

## Consequences

- On-PATH `git.exe` drops from ~15 MB to ~75 KB; self-update rewrites one binary
  in `bin\`, never the on-PATH launchers.
- New: `internal/installer/shim` (vendored `shim.c` + `go:embed`), `paths.BinDir`
  / `paths.CanonicalPath`, `task shims`, `installer.placeWindowsLaunchers`.
- The committed `shim_<arch>.exe` are a build artifact of `shim.c`; regenerate
  with `task shims` when `shim.c` changes (a CI reproducibility check is backlog).
- The full-git backend extraction now prunes `bin/`, `tmp/`, `dev/` — gitc uses
  `cmd/git.exe` and the `usr/bin`/`mingw64/bin` shells directly, never the
  tarball's top-level `bin/` launchers.

## Alternatives considered

- **Keep 15 MB hard-linked copies** — simplest, and disk cost is a single inode,
  but leaves the update-churn `.old` problem and the size optics.
- **A Go micro-launcher** — pure-Go and cross-platform, but a minimal Go binary
  floors at ~1.7 MB vs `shim.c`'s ~15–75 KB, and adds no Windows-signal handling.
- **Precompiled C shim without vendoring source** — opaque; vendoring `shim.c`
  keeps the launcher auditable and rebuildable.
