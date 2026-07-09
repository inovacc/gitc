# 0004 — Provision the git backend by downloading MinGit

- **Status:** Accepted
- **Date:** 2026-07-09
- **Deciders:** dyammarcano
- **Supersedes:** the "build git from a `third_party/git` submodule" backend approach

## Context

gitc is a proxy and needs a real git to exec. The original plan built git from
source via a `third_party/git` submodule (`task git:build`). In practice that
proved painful and non-portable:

- Building upstream git on a bare Windows/MinGW toolchain hit a cascade of
  environment issues (missing pcre2/curl/openssl, git 2.55's new Rust
  component, MSYS `sh` recipe quirks) and only produced a **core git without
  HTTPS**.
- It requires a full C toolchain at build time and is slow/fragile in CI.
- The submodule bloats clones and pins a single upstream version.

## Decision

Drop the `third_party/git` submodule and the from-source build. Instead,
**download a prebuilt MinGit** from the git-for-windows releases and unpack it.

- MinGit is git-for-windows' minimal, redistributable git as a plain `.zip` —
  designed for apps to bundle. It is HTTPS-capable and needs no build toolchain.
- A pinned manifest, [`git_release.json`](../../git_release.json) (embedded in
  the binary via `//go:embed`), records per-platform asset URLs + **sha256**
  hashes for a fixed version (v2.55.0.windows.2). Downloads are verified against
  it — integrity + reproducibility.
- `internal/gitwin` implements: releases query (latest/list), architecture
  selection (amd64→64-bit, 386→32-bit, arm64), download, sha256 verify, and
  zip-slip-guarded unpack.
- `git fetch-git` fetches the pinned MinGit by default; `--latest` queries the
  releases API (unverified); `--list` shows recent releases. Unpacked into
  `%LOCALAPPDATA%\gitc\git\<version>\`.
- Backend resolution order: `GITC_GIT_BACKEND` → newest downloaded git in the
  cache → first non-self system git on PATH.

Scope: git-for-windows is **Windows-only**; Linux/macOS use the system git
(universally available via package managers).

## Consequences

- No C toolchain, no submodule, no slow from-source CI. gitc can provision a
  full **HTTPS-capable** git on Windows on demand, verified by hash.
- The pinned version must be refreshed in `git_release.json` when bumping
  (fetch the new release's MinGit assets + digests). `--latest` covers the
  always-current case at the cost of no pre-pinned hash.
- Removed: `third_party/git` submodule, `.gitmodules`, `task git:submodule`,
  `task git:build`, `internal/vendor-build`, and the vendored-git CI job.
