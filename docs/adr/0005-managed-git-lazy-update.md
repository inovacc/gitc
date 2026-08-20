# ADR 0005 — Managed git backend: UUID-namespaced installs + lazy background updates

Status: Proposed
Date: 2026-07-09

## Context

The managed git backend currently lives at a version-named path
(`%LOCALAPPDATA%\gitc\git\v2.55.0.windows.2\`) and `paths.ManagedGitPath()`
resolves it by scanning the cache dir for the newest install. There is no
controlled way to (a) install a new backend side-by-side without touching the
running one (a running `git.exe` cannot be modified on Windows), (b) switch to
it atomically, or (c) refresh it in the background without slowing down the
foreground `git` command.

We want: side-by-side immutable installs, an explicit active-pointer, and a
throttled, non-blocking, self-healing background update check.

## Decision

### On-disk layout

```
%LOCALAPPDATA%\gitc\
  settings.yaml                      # single source of truth (see schema)
  app\
    0192f8a1-...(uuidv7)\            # one IMMUTABLE install per download
      v2.55.0.windows.2\cmd\git.exe ...
    0192f9b2-...(uuidv7)\            # a newer install, side-by-side
      v2.56.0.windows.1\...
  audit\gitc.db
  git\                               # LEGACY location — migrated on first run
```

- Each backend download lands in a **fresh UUIDv7 directory**, so a new install
  never touches the in-use one. UUIDv7 is **time-ordered**, so directory names
  sort chronologically → trivial GC (keep active + previous, prune older).
- UUIDv7 is generated in-process (`internal/uuidv7`, ~30 LOC: 48-bit unix-ms +
  crypto/rand) — no new dependency.

### settings.json — the source of truth

Format is **JSON** (`settings.json`), zero new dependency and consistent with the
embedded `git_release.json` manifest.

```json
{
  "version": 1,
  "backend": {
    "active": "app/0192f8a1-.../v2.55.0.windows.2",
    "previous": "app/0190.../v2.54.0.windows.1"
  },
  "update": {
    "enabled": true,
    "channel": "pinned",
    "interval": "336h",
    "backendLastCheck": "2026-07-09T20:00:00Z",
    "gitcLastCheck": "2026-07-09T20:00:00Z"
  }
}
```

`update.enabled` defaults **true** (checks every 2 weeks out of the box); it
never activates an unverified install. Two independent throttle timestamps cover
the two update targets (see Scope).

### Resolution — every invocation, fast, no network

1. Load `settings.yaml`; if absent, create it with defaults and **migrate** any
   legacy `git\<version>` install (move under `app\<uuid>\`, point `active` at it).
2. `ManagedGitPath = backend.active`; if its `git.exe` is missing, fall back to
   `backend.previous`, else to a cache scan, else `ErrNoBackend` (→ `fetch-git`).
3. **Lazy update trigger** — if `update.enabled` and `now - last_check >= interval`:
   - Acquire a **non-blocking lockfile** (`update.lock`); if held, skip (single-flight).
   - **Optimistically write `last_check = now`** immediately, so a burst of
     parallel `git` calls (an IDE) spawns exactly one checker and a failed check
     still waits a full interval.
   - **Spawn a detached background process** (`gitc gitc backend-update`) and
     return at once. The foreground `git` command is never blocked on the network.

### Background updater — `gitc gitc backend-update`

1. Query the channel for the newest version.
2. If newer than `active`: download into `app\<new-uuidv7>\<version>\` and
   **verify sha256** — never activate an unverified binary.
3. Atomically rewrite `settings.yaml` (write temp + rename): `previous = active`,
   `active = new`, `last_check = now`.
4. GC installs older than `previous`.
5. Exit. The next `git` invocation resolves the new backend from `settings.yaml`.

## Coherence constraints (why this shape)

- **Verification is mandatory.** A background auto-updater that swaps in an
  unverified git would undo ADR-0004 / hardening items **H-01** and **H-05**
  (we just closed the "install an unverified binary" hole). So `channel: latest`
  (unpinned, unverified) stays gated behind an explicit opt-in; the default
  `channel: pinned` only activates a sha256-verified install.
- **Never mutate the running git.** Activation is a pointer flip in
  `settings.yaml`, not an in-place overwrite — safe on Windows, and a
  failed/partial download leaves the working install active. Rollback = flip
  `active` back to `previous`.
- **Single-flight + optimistic `last_check`** — prevents an IDE's parallel git
  invocations from each spawning a checker or re-checking every call.
- **Bounded disk** — GC keeps active + previous only.
- **Backwards compatible** — the legacy `git\` install is migrated, not orphaned;
  `GITC_GIT_BACKEND` env override still wins for tests/pinning.

## Resolved decisions

1. **Config format: JSON** (`settings.json`) — zero new dependency, matches
   `git_release.json`.
2. **Auto-update: enabled by default, verified-only** — checks every 2 weeks out
   of the box; refuses to activate any install it cannot sha256-verify.
   Unverified `latest` stays gated behind an explicit opt-in.
3. **Scope: git backend AND gitc self-update** — one `settings.json` throttle,
   two timestamps (`backendLastCheck`, `gitcLastCheck`). The backend updater
   swaps `app/<uuid>/` installs; the gitc updater reuses the verified
   `git update --apply` path (H-01) but triggered lazily in the background.

## Implementation plan

- **Phase A — foundation (pure, testable):** `internal/uuidv7`,
  `internal/settings` (schema, load/save with atomic temp+rename, defaults),
  and legacy-install migration; wire `paths`/`backend` resolution through
  `settings.json` (keeping the `GITC_GIT_BACKEND` override and on-disk fallback).
- **Phase B — background refresh:** the lazy trigger in `run()` (single-flight
  lock + optimistic timestamp + detached spawn), the `backend-update` command,
  verified activation + `previous` rollback pointer, install GC, and the gitc
  self-update throttle.

## Consequences

- New: `internal/settings` (load/save/atomic-replace), `internal/uuidv7`, a
  `backend-update` meta command, and a background-spawn helper.
- Changed: `internal/paths` + `internal/backend` resolve via `settings.yaml`
  instead of a newest-on-disk scan.
- The settings.yaml schema becomes a compatibility contract (versioned; changes
  follow the deprecation policy).
```
