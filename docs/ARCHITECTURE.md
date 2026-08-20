# Architecture
<!-- rev:001 -->

gitc is a transparent proxy that installs *as* `git` and routes every
invocation through a policy/audit chokepoint before delegating to a real git
backend. This document diagrams the real code in `main.go` + `internal/*`.

## System overview

```mermaid
flowchart TB
    agent["AI agent / shell<br/>calls `git ...`"]
    subgraph gitc["gitc (installed as git via PATH shim)"]
        router["router.Classify<br/>(main.run)"]
        native["native commands<br/>scan · scrub · audit · where<br/>install · fetch-git"]
        short["shortcuts<br/>sync · undo · log-graph · quick-commit"]
        runner["runner<br/>exec + audit"]
        policy["policy<br/>init → main default"]
    end
    subgraph backends["git backend (backend.Resolve)"]
        managed["managed MinGit<br/>%LOCALAPPDATA%\\gitc\\git\\&lt;ver&gt;"]
        system["system git on PATH<br/>(self-invocation guard)"]
    end
    store[("audit log<br/>SQLite, append-only")]

    agent -->|argv| router
    router -->|native name| native
    router -->|shortcut name| short
    router -->|everything else| policy --> runner
    short --> runner
    runner -->|exec, inherit stdio| managed
    runner -->|fallback| system
    runner -->|one row per call| store
    native -.->|scrub/fetch-git use| backends
```

## Command routing (`main.run` → `router.Classify`)

Only gitc-native names and the reserved `gitc` token are intercepted; names that
collide with real git (`clean`, `version`) pass through untouched.

```mermaid
flowchart TD
    start["args[0]"] --> gitc{"== 'gitc'?"}
    gitc -->|yes| meta["runMeta (forced namespace)"]
    gitc -->|no| fcm{"first-class native?<br/>scan/scrub/audit/where/<br/>install/uninstall/fetch-git"}
    fcm -->|yes| meta
    fcm -->|no| sc{"shortcut?<br/>sync/undo/log-graph/quick-commit"}
    sc -->|yes| shortcut["runner.Shortcut"]
    sc -->|no| pass["runner.Passthrough → real git<br/>(git clean, git version, git status…)"]
```

## Passthrough + audit (per invocation)

```mermaid
sequenceDiagram
    participant A as agent
    participant R as runner
    participant B as backend (MinGit)
    participant S as store (SQLite)
    A->>R: git <args>
    R->>R: capture cwd, user, env subset, argv
    R->>B: exec CommandContext (inherit stdin/stdout/stderr)
    B-->>R: exit code + duration
    R->>B: enrich: `git status --porcelain=v2` (out-of-band)
    R->>S: INSERT audit row (raw, unredacted)
    Note over R,S: audit write is best-effort;<br/>never blocks the git command
    R-->>A: git's stdout/stderr + exit code
```

## Backend resolution (`backend.Resolve`)

```mermaid
flowchart TD
    r["Resolve(managedPath, self)"] --> env{"GITC_GIT_BACKEND set?"}
    env -->|yes| useenv["use it (managed)"]
    env -->|no| cache{"downloaded MinGit<br/>in cache?"}
    cache -->|yes| usecache["use newest (managed)"]
    cache -->|no| path["walk PATH for git,<br/>skip self (guard)"]
    path -->|found| usesys["use system git"]
    path -->|none| err["ErrNoBackend →<br/>suggest `git fetch-git`"]
```

## History scrub pipeline (`internal/filterrepo`)

Clean-room Go port of git-filter-repo's fast-export mechanism.

```mermaid
sequenceDiagram
    participant C as gitc gitc scrub
    participant E as git fast-export
    participant P as FastExportParser
    participant I as git fast-import
    C->>E: spawn (--show-original-ids …)
    E-->>P: fast-export stream
    loop each record
        P->>P: blobfilter (redact text) / pathfilter (drop paths) / commitfilter (prune)
        P->>I: re-serialized record
    end
    I-->>C: rewritten refs
    C->>C: reflog expire + gc (cleanup); sanity guard requires --force
```

## Git backend provisioning (`internal/gitwin`, ADR 0004)

```mermaid
flowchart LR
    fg["git fetch-git"] --> m{"pinned or --latest?"}
    m -->|pinned| man["embedded git_release.json<br/>(URL + sha256)"]
    m -->|--latest| api["git-for-windows<br/>releases API"]
    man --> dl["download MinGit .zip"]
    api --> dl
    dl --> vf["sha256 verify (pinned)"]
    vf --> uz["unzip → cache dir"]
    uz --> ready["managed backend ready"]
```
