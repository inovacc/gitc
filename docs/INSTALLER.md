# gitc installer & PATH shadowing

How `gitc` shadows the real `git` so every invocation is proxied and audited,
and how to undo it. Implemented by `internal/installer` and exposed as
`gitc gitc install` / `gitc gitc uninstall`.

## Model: PATH precedence, not file overwrite

`gitc` never modifies files under an existing Git install. Shadowing is purely
a matter of PATH ordering:

1. `gitc gitc install` copies the running `gitc` binary into a dedicated **shim
   directory** — `%LOCALAPPDATA%\gitc\shim\` on Windows,
   `~/.local/share/gitc/shim/` elsewhere — named `git.exe` / `git`.
2. That shim directory is placed **earlier** on the user's `PATH` than any real
   git install. Shell and tool invocations of `git` now resolve to the shim
   (the wrapper) first.
3. The wrapper resolves the *real* git later in PATH (skipping itself via the
   self-invocation guard) or the vendored build, execs it, and audits the call.

Because the real git is only shadowed by PATH order, removing the shim dir from
PATH — or running `uninstall` — fully restores the original behavior.

## Safety guard

`install` refuses to proceed if no real git backend can be resolved once the
shim is in place (no vendored build and no non-self system git). This prevents
installing a shim that would shadow git with nothing behind it.

## Applying the PATH change

- **`gitc gitc install`** (no flag) sets up the shim dir and prints the exact
  manual PATH step for your platform. Nothing on PATH is changed.
- **`gitc gitc install --apply`** additionally prepends the shim dir to the
  **user** PATH. On Windows this uses the user Environment API via PowerShell
  (`[Environment]::SetEnvironmentVariable('Path', …, 'User')`), which does not
  suffer `setx`'s 1024-character truncation. It is idempotent — the shim dir is
  added only if not already present. Restart the shell to pick up the change.

Automatic PATH mutation on Linux/macOS is intentionally **out of scope**:
editing shell rc files programmatically is error-prone, so `--apply` there
returns the manual `export PATH=…` instruction instead.

## Uninstall

`gitc gitc uninstall` removes the shim directory. Removing the shim dir entry
from PATH is left to the user (the command prints a reminder); nothing else is
touched.

## Verifying

After install and a shell restart:

```
git gitc where     # backend: <real git> (system|vendored); audit: <db path>
git status         # normal git output — now audited
git gitc audit 5   # last 5 audited invocations
```

## Follow-ups

- Optional machine-wide (system PATH) install mode with elevation.
- Linux/macOS rc-file editing behind an explicit, reversible opt-in.
- Windows ACL hardening of the audit DB during install (owner-only).
