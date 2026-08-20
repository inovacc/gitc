# ADR 0006 — Enforcement gates & policy.json

Status: Accepted
Date: 2026-07-10

## Context

gitc's mission is to *block* AI agents from leaking secrets or exfiltrating to
unapproved remotes — not merely detect afterwards. The audit log, `git scan`,
and `git scrub` are building blocks; enforcement is the goal. An agent flows
through gitc (the shim) for every git call, so gitc is the natural chokepoint to
refuse a dangerous command before it reaches git.

Two forces shape the design:

- The policy must be **non-overridable by the agent.** An agent can pass any git
  flag, set any env var, and edit repo-local config — so the control cannot live
  in git config or a flag.
- gitc must **fail safe.** A broken or ambiguous policy should refuse, not
  silently allow.

## Decision

A machine/org **`policy.json`** in the gitc data dir
(`%LOCALAPPDATA%\gitc\policy.json`) drives enforcement. gitc reads it read-only;
nothing an agent can do at the git command line changes it. An **absent file
means no enforcement** — enforcement is strictly opt-in by an operator dropping
the file. `internal/policy.LoadPolicy` returns a zero (no-enforcement) policy on
a missing file and **fails closed** (refuses the command) on a malformed one.

Gates run in `main.enforceGates`, before a passthrough command reaches git:

### Secret gate (GATE-1 / GATE-2)
When enabled and the subcommand is `commit`/`push` (configurable), gitc runs a
working-tree secret scan. On any finding it **refuses** (non-zero, git never
runs) — or, with `mode: "warn"`, reports and proceeds. Per-severity thresholds
were considered but the gitleaks ruleset carries no severity on findings, so the
knob is a binary block/warn `mode`.

### Remote allowlist (GATE-3)
When enabled, gitc blocks `push`/`fetch`/`clone`/`pull`/`remote` to a host (or
`host/owner`) not on the list. Crucially it resolves the **effective remote
URL** first — a named remote (`git push origin`) via `git remote get-url`, and a
bare `git push` via the branch's `@{push}` / `origin`. Checking only literal URL
arguments would let an agent pre-configure a remote (`git remote add evil …`)
and push to it by name; resolving names closes that bypass.

## Consequences

- New: `internal/policy.Policy` (schema + `LoadPolicy` + `SecretGateApplies` /
  `RemoteRefs` / `RemoteAllowed`), `main.gates.go` (orchestration + remote
  resolution via the backend).
- The allowlist runs short, read-only `git` queries (bounded by a 5s timeout)
  before a remote-facing command — a small latency cost only when enabled.
- `policy.json` is a compatibility contract (versioned); changes follow the
  deprecation policy.
- Enforcement composes with the rest of the gate: credential redaction and the
  tamper-evident audit chain (ADR-... / the audit-integrity work) ensure that
  even an *allowed* command's record can't leak or be quietly altered.

## Alternatives considered

- **git hooks** — bypassable (an agent can `--no-verify` or delete the hook) and
  per-repo; rejected for a non-bypassable control.
- **Policy in git config / env** — agent-writable; rejected.
- **Per-severity secret thresholds** — not supported by the ruleset's finding
  shape; deferred until findings carry severity.
