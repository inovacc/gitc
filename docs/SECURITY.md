# Security Policy & Threat Model
<!-- rev:001 -->

gitc is a **non-bypassable, forensically-audited gate for AI coding agents** — it
shadows `git` on PATH so every git invocation flows through it, enforces a
machine/org policy that a git flag cannot override, and records an append-only
tamper-evident audit trail. This document states what gitc defends against, the
trust boundary, the known residual gaps, and how to report a vulnerability.

## Threat model

**Primary adversary:** an autonomous AI coding agent (or a careless automation)
running on a developer's machine that should not exfiltrate secrets or push to
unapproved remotes through git — whether by mistake or prompt injection.

**What gitc stops:**
- Leaking secrets by committing/pushing them (pre-flight secret gate).
- Pushing/fetching to a remote whose host/owner is not allow-listed.
- Routing around the gate via git's own escape hatches (built-in shortcuts,
  `-c` config overrides, alias injection, low-level ref-transfer plumbing).
- Silently deleting or editing audit history to hide activity.

## Trust boundary (read this first)

gitc runs as the **same OS user** as the agent it audits. It is therefore a
control against a **non-privileged, non-gitc-aware adversary** — the realistic
case for an LLM agent — **not** against a local root/Administrator attacker who
can replace the gitc binary, read admin-only files, or attach a debugger.

Concretely:
- An attacker who can **overwrite the gitc binary or the PATH shim** defeats the
  gate. Protect the install directory with OS permissions.
- The enforcement policy is read from a **machine directory**
  (`%ProgramData%\gitc\policy.json` / `/etc/gitc/policy.json`) precisely because
  the per-user path is agent-relocatable. On a properly-installed system that
  directory is admin-writable only; a non-admin agent cannot weaken the policy.
  An `ENFORCE` marker there makes a missing policy **fail closed**.

## Controls

| Control | Mechanism | Fails… |
|---------|-----------|--------|
| Non-bypassable shadow | PATH-precedence shim → single `runner.execAndAudit` choke point; shortcuts + passthrough both gated | — |
| Secret gate | embedded gitleaks ruleset; blocks commit/push on findings | closed (blocks) |
| Pre-flight commit scan | always-on scan of the **staged index + working tree** on `git commit`; warn by default, block under a policy `secretGate` | warn/closed |
| Remote allow-list | resolves named/default remotes to a URL and vets host/owner; covers push/fetch/clone/pull/remote/send-pack/http-push | closed on any query error |
| Config-override guards | reject `-c url.*.insteadOf` / `remote.*.pushurl` / `--config-env` / `GIT_CONFIG_*` and `-c alias.*` injection on remote-facing commands | closed |
| Credential redaction | URL userinfo + `Authorization` masked in stored **argv and env** | — |
| Tamper-evident audit | append-only SQLite; each row folds in the prior row's SHA-256 (`prev_hash`/`row_hash`); `git audit --verify` | see below |

## Audit chain: property and limitation

Each audit row's hash folds in the previous row's hash, so **deleting or editing
any row breaks the chain** and `git audit --verify` reports the first broken id.

**Limitation (keyless chain):** the hash is an unkeyed SHA-256. An attacker with
write access to the DB who edits a row can **recompute every subsequent hash**
and present an internally-consistent chain — the tamper is undetectable without
an out-of-band copy of a known-good hash.

**Planned mitigation (H-36, SEC-9):** key the chain with an HMAC so recomputation
requires the key. This is only meaningful if the key is **out of the adversary's
reach**. Given the same-user trust boundary, the intended custody is:
- **machine dir key** (`%ProgramData%\gitc` / `/etc/gitc`, admin-only) → real
  forgery-resistance against a non-admin agent;
- **per-user fallback** when no machine key exists → raises the bar (an attacker
  must find and use the key file) but is not a guarantee against a same-user
  adversary who reads it. The audit log's real anchor against a privileged local
  attacker is **shipping rows off-box** (future work), not local HMAC.

We document this rather than ship a keyed chain that *implies* protection it
cannot provide under the stated trust boundary.

## Known residual gaps (tracked in [BACKLOG.md](BACKLOG.md))

- **SEC-5** — `git svn dcommit` (config-based svn-remote), `git bundle create
  <file>` and `git fast-export` can exfiltrate to a **local file** or a
  non-URL remote that a host allow-list does not model.
- **SEC-6** — a **pre-configured** git alias (`git config alias.p push` then
  `git p`) evades subcommand classification; only command-line `-c alias.*`
  injection is currently blocked.
- **SEC-7** — the secret gate scans the working **tree**, not the exact commit
  range a `push` sends. A secret committed while the gate was off and then
  removed from the worktree can still ship on push. (Being addressed via a
  `git rev-list <remote>..<local>` range scan.)

## Supply-chain integrity

- The managed git backend is installed from an **in-code, SHA-256-pinned**
  manifest and verified before activation.
- `git update` self-update verifies the release asset's SHA-256 (and size)
  against the release `checksums.txt` before the in-place swap.
- **Planned (H-37, SEC-10):** sign `checksums.txt` (minisign/cosign) so the
  manifest itself is authenticated, not just internally consistent.

## Reporting a vulnerability

Report suspected vulnerabilities **privately** — do not open a public issue.
Use GitHub's private security advisory on the `inovacc/gitc` repository
(Security → Report a vulnerability). Include a reproduction and the affected
version (`git gitc version`). We aim to acknowledge within a few business days.
