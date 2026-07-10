# AGENTS.md
<!-- rev:002 -->

Canonical cross-tool agent instructions for **gitc** — a Go CLI that transparently
proxies the real `git` binary (args, stdin/stdout/stderr, exit code) while recording an
append-only, tamper-evident forensic audit trail and enforcing a non-bypassable
machine/org policy (secret gate + remote allowlist). Architecture: `docs/ARCHITECTURE.md`;
decisions: `docs/adr/`.

## Project shape

- **Module:** `github.com/inovacc/gitc`. **Pure Go, `CGO_ENABLED=0`** — no cgo, no C
  toolchain, no libgit2. Single static binary.
- **Command layer:** root `package main` (`main.go`, `gates.go`, `doctor.go`,
  `shell.go`, `backendupdate.go`, `cmdtree.go`, `audit_tui.go`) — flag parsing + dispatch.
  It should stay thin; business logic belongs in `internal/*`.
- **`internal/` packages:** `backend` (resolve/exec the git backend, self-recursion
  guard), `gitwin` (download + sha256-verify + extract the pinned git-for-windows
  MinGit/full), `installer` (PATH-shim install; tiny launcher shims → one canonical
  `gitc.exe`, ADR 0007), `paths`, `policy` (policy.json parsing + gate predicates),
  `settings`, `store` (WAL SQLite audit DB + tamper-evident hash chain), `runner`
  (exec + audit + the enforcement gate hook), `redact` (credential masking),
  `selfupdate` (sha256-verified in-place update), `origin` (sha256-pinned repo URLs),
  `scan` (gitleaks secret detection), `enrich`, `filterrepo` (clean-room
  git-filter-repo port, ADR 0003), `gitargs`, `router`, `shortcut`, `uuidv7`.
- **Backend:** a git-for-windows MinGit/full distribution, sha256-pinned in code and
  auto-provisioned on first use (Windows), or a system git. gitc never reimplements git.
- **Audit storage:** `modernc.org/sqlite` (WAL journal, IMMEDIATE tx) with migrations
  under `internal/store/migrations/` and a per-row hash chain (`git audit --verify`).

## Build / test / lint

Prefer Task (`Taskfile.yml` present):

```bash
task build          # go build ./... (version via -ldflags)
task test           # fast tests
task test:full      # tests + race detector + coverage
task check          # fix + fmt + vet + lint + tests
task shims          # regenerate the embedded Windows launcher shims (needs `zig`)
```

Lint uses **pinned** golangci-lint v2 — run it via `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint run ./...`, not a PATH binary (the pinned version is stricter). Direct Go: `go build ./...`, `go test ./...`, `go vet ./...`.

## Code style

Follow `~/.claude/docs/GO_STYLE.md`. Project-specific:

- All git operations are delegated to the exec backend — never reimplement git
  plumbing/porcelain (the `filterrepo` port is the deliberate, isolated exception).
- The **self-invocation guard** (resolving gitc's own path before searching PATH for a
  backend) is safety-critical — any backend-resolution change needs a test proving it
  can't recurse into itself.
- **Audit writes never block or fail the underlying git command** — a write failure
  degrades to a stderr warning (availability over audit completeness).
- The enforcement gate runs at a single choke point (`runner.execAndAudit`) so
  passthrough and every shortcut step are gated identically — do not add a git-exec
  path that bypasses it.

## Security (this is the product)

- **Enforcement is the goal, not just detection.** `policy.json` (resolved from a
  machine dir — `%ProgramData%\gitc` / `/etc/gitc` — not the agent-relocatable user
  env) drives a secret gate (gitleaks) and a remote allowlist. Gates **fail closed**:
  a malformed/unresolvable/ambiguous state blocks rather than allows.
- **Redaction IS applied** — `internal/redact` masks URL userinfo + Authorization
  tokens in the stored argv *and* env before they reach the audit DB. (This reverses
  the abandoned early "no redaction" design.)
- Downloads (git backend, self-update) and the repo URLs are **sha256-pinned and
  verified**; verification fails closed. The audit DB is owner-only (0600).
- When changing a gate, remote/secret classification, or the audit record, add a
  regression test — the gate's non-bypassability is the whole value proposition.

## PR / commit conventions

Conventional-commit messages (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`). No AI
attribution in trailers. Work on a branch → PR → squash-merge on protected `main`.
Follow the global git-commit rules in the user's `~/.claude/AGENTS.md`.
