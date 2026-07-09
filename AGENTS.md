# AGENTS.md
<!-- rev:001 -->

Canonical cross-tool agent instructions for **gitc** — a Go CLI that transparently
proxies the real `git` binary while recording an append-only forensic audit trail of
every invocation. Full design: `docs/superpowers/specs/2026-07-09-gitc-forensic-git-wrapper-design.md`.

## Project shape

- **Module:** `github.com/dyammarcano/gitc`
- **Layout:** single-binary CLI (`main.go` + `internal/app`, `internal/db`,
  `internal/platform`), built on `github.com/inovacc/mantle` bootstrap.
- **Backends (planned, see design doc):** vendored `git/git` built from source and
  exec'd as the passthrough backend; optional `libgit2`/`git2go` (cgo) for structured
  audit enrichment only — never for passthrough.
- **Audit storage:** SQLite via `sequa`-scaffolded migrations under
  `internal/store/migrations/` (currently empty — schema is an implementation task).

## Build / test / lint

Prefer Task (`Taskfile.yml` present):

```bash
task build          # go build ./... (version-injected via -ldflags)
task test           # fast tests
task test:full      # tests + race detector + coverage
task vet            # go vet ./...
task lint           # golangci-lint run ./...
task check          # fix + fmt + vet + lint + tests
```

Direct Go equivalents: `go build ./...`, `go test ./...`, `go vet ./...`.

## Code style

Follow `~/.claude/docs/GO_STYLE.md` (Uber Go Style Guide + Effective Go). Key points
for this project specifically:

- All actual git operations are delegated to the exec backend — never reimplement
  git plumbing/porcelain logic in Go.
- The self-invocation guard (resolving `gitc`'s own absolute path before searching
  PATH for a backend) is safety-critical — any change to backend resolution needs a
  test proving it can't recurse into itself.
- Audit-log writes must never block or fail the underlying git command (see design
  doc's Error Handling section) — log write failures degrade to a stderr warning.

## Security

- **No redaction by default** — this is a deliberate, documented decision. Raw argv/
  env/output land in the audit DB verbatim, which can include embedded credentials.
  Mitigation is filesystem permissions on the audit DB (0600 / owner-only), not
  application-level scrubbing. Do not add redaction without updating the design doc's
  explicit risk-acceptance note.
- Building `gitc` requires a C toolchain (MSYS2/MinGW-w64 on Windows) for the
  vendored git-from-source build and for cgo-linking libgit2/git2go. Running a
  prebuilt `gitc` binary does not.

## PR / commit conventions

Use conventional-commit-style messages where practical (`feat:`, `fix:`, `docs:`).
No AI attribution in commit trailers. Follow the global git-commit rules in the
user's AGENTS.md (concise, descriptive, no destructive ops without explicit request).
