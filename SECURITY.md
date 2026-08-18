# gitc — local secret-leak lifecycle

`gitc` is a drop-in `git` (git's own C compiled in) with two extra pseudo-commands
that add a **complete, offline, hardened secret-leak lifecycle** on top of git's
own on-disk formats. Everything other than `gitc scan …` / `gitc scrub …` passes
straight through to real git.

```
detect → classify → report → prevent → trace → remediate → verify
 scan   ───────────────────────────────►│         scrub ──────────►
```

Detection is the vendored **betterleaks** engine used **as a library only** — no
CLI, no remote scanners, no live secret validation, no secret-derived network
requests. Detection runs over git's own objects via pure-Rust readers
(`gitindex`/`gitobj`/`gitpack`/`gitwalk`) — no checkout, no subprocess. History
remediation is the vendored **git-filter-repo** port. Library code never calls
`process::exit`; the command surface returns the exit code.

## `gitc scan` — detect (read-only)

| Command | What |
|---|---|
| `gitc scan git [--staged\|--working-tree]` | staged index blobs / working tree |
| `gitc scan git --history [--all-refs]` | all reachable history, introduction-attributed |
| `gitc scan git <commit> \| <A..B> \| <A...B>` | a commit or commit range |
| `gitc scan git --pre-push [--remote <r>]` | only outgoing commits (new leaks) |
| `gitc scan git --trace-finding <fp>` | trace a finding to its introducing commit |
| `gitc scan dir <path>` / `gitc scan stdin` | filesystem tree / piped input |
| `gitc scan known <file>:<line>` | stamp `// gitc:known [v1:<fp>]` (ack only) |
| `gitc scan baseline create [scope]` | write a JSON baseline |
| `gitc scan explain <rule-id>` | a rule's description / regex / keywords |
| `gitc scan hooks <install\|uninstall\|status>` | pre-commit secret-scan hook |
| `gitc scan config <check\|show\|path> [file]` | load + validate a rule config |

Flags: `--report-format human|json|sarif|junit|csv`, `--report-path`, `--config`,
`--confidence`, `--baseline`, `--redact`, `--exit-code`, `--cache` (incremental
per-blob-OID reuse), `--jobs <n>` (bounded parallel history scan, deterministic
order), `--max-target-megabytes`, `--max-total-megabytes`, `--max-decode-depth`,
`--follow-symlinks`.

### Suppression vs. acknowledgement (§26/§27)

- **Suppress** (hide the finding): inline `betterleaks:allow` / `gitleaks:allow`,
  the config allowlist, `.betterleaksignore` / `.gitleaksignore`, and `--baseline`.
- **Acknowledge only** (finding is still reported): `gitc:known [v1:<fp>]`.

Finding identities are stable canonical fingerprints `[commit:]file:rule:line`.

## `gitc scrub` — remediate (destructive)

| Command | What |
|---|---|
| `gitc scrub plan [<fp>] [--output plan.json]` | inspectable, serializable rewrite plan |
| `gitc scrub secret [<fingerprint>]` | redact every detected secret, or one by id |
| `gitc scrub path <glob>...` | remove matching paths from all history |
| `gitc scrub blob <oid>...` | remove path(s) carrying a blob object |
| `gitc scrub replace <from>=<to>... \| --replace-file <f>` | redact literal / rules text |
| `gitc scrub rollback` | restore refs+objects from the latest backup |
| `gitc scrub cleanup [--prune-backups]` | expire reflogs + gc old object bytes |

Scope (default: all refs — a secret left on any ref stays reachable): `--all-refs`,
`--branch <b>`, `--branches`, `--tags`, `--ref <r>`, `--exclude-ref <r>`. Safety:
`--plan`, `--dry-run`, `--force`, `--no-backup`, `--strip-invalid-signatures`.

Every rewrite is fenced by preconditions (clean tree unless `--force`; filter-repo
fresh-clone check), an all-objects `git bundle` + ref-snapshot backup under
`<git-dir>/gitc-scrub/`, a signature-invalidation warning (§12), and — for
`scrub secret` — post-rewrite verification across **every ref** that fails
(exit 4) and names any residual refs. Remediation targets and logs use
fingerprints/hashes, never raw secrets. `gitc` never force-pushes; it prints the
push guidance and reminds you that repository remediation is not credential
rotation.

## Exit codes (stable — §46)

```
0  clean / successful operation
1  findings
2  usage / configuration error
3  scanner / runtime error
4  remediation verification failed
5  rewrite safety precondition failed
```

## Hardening

Resource bounds (per-blob, whole-scan, decode depth, walk depth) are enforced and
configurable; symlinks are not followed unless asked, and a depth cap defeats
symlink loops. The git object/index/tree/commit parsers and the detector are
covered by a deterministic fuzz corpus asserting **no panic on hostile bytes**
(malformed loose objects, garbage packs, truncated trees, decoder-amplification
input). Parallel scans share one atomic byte budget with no unbounded queues, and
scans/rewrites are cancellation-safe (a scan mutates no state; a rewrite updates
refs only after the rewritten graph is imported).

Build: `cargo zigbuild --release --target x86_64-pc-windows-gnu` (see `README.md`).
The library, `scan`, and `scrub` all build/test on any host; only the git-FFI
binary requires the GNU target.
