# PORT-TRACK — betterleaks → betterleaks-rs

Durable ledger. One line per module. Resume at the first module not `verified`.

**Scope (operator, 2026-08-14): EVERYTHING — 1:1 full repo.** The earlier
"suite end-to-end test on one leaf module (`internal/sigv4`)" scope is
SUPERSEDED. The dependency-ordered wave plan for the ~19,250 remaining Go LOC is
in [`PORT-PLAN.md`](PORT-PLAN.md).

## Drift status — RESOLVED 2026-08-14

Manifest is re-anchored from `0b4063d7` to **`6cf4f1a2`** (the current source
HEAD) and every module re-hashed: **22 UP-TO-DATE, 0 DRIFTED.**

The drift was real and SEMANTIC, not cosmetic. Upstream renamed the whole
"required" vocabulary to "component" and extended it:

| Go, before | Go, after |
|---|---|
| `Finding.RequiredSets []RequiredSet` | `ComponentSets []ComponentSet` |
| `RequiredSet` / `RequiredFinding` | `ComponentSet` / `ComponentFinding` |
| `BuildRequiredSets` / `maxRequiredSets` | `BuildComponentSets` / `maxComponentSets` |
| `config.Rule.RequiredRules []*Required` | `Components []*Component` |
| `Required{WithinLines, WithinColumns}` | `Component{Optional bool, Within string}` |

**This is a WIRE change** — the emitted JSON key is now `ComponentSets` — plus
two behavioural additions: `ComponentFinding` gained `Optional bool` (declared
with NO tag, so it is emitted even when false, in second position), and `Redact`
now also masks a component's own `Line` and every `CaptureGroups` value.
`config.Rule` additionally gained `Confidence`, and its `Validate()` now parses
`component.Within` through `contextwindow.Parse` — the module ported in Wave 1.

What was done:

- **`report.finding` re-ported.** The rename applied across `finding.rs`,
  `json.rs` and the `lib.rs` re-export; `optional` added in Go's field position;
  `redact` extended to component `line` + capture groups. The `json.rs`
  differential golden was **RE-CAPTURED by marshalling the equivalent Finding
  through the current Go source**, not hand-edited — it now carries
  `"ComponentSets"` and `"Optional":false`. The new Go assertions were ported
  too (component line/capture-group masking, an `Optional: true` component, and
  Go's `assert.NotContains(parsed, "RequiredSets")`). **28 tests green**; Go
  baseline `go test ./report/` → ok.
- **`config.rule` needed no code change.** The ported crate is a two-field
  subset (`rule_id`, `description`) and the diff leaves both untouched — the new
  `Confidence` and `Components` fields are outside the subset. Re-signed with a
  note; the full struct remains M9 (`config.full`).
- **`validate.pool`** re-hashed; still EXCLUDED (blocked on `exprruntime`,
  `sources`, `singleflight`), so no ported code was affected.

Both `report.finding` and `config.rule` are `verified` again, and the marks are
now trustworthy: the mutation runs below show the assertions can fail.

## Wave 1 (2026-08-14) — leaf modules

- version: **tests-ported | code-ported | VERIFIED**. 3 tests green
  (`cargo test -p version`). Go `version/version.go` has NO test file, so these
  are characterization tests: the unstamped `"dev"` defaults, the source's own
  stated invariant ("these two gotta be the same"), and `GITLEAKS_COMPAT`
  pinned byte-for-byte at `"8.25.0"`. Zero dependencies.
  **Reshape (flagged):** Go's `DefaultMsg`/`Version` are package `var`s so a
  release can overwrite them via `-ldflags -X`. Rust has no link-time string
  injection → `option_env!("BETTERLEAKS_VERSION"/"BETTERLEAKS_DEFAULT_MSG")`
  read at COMPILE time, defaulting to `"dev"`. The two default-assertion tests
  self-skip when a version IS stamped, so a real release build stays green.

- color: **tests-ported | code-ported | VERIFIED**. 11 tests green
  (`cargo test -p color`). Go `internal/color` has NO test file → all
  characterization, read off `color.go`.
  **std-first win: `go-isatty` REPLACED BY STD** — `std::io::IsTerminal`
  (stable 1.70). Zero dependencies added.
  **Deviation (flagged):** Go caches
  `isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)`; Rust std has no
  `IsCygwinTerminal`, so under a Cygwin/MSYS pty Go colorizes and this port does
  not. Everything else is 1:1.
  **Reshape:** Go's `isTTY` package var makes the colorizing branch unreachable
  under `go test`; the port splits a private `render_with_tty(text, tty)` so BOTH
  branches are tested (code ORDER bold`1`;italic`3`;fg, the `len(codes)==0`
  passthrough, and the empty-`fg` skip).
  **Quirk preserved:** Go slices `hex[0:2]` by BYTES and discards ParseUint's
  error, so a 6-BYTE/5-char input like `"é05c0"` yields `38;2;0;5;192` rather
  than panicking — the port works on `as_bytes()` for exactly this reason (a
  naive `&hex[0..2]` would panic mid-rune). Test:
  `hex_to_ansi_multibyte_does_not_panic`.

- confidence: **tests-ported | code-ported | VERIFIED** (parity: PASS). 7 tests
  green (`cargo test -p confidence`); Go baseline
  `go test ./internal/confidence/` → **ok**. Ports the 5-case `TestMeets` table
  and the `Parse(" HIGH ")`/`Parse("certain")` assertions verbatim, plus
  characterization for the full 4×4 `meets` matrix, `valid`'s exact-three-levels
  case sensitivity, `Parse("")`, and the error text. Zero dependencies.
  **Detail preserved:** `Parse` trims THEN lowercases before validating, so the
  error carries the NORMALIZED value — `Parse("  CERTAIN  ")` reports
  `invalid confidence "certain" …`, not the raw input.
  **Approximation (flagged):** Go's `%q` verb → a hand-rolled `go_quote`
  covering ASCII printables, the seven single-letter escapes, `\"`/`\\` and
  `\xHH`. Go additionally renders non-printable NON-ASCII as `\uXXXX`; that path
  is unreachable here (the value is already trimmed+lowercased) but is a known
  gap, not claimed parity.

- ahocorasick: **tests-ported | code-ported | VERIFIED** (parity: PASS). 10 tests
  green (`cargo test -p ahocorasick`); Go baseline
  `go test ./internal/ahocorasick/` → **ok**. Zero dependencies.
  **The bespoke matcher was PORTED, not swapped for the `aho-corasick` crate** —
  per PORT-PLAN §2: the API is `Compile(patterns, foldASCII)` + `Visit(text, fn)`
  with an early-abort contract (`fn` returning false stops traversal mid-scan)
  the crate does not reproduce, and the source-offset bookkeeping for runes that
  fold to ASCII is specific to this design. Ports all 4 Go tests (`TestVisit`
  overlapping+ordering, `TestVisitUnicodeSimpleFoldOffsets`,
  `TestVisitStableIDsAndStop`, `TestVisitConcurrent` via `thread::scope`).
  **DIFFERENTIAL GOLDEN — `unicode.SimpleFold`.** Rust std has NO `SimpleFold`,
  and approximating it with `to_lowercase`/`to_uppercase` gets `U+0130`/`U+0131`
  wrong. Instead the Go source's own `foldRuneASCII` was swept over EVERY valid
  rune (`.scripts/05-B_gen_fold_golden.ps1`), yielding exactly TWO non-ASCII
  runes with an ASCII fold: **`U+017F ſ→s`** and **`U+212A K→k`**. The port
  encodes that set directly; `fold_rune_ascii_matches_go_golden` asserts both,
  plus 7 near-miss runes that a naive approximation would get wrong.
  **Not ported (flagged):** `TestVisitASCIIAllocations` uses
  `testing.AllocsPerRun`; Rust std has no equivalent. The structural property is
  preserved (128-entry STACK ring, heap only when a pattern exceeds it, mirroring
  Go's `localStarts [128]int`) but is UNASSERTED.
  **Determinism note:** Go seeds the BFS from a `map` (randomized order); output
  order per state is still deterministic because a failure state is always at a
  shallower depth and is processed first. The port uses a `BTreeMap` so the build
  is deterministic outright.

- logging: **tests-ported | code-ported | VERIFIED**. 10 tests green
  (`cargo test -p logging`). Go `logging/log.go` has NO test file → all
  characterization. Zero dependencies.
  **Reshape (flagged):** Go wraps `github.com/rs/zerolog`. `tracing` + a
  subscriber would be a large ecosystem dependency for a 39-line stderr writer
  that no test asserts, so the port hand-rolls the equivalent: same levels, same
  `InfoLevel` default gating, same stderr destination, and — because ~279
  downstream call sites depend on it — the same FLUENT API
  (`trace/debug/info/warn/error/err/fatal/panic` → `Event` →
  `.str/.int/.err/.msg/.send`). Call-site survey: `Msg` 138, `Err` 114, `Str` 79,
  `Msgf` 51, `Send` 13, `Int` 8, `Int64` 4.
  **Quirk preserved:** the Go source comment says *"send all logs to stdout"* but
  the code writes to `os.Stderr`. The CODE is the behaviour — this port writes to
  stderr.
  **Terminal semantics preserved:** `Fatal` writes then `std::process::exit(1)`;
  `Panic` writes then panics.
  **Approximated (flagged):** zerolog's exact ConsoleWriter layout (colour codes,
  timestamp, field alignment) is NOT byte-reproduced; the shape is
  `<TAG> <message> key=value…`. Nothing observable depends on it.
  **Known duplication:** a UTC timestamp helper is deliberately NOT added here to
  avoid a `logging → sigv4` dependency; if a third crate needs one, extract a
  shared `timeutil` crate rather than copying it twice.

- regexp: **tests-ported | code-ported | VERIFIED** (parity: PASS). 10 tests green
  (`cargo test -p regexp`); Go baseline `go test ./regexp/` → **ok**. Ports the
  FACADE, which is the point of the module: lazy compilation (`Compile` validates
  and records the capture count but builds no program until first use) and a
  swappable engine. All three Go tests ported — `TestCompileIsLazy` (metadata
  access must not compile; a second match must not recompile),
  `TestLazyCompileFailureDoesNotPanic` (every accessor degrades to a zero value,
  and `ReplaceAllString` returns the SOURCE unchanged), and
  `TestCompileReturnsLazyCompileError`.
  **Dependencies — 2 JUSTIFIED:** `regex` (std has no regex at all; RE2 lineage
  matches Go's semantics, since `regexp.go:96` gates every pattern through
  `syntax.Parse(str, syntax.Perl)` and `:88` defaults to the stdlib engine, so no
  lookaround/backreference is reachable — `fancy-regex` was REJECTED as it would
  accept patterns Go rejects); `regex-syntax` (Go records `parsed.MaxCap()`
  WITHOUT compiling, and `TestCompileIsLazy` asserts exactly that, so counting
  capture groups needs a parser separate from the compiled engine).
  **Harness adaptation (flagged):** Go runs a package's tests SEQUENTIALLY, so its
  `SetEngine`/`defer SetEngine(previous)` is safe. Rust runs tests in parallel
  THREADS and the engine is process-global, so every test takes one `serial()`
  lock. That restores Go's semantics; it is not a behaviour change.
  **Carried forward, NOT solved here:** Go's `\w`/`\d`/`\s`/`\b` are ASCII and
  Rust's are Unicode. This crate does NOT silently rewrite patterns — that
  decision belongs to M9, which owns the rule catalogue (PORT-PLAN §7).

- contextwindow: **tests-ported | code-ported | VERIFIED** (parity: PASS). 7 tests
  green (`cargo test -p contextwindow`); Go baseline
  `go test ./internal/contextwindow/` → **ok**. All four Go test functions ported
  table-for-table, including both `Extract` fixtures with their exact expected
  strings. Zero dependencies: the Go source imports stdlib `regexp` for ONE
  anchored token pattern `(?i)^([+-]?)(\d+)([CL]?)$`, hand-rolled here rather than
  pulling a regex engine into a leaf crate.
  **Byte semantics preserved:** column clipping is defined in BYTES, so a
  multibyte character can land inside a clip window. Go slices bytes and never
  panics; `&str` slicing would. The core is `extract_bytes(&[u8]) -> Vec<u8>` and
  `extract` is a `&str` convenience.
  **Deviation (flagged):** where Go would return a string holding invalid UTF-8
  (a clip that split a character), `extract` substitutes U+FFFD — Go's string
  permits arbitrary bytes, Rust's `String` does not. Use `extract_bytes` for the
  faithful bytes.
  **Falsified, not assumed:** these tests passed on their FIRST run, so their
  failure had never been observed. Two mutations — removing the `10L` = 10-lines-
  TOTAL decrement, and removing the show-short-lines-in-full rule — each turned
  the suite red, and restoring returned it to green.
  This module is on the critical path: `config.Rule.Validate()` now parses a
  component's `Within` field through `contextwindow.Parse`.

**Wave 1 COMPLETE** — all 7 leaves ported and verified.

## Wave 5 — in progress (2026-08-14)

- scm: **code-ported | VERIFIED** (parity: PASS). 23 tests green
  (`cargo test -p scm`); Go baseline `go test ./sources/scm/` → **ok**. Ports
  `scm.go` (the platform enum) and `clone.go` (the shared clone helper). Zero
  dependencies beyond the regex facade.
  **`git` is a SUBPROCESS, not a library — and that is a security design, not an
  accident.** The token is injected as a temporary git config entry through
  `GIT_CONFIG_*` environment variables, so it never touches the remote URL or
  argv (which is world-readable on most systems). `GIT_CONFIG_GLOBAL`/`SYSTEM`
  point at the null device so the clone cannot pick up ambient credentials or
  URL rewrites, and `GIT_TERMINAL_PROMPT=0` stops it blocking on a prompt.
  Substituting `git2`/`gix` would replace all of that with different credential
  handling — a rewrite, not a port.
  **Vacuous test caught and fixed:** the first `token_never_appears_in_argv`
  never passed a token to the function under test, so it could not fail. It now
  drives the same path `clone_authed` does and asserts BOTH halves — absent from
  argv, present in the environment.
  Hand-rolled with no crates: base64 (pinned against RFC 4648 vectors) and Go's
  `url.QueryEscape`, matching the `codec` precedent.

- sources.file: **code-ported | VERIFIED**. 23 tests green (`cargo test -p
  sources`, 11 core + 12 file). Ports `file.go`'s chunked read path plus
  `readUntilSafeBoundary` from `common.go`.
  **A REAL BUG, found by mutation testing.** The first version of
  `read_until_safe_boundary` only INSPECTED the bytes already buffered, where Go
  READS MORE from the reader. That made the boundary hunt inert: a secret
  straddling the 100 kB chunk boundary would still be sliced in half — and the
  failure is SILENT, because a split secret simply never matches and nothing
  reports it was missed. Mutation testing exposed it: removing the carry-over
  changed no test result, because there never was any carry-over. Fixed to grow
  the chunk from the reader, and covered by
  `token_straddling_the_buffer_boundary_survives_intact`, which was then
  falsified — disabling the read-ahead fails that exact assertion.
  Ported quirks: a `\r`/space/tab does NOT reset the consecutive-newline count
  (so `\n \n` still counts as a blank line); the `MAX_PEEK_SIZE` cap is measured
  from the ORIGINAL read length, not from zero; EOF stops the hunt rather than
  erroring; `start_line` accumulates across chunks; paths are slash-normalised
  on Windows.
  **DEFERRED — archive descent.** Go asks `mholt/archives` whether content is an
  archive or compressed stream and descends into it. PORT-PLAN records that no
  single Rust crate covers that format set (zip, tar, gzip, xz, zstd, bzip2, 7z,
  brotli, lz4, rar — eight-plus crates assembled by hand). `max_archive_depth`
  exists and gates the descent at 0, so enabling it later is additive.
  **Deviation (flagged):** the binary check uses git's NUL-byte heuristic rather
  than `h2non/filetype`'s magic-byte MIME sniff. They agree on the cases that
  matter (executables, images, objects all carry NULs early) but differ on
  NUL-free binary formats. Revisit with `infer` when archives land, since that
  path needs real type detection anyway.

- sources.files + sources.stdin: **code-ported | VERIFIED**. 36 sources tests
  green (11 core + 12 file + 13 files/stdin). Ports the directory walk, the
  size/empty/symlink rules, and the stdin source. Zero dependencies.
  **`fastwalk` is NOT a dependency, and that is faithful.** Go uses it purely as
  a fast walker, then spends a comment restoring `filepath.WalkDir`'s exact path
  semantics ("fastwalk joins paths by concatenating … which leaves lexical
  elements such as `./`"). The observable contract is WalkDir's, which std
  recursion reproduces directly.
  **Concurrency reshape (flagged):** Go walks concurrently and scans through a
  `semgroup` pool, but serialises the yield callback behind a mutex — so the
  OBSERVABLE order is already serial. This port is serial throughout: same
  behaviour, lower throughput. Parallelism is a performance property here, not a
  semantic one.
  Ported rules: an empty file is skipped before opening; `max_file_size` 0 means
  UNLIMITED (not "skip everything"); a skipped DIRECTORY is pruned with all its
  descendants (Go's `filepath.SkipDir`) while a skipped file only drops itself;
  a symlink to a directory is skipped rather than descended; the Windows
  forward-slash retry (gitleaks#1641) is preserved. Walk order is SORTED — an
  improvement over Go's filesystem order, pinned so a scan is reproducible.
  `Stdin` merges caller attributes BEFORE skip filtering, so a supplied path
  participates in the decision.

- httpclient: **code-ported | VERIFIED** (parity: PASS). **30 tests green**;
  Go baseline `go test ./internal/httpclient/` → **ok**. **Zero dependencies.**
  **What is ported is the POLICY, and the I/O is a seam.** Go's package is
  transport middleware — retry decisions, exponential backoff with jitter,
  `Retry-After` parsing, rate-limit accounting, idempotency, and host-scoped
  auth. All of that is pure logic over status codes, headers and time, and it is
  where the behaviour worth testing lives. `RoundTripper` stands in for
  `http.RoundTripper`, the same seam pattern `exprruntime` uses for the
  tokenizer.
  **The HTTP crate choice is deliberately NOT made here.** `ureq` (blocking) vs
  `reqwest` (async) has async blast radius across every remote source; nothing
  in this crate forces it, and a future choice plugs into the trait without
  reshaping. Time is passed IN rather than read from the clock, so every
  decision is deterministic — Go threads `now time.Time` for the same reason.
  Security-critical behaviour, tested hardest: an EMPTY allowlist authenticates
  NOTHING; hosts are compared case- and port-insensitively; a lookalike host
  (`api.github.com.evil.test`) does not match; a caller-set `Authorization` is
  never overwritten. Attaching a credential to the wrong host is a leak whose
  failure mode is silent.
  Ported quirks: an explicit `Retry-After` beats the status default and makes a
  normally-non-retryable 4xx retryable; 429/503 default to a flat 60s; a
  past-dated `Retry-After` yields zero, not a negative wait; cancellation is
  never retried; POST/PATCH are deliberately absent from the idempotent set;
  backoff CLAMPS instead of overflowing at large attempt counts.
  **Narrowing (flagged):** `parse_http_date` implements only the IMF-fixdate
  form that RFC 7231 requires senders to use. The two obsolete forms return
  `None`, which callers treat as "no Retry-After" and fall back to the
  status-based default — a safe degradation rather than a misparse.

- gitdiff: **code-ported | VERIFIED**. 25 tests green (19 unit + 6 against real
  output). Ports the slice of the `gitleaks/go-gitdiff` FORK the git source
  consumes. Not a crate: Go depends on a fork, so no upstream crate is a drop-in
  by definition, and PORT-PLAN flagged the Rust `patch` crate for that reason.
  Zero dependencies.
  **`Raw(OpAdd)` is the load-bearing behaviour** — only ADDED lines are scanned.
  Including deletes would report every secret ever removed; including context
  would re-report the same secret on every later commit; missing adds would
  report nothing at all. All three directions are covered.
  **Validated against REAL `git log -p` output**, not only hand-written
  fixtures: a captured 541 KB / 3-commit / 279-file / 989-hunk stream. The
  strongest assertion counts `+` lines in the raw fixture with an independent
  method and requires the parser to reproduce that count exactly, so silently
  dropping a file or hunk fails rather than looking healthy.
  Two bugs found and fixed while porting: blank lines inside a commit message
  were dropped (git does not pad a paragraph break to four spaces), and one of
  my own tests miscounted a `@@ -10,4 +10,4 @@` hunk as 3 lines when the header
  says 4.

- sources.git: **code-ported | VERIFIED**. 64 sources tests green.
  **The Go source has NO tests for this module** — `sources/git_test.go` is 100%
  commented out with a note that it was flaky. So these are CHARACTERIZATION
  tests, and the pure helpers (argument construction, the `--log-opts`
  tokenizer, the stderr classifier, remote-URL normalisation, date
  normalisation) carry the parity contract because they can be pinned without a
  live repository. The last test builds a REAL repository, commits a
  live-format AWS key and reads it back through `git log -p`.

  **⚠ A REAL UPSTREAM DEFECT, FIXED RATHER THAN PORTED — Go betterleaks cannot
  scan git history on Windows, and reports the failure as a clean result.**
  Go's `gitConfigIsolationEnv` sets `GIT_CONFIG_GLOBAL=NUL` on Windows. Git for
  Windows is MSYS2-based and rejects it. Measured, git 2.55:

  ```
  GIT_CONFIG_GLOBAL=NUL git -C repo log -p   →  fatal: unable to access 'NUL':
                                                Invalid argument   (exit 128)
  ```

  Running the **Go binary** against a repo containing `AKIA<16 base32 chars>`:

  ```
  ERR failed to scan Git repository error="git stderr: fatal: unable to access 'NUL'"
  WRN scanned ~0 bytes (0)
  WRN no leaks found in partial scan
  ```

  Zero bytes scanned, reported as "no leaks found" — FAILURE-REPORTED-AS-SUCCESS
  (Failure Catalogue class 1) in the upstream tool. My port reproduced it
  faithfully at first and the real-repository test caught it. Fixed at the root
  layer (`scm::git_clone_env`, which both the clone path and the scan path use)
  by using `/dev/null` on every platform — what git itself documents, and
  measured working here. Guarded by
  `the_isolation_environment_does_not_break_git`, **falsified**: restoring the Go
  value makes it fail with the exact `unable to access 'NUL'` message, and the
  end-to-end repository test fails with it too.

  Deviations, all deliberate: **serial** where Go fans out over a
  `semgroup.Group` (same fragment set, lower throughput); **buffered** where Go
  streams git's stdout into an incremental parser (a real memory cost on a large
  history, and it means a fatal git error surfaces AFTER the fragments git did
  emit rather than aborting mid-stream); **binaries skipped** because Go's
  archive descent via `git cat-file` is deferred with the rest of archive
  support — a MISSED-FINDING gap (a secret inside a committed `.zip`), never a
  false positive.
  Ported quirks: `-U0` (zero context) is what attributes a secret to the commit
  that introduced it instead of re-reporting it as context forever; user
  `--log-opts` REPLACE the default `--full-history --all` range rather than
  extending it; a standalone empty quoted token (`''`) is dropped; the prefilter
  sits INSIDE the commit-header branch, so a headerless `git diff` is never
  prefiltered; a hunk with no additions still yields an empty fragment.
  Hand-rolled, no crates: `filepath.Clean` (its edge rules are load-bearing — a
  leading `..` survives, a rooted `..` is dropped) and RFC 3339 UTC date
  normalisation via `days_from_civil`/`civil_from_days`, covered for leap years
  and for offsets that roll the day and the year over. A date crate would be a
  dependency for one fixed format that git's own isolation env pins.
  **Security-critical:** userinfo is stripped from the remote URL, so a remote
  configured as `https://user:ghp_TOKEN@host/...` cannot carry that token into a
  finding link — the leak scanner must not become the leak.

- cli (`betterleaks-rs` binary): **code-ported | PARTIAL — see the differential
  below.** 25 tests green. **The workspace now produces an EXECUTABLE.** Until
  this module every crate was verified by its own tests and nothing had ever run
  against a real repository from a real command line.
  Ports the scan path of Go's `cmd`: the flag contract (names + defaults cited to
  `cmd/root.go`), detector wiring, report emission, and the EXIT-CODE contract
  from `findingSummaryAndExit` — error → 1, findings → `--exit-code` (default 1),
  clean → 0, with the error outranking findings so a FAILED scan can never exit 0
  for having found nothing.
  Zero third-party crates: argument parsing is hand-rolled, because what is
  ported is cobra's BEHAVIOUR, not its API. `clap` is the right call if full
  cobra parity (help trees, completions) is ever ported.
  `bytes_convert` was corrected against the Go binary's own output: `0` has no
  unit, the sub-kilobyte unit is the word `bytes`, `KB`/`MB`/`GB` are uppercase
  and decimal, a trailing `.00` is trimmed, and there is no TB tier.
  Also ported here: `.betterleaksignore` / `.gitleaksignore` support
  (`AddGitleaksIgnore` + the `AddFinding` check) with Go's three additive
  discovery sites, and `Detector::should_skip` (Go's `SkipFunc`) wiring the
  catalogue's GLOBAL PREFILTER into both sources — without it a scan reads
  images, binaries, `vendor/`, `node_modules/` and lockfiles it should skip.
  Not ported and SAID to be absent rather than stubbed: the remote sources
  (blocked on the HTTP-crate decision), baselines, validation, diagnostics, and
  the `template` report format (which is REFUSED with an error rather than
  silently emitting a different format).

### Differential vs the Go binary

Run on real corpora, both binaries, same inputs.

| Case | Go | Rust | Verdict |
|---|---|---|---|
| One file (`cmd/generate/config/rules/1password.go`) | 8 findings, 6,624 B | 8 findings, 6,624 B | **EXACT** — same rules, lines, fingerprints |
| Small dir, one AWS key | 1 × `generic-api-key`, entropy 4.121928, 51 B, exit 1 | identical to 6 dp | **EXACT** |
| **Whole betterleaks tree (3.47 MB)** | 1 finding | 1 finding | **EXACT — `ONLY-GO=0 ONLY-RS=0`** |
| `git` scan of a real repo | **0 bytes, "no leaks found"** | 31 B, finds the key | **Rust is CORRECT, Go is broken on Windows** |

The whole-tree case reached parity only after `config.allowlist` +
`config.extend` + config auto-discovery were ported (below); it read 559 findings
before.

**The byte counter now matches too — and the earlier explanation for it was
WRONG.** It read Go 3,474,939 vs Rust 1,496,615, and this ledger attributed the
gap to prefilter placement. It was ARCHIVES: Go descends into the repository's
`.zip`/`.tar.gz` testdata and this port skipped them. After `sources.archive`
landed the counts are 3,474,939 vs **3,475,408** — 469 bytes apart, with the
finding sets still identical. The residual is small and unexplained; the likely
causes are the formats this port still refuses (7z / rar / bz2 / xz) and
boundary-read differences. Recorded as open rather than rationalised.

- config.allowlist + config.extend + config discovery: **code-ported |
  VERIFIED**. 35 config tests + 28 cli tests green.
  **This is what closed the whole-tree differential: 559 findings → 1, matching
  the Go binary exactly.**
  Ports `allowlist.go` and `translate_filters.go`. Allowlists are not evaluated
  directly — Go TRANSLATES them into the same filter-expression language
  everything else uses, so there is one evaluator rather than two subtly
  different ones. The prefilter/filter split is the load-bearing part: `paths`
  and `commits` are ATTRIBUTE-only and can suppress a fragment before any regex
  runs, while `regexes` and `stopwords` need a finding and must wait. An AND
  allowlist stays ENTIRELY in the filter, because promoting its path half to the
  prefilter would suppress fragments the AND was never meant to reach.
  Also ports `[extend]` (`useDefault` / `path`, `disabledRules`, the field-merge
  rules, `maxExtendDepth = 2`) and Go's five-step config precedence
  (`cmd/root.go:39-44`), of which step 4 — a config found INSIDE the scan target
  — is the one that silently changes results.
  **Falsified.** Disabling step 4 makes
  `a_config_in_the_scan_target_is_discovered_and_applied` fail with
  `must suppress it, got ["generic-api-key"]` AND regresses the corpus scan from
  1 finding to 559; restoring it returns both.

  **This corrects an earlier ledger claim, and the reasoning error is worth
  keeping.** `config`'s note justified deferring allowlists because "the shipped
  catalogue contains zero allowlists" — measured, true, and beside the point.
  Allowlists are what USER configs are made of, and `[extend] useDefault` is how
  a user config reaches the catalogue at all. *Unused by the default config* is
  not *unused*. The same error was nearly repeated for `Extend`, deferred in the
  same sentence for the same reason.

- transport (+ **the HTTP crate decision, finally made**): **code-ported |
  VERIFIED**. 15 tests green.
  **`ureq` (blocking), not `reqwest` (async).** The reason is architectural, not
  taste: every ported source is synchronous — `Source::fragments` is a sync
  trait and there is no async runtime in the workspace — so reqwest would mean
  introducing a runtime and reshaping every source signature. That is a rewrite,
  not a port.
  It lives in a SEPARATE crate so `httpclient`, where the retry/backoff/auth
  POLICY lives and is tested, stays free of I/O and of dependencies. Swapping
  the HTTP crate later touches this crate only.
  **Three bugs in my first retry loop, all found by reading Go's loop rather
  than assuming**, and all now covered by exact-duration tests:
  1. an explicit `Retry-After` was `max`-ed with computed backoff; Go REPLACES
     ("Explicit waits bypass jitter/backoff"). Taking the larger ignores a
     server that said "come back in 1s".
  2. the idempotency check gated retryable STATUSES as well as network errors.
     Go gates network errors only — a 503 means the server did NOT process the
     request, so replaying a POST is safe, and refusing abandons a request the
     server asked us to repeat.
  3. `max_retries` was read as an attempt count; Go loops `attempt <=
     MaxRetries`, so 5 permits SIX round trips.
  The sleeper and the clock are INJECTED, as Go injects `t.Sleep`/`t.Now`. That
  is what makes the exact waits assertable — and without it the suite took
  **120 seconds**, because a bare 503 legitimately asks for 60.

- remote.s3: **code-ported | VERIFIED**. 52 tests green.
  Ports `sources/s3.go`. The bulk is URL PARSING, and it earns the attention:
  one target URL must yield host, bucket, prefix, signing region and addressing
  style across AWS (four spellings incl. `dualstack` and dotted bucket names),
  Cloudflare R2 (two) and any generic endpoint. A misparse surfaces as a
  signature mismatch or a 404, neither of which names the cause. Accelerate and
  FIPS endpoints are REFUSED with a message naming the working form, as in Go.
  The scan loop sits behind an `Objects` trait, so pagination, per-object
  skipping, prefiltering and per-bucket error tolerance are tested without a
  network or a credential — including that one AccessDenied bucket does not
  abandon the account, while failing to list the account IS fatal.
  **A real divergence found and fixed:** Go's `XMLName` field makes
  `encoding/xml` reject a document whose root element is wrong; serde has no
  equivalent, so an S3 `<Error>` body deserialised as a page with ZERO objects
  and the bucket would have been reported clean. Now checked explicitly
  (`expected element type <ListBucketResult> but have <Error>`). That is the
  failure-reported-as-success shape again — third instance this port.
  `quick-xml` added (serialization format → use a library, per the rubric).
  Credentials fail LOUDLY when nothing resolves, rather than falling back to
  anonymous: the fallback would turn "your credentials are wrong" into "this
  bucket appears to be empty", which is the same shape as a clean scan.
  Go's `path.Match` is hand-ported rather than delegated to a glob crate — `*`
  must not cross `/`, `[^…]` negation must work, and a MALFORMED pattern must
  ERROR rather than silently match nothing.
  Deviation: serial where Go fans out over 16 workers; same objects, same
  findings, lower throughput.

- remote.github: **code-ported | PARTIAL, and the gap is ENFORCED.** 107 remote
  tests green.
  **Implemented:** `repos` (clone + git-history scan, the default and the
  highest-value path), `forks`, `releases`, `release-assets`, `gists`, owner
  enumeration with Link-header pagination, exclusion globs, date windowing, the
  GitHub-specific rate-limit policy, GHE host handling — plus the **GraphQL
  family**: `issues`, `prs` and both comment kinds, including PR REVIEW THREADS.
  **Not implemented:** `actions` / `action-artifacts` and `discussions`.

  On the GraphQL surface (`github_gql.rs`): people paste credentials into PR
  descriptions and review comments far more casually than into committed code,
  because a comment feels ephemeral — it is public and permanent. Go builds its
  queries from `githubv4` struct tags; with no Rust equivalent they are written
  as literal GraphQL, which is what that library generates anyway and is more
  readable for it. A test asserts the query REQUESTS every field the parser
  reads, because a drift there yields a successful request, no findings, and a
  repository that looks clean.
  Ported carefully: issues and PRs are fetched in ONE query (GitHub scores its
  GraphQL limit per query, not per node) but page INDEPENDENTLY; both
  connections are `CREATED_AT DESC`, which is what lets `--since` terminate the
  walk; a comment tail is followed to the end, or an issue with more than 25
  comments is scanned only as far as the first page; review-thread comments are
  a SEPARATE connection from a PR's issue-style comments; a comment with no URL
  of its own inherits its parent's; `hasNextPage` is only honoured WITH a
  cursor, since `true` plus an empty cursor would re-request page one forever;
  and a **GraphQL 200 carrying an `errors` array is treated as the failure it
  is**, because reading it as success gives empty data and a clean report.
  **The unimplemented ones are REFUSED BY NAME at validate, not skipped.** A
  resource that is silently skipped scans nothing and reports clean — the
  failure-reported-as-success shape this port has already hit three times.
  `github.com/o/r/pull/1` therefore fails with a message saying so, rather than
  appearing to scan a pull request it cannot read. `Api::graphql` likewise
  returns an error instead of an empty result.
  Ported with care: the **403 ambiguity** — GitHub signals an exhausted rate
  limit with a bare `403`, indistinguishable from a permissions failure unless
  `X-RateLimit-Remaining: 0` is read. Treat it as permanent and a scan stops
  early and reports clean; treat every 403 as throttling and a real permissions
  error retries forever. Both directions are tested.
  Also: **`next_link`**, because missing it scans only the first page of every
  list and reports the rest clean; **`in_date_range`'s `terminate` flag**,
  because GitHub returns newest-first and without it "the last week" walks the
  entire history; **truncated gist files**, which must be re-fetched from
  `raw_url` or everything past ~1 MB is silently unscanned; and **token
  scoping**, so a release-asset URL pointing at a third-party CDN cannot receive
  the credential.
  A cloned mirror is removed whether or not the scan succeeded — otherwise every
  scanned repository, and the secrets just found in it, stay in the temp dir.
  `retry_decider` is pluggable on `RetryingClient`, mirroring Go's `Decider`
  field, which is what lets GitHub override the generic policy.

- remote.gitlab: **code-ported | PARTIAL, gap ENFORCED.** Implemented: `repos`
  (clone + history), `forks`, `snippets`, `releases`, `release-assets`, group
  enumeration with `X-Next-Page` pagination, exclusion globs, date windowing.
  Not implemented and REFUSED BY NAME: `mrs`, `mr-comments`, `issues`,
  `issue-comments`, `ci-jobs`, `ci-artifacts`.
  **The thing that makes GitLab different is the `/-/` separator.** A project
  path may be arbitrarily deep (`group/sub/sub/project`), so only `/-/` marks
  where the namespace ends and a resource begins — anything that counts path
  segments breaks on the first subgroup. It also means the parser CANNOT know
  whether a path is a project, a group or a user; Go says so honestly
  (`kind: "namespace"`) and resolves it by trying the project endpoint and
  falling through to the group one, and so does this.
  Two other silent-failure guards: a project path must be **percent-encoded as
  one segment** (`group%2Fproject`) or the request hits a different endpoint
  entirely; and a next-page must be **strictly greater** than the current one
  (Go's `nextPage <= page` check), or a server echoing the same page number
  loops forever rescanning it.
  A snippet's body is NOT in the list response — it is fetched from `/raw`, or
  every snippet scans as empty.

- remote.huggingface: **code-ported | PARTIAL, gap ENFORCED.** Implemented:
  `repos` for all three kinds (model / dataset / space) plus owner enumeration.
  Not implemented and REFUSED BY NAME: `discussions`, `prs`, `buckets`.
  **The default is the subtle part:** three repository kinds share one path
  space, `datasets/…` and `spaces/…` are explicit, and everything else is a
  MODEL — while a single path segment is an OWNER. Confusing those turns a repo
  scan into an owner enumeration or the reverse.
  Owner enumeration lists all three kinds and DEDUPES by a case-folded
  canonical key, because the API returns the same repository from more than one
  endpoint and scanning it twice doubles both the work and the findings.
  One kind failing to list is survivable (a token may see models but not
  spaces); all three failing is an error, since a silent success would report
  the owner clean.

- sources.archive: **code-ported | VERIFIED.** 83 sources tests green (19 new).
  **This closed a detection gap that spanned the whole tool.** Until it landed, a
  secret inside a committed `.zip` was missed by EVERY source — git, filesystem,
  S3, GitHub, GitLab, Hugging Face — because the archive was classified as
  binary and skipped. Nothing reported it. That is the quietest possible miss,
  and it was the longest-standing deferral in this port.
  Measured effect on the real corpus: the byte counter went from 1.50 MB to
  **3,475,408 bytes against Go's 3,474,939** — 469 apart, from 2 MB apart — with
  the finding sets still identical.
  Formats: **zip, tar, gzip** (so `.tar.gz` chains), via `zip` / `tar` /
  `flate2` — mature, and PURE RUST with `rust_backend`, so the build still needs
  no C toolchain. 7z, rar, bz2, xz, zstd, brotli and lz4 are **recognised and
  named** rather than silently treated as binary, so an unscanned archive is
  visible in the log instead of invisible.
  Ported behaviours: format identified by CONTENT first and extension second
  (archives arrive misnamed constantly, and trusting the name misses exactly
  those); non-regular entries skipped; the container path prefixed with `!`
  (`outer.zip!inner.zip!creds.txt`); the decompressed stream renamed by dropping
  the compression suffix so `x.tar.gz` becomes a tar on the next descent rather
  than looping; and `max_archive_depth` (Go's default 8) bounding the nest,
  which is the zip-bomb guard.
  Added beyond Go: zip-slip paths (`../../escape.txt`) are refused. Nothing is
  written to disk so the classic risk does not apply, but a traversal path in a
  finding is misleading enough on its own.
  A malformed archive is skipped with a warning; Go recovers from an outright
  library panic at the same place for the same reason.
  **A Rust-specific trap worth recording:** the recursive descent originally
  monomorphized `&mut F` without bound and the compiler stopped with a recursion
  overflow. The fix is one erased callback type (`fragments_dyn`), not a
  recursion-limit bump.

### Remote sources — resource coverage is now COMPLETE

All three remote sources scan every resource type Go defines. The
`IMPLEMENTED_RESOURCES` constant and its refuse-by-name check are KEPT in each,
so a resource added later is refused rather than silently no-opping.

| Source | Resources | Status |
|---|---|---|
| GitHub | 12/12 | repos, forks, prs, pr-comments, issues, issue-comments, actions, action-artifacts, discussions, releases, release-assets, gists |
| GitLab | 11/11 | repos, forks, mrs, mr-comments, issues, issue-comments, snippets, releases, release-assets, ci-jobs, ci-artifacts |
| Hugging Face | 4/4 | repos, discussions, prs, buckets |

Added in this pass, each with the reason it matters:

* **GitHub Actions** — a workflow step that echoes its environment writes every
  secret into a log anyone with read access can download. Logs and artifacts
  are ZIPs, so the archive descent opens them. An EXPIRED artifact is skipped
  without a request; an expired run log 404s and is survived.
* **GitHub discussions** — a discussion comment has REPLIES, a second level the
  issue/PR shapes lack. On a Q&A discussion the accepted answer *is* a reply, so
  scanning only top-level comments misses most of the content.
* **GitLab issues/MRs/notes** — one function covers both, since they differ only
  in endpoint and attribute. `scope=all&state=all` is deliberate: a secret in a
  CLOSED merge request is still leaked. SYSTEM notes ("merged", "assigned to")
  are skipped as pure noise. The date window is pushed to the server via
  `created_after`/`created_before` as well as enforced locally.
* **GitLab CI jobs/artifacts** — same log-echo risk as Actions.
* **Hugging Face community** — a PR there *is* a discussion with
  `isPullRequest: true`, so both resources share one endpoint and are gated
  separately. The text lives at `data.latest.raw`, because an edited comment
  keeps its history and `latest` is what is published. The `author` field is
  polymorphic (bare string or object) and is read defensively.
* **Hugging Face buckets** — the S3-compatible object surface, walked through
  HF's own tree API.

**A real bug caught here:** GitHub returns `id` as a JSON NUMBER, and the
`s()` field helper only handled strings — so `run_id` came out empty and
produced URLs like `/actions/runs//artifacts`. That is a 404 that reads as "no
artifacts", and it would have failed against the live API exactly as it failed
in the test.

Also ported: `safe_path` for CI job names (user-controlled text that becomes
part of a path — `../../etc/passwd` cannot traverse), and GitLab's
`#note_<id>` fragment so a finding links to the comment rather than the top of
a long thread.

- validate.pool: **STILL DEFERRED, reason updated.** Previously blocked on
  `exprruntime` + `sources` + `singleflight`; both of those are now ported, but
  the pool's actual job is running VALIDATION programs
  (`exprruntime.Runtime.EvalValidate`), which is M11 — excluded from core and
  feature-gated because validation is off by default upstream
  (`detect.go:39-41`). Porting a worker pool that cannot validate anything would
  be scaffolding. Blocked BY DESIGN, not by oversight.

## Wave 4 (2026-08-14)

- detect.core: **code-ported | VERIFIED**. **38 tests green** (`cargo test -p
  detect`). **REPLACES the hand-written 26-rule engine with the real one**,
  driven by `config.full` (414 rules) and `exprruntime.filter`.

  Ports `detect.go`'s core path, `utils.go`, `location.go`, and
  `processComponents`/`withinProximity`. The path is: Aho-Corasick keyword
  prefilter → candidate rules in DESCENDING specificity → regex → secret
  extraction (`secretGroup`, named captures) → allow-signature → specificity
  suppression → entropy → global + rule filter expressions → components →
  dedupe.

  ### Three divergences found by running the GO ENGINE, not by reading it

  Each was caught because the Go binary was executed on the same input, and each
  had made the port **more permissive than the source** — false positives in a
  commit gate:

  1. **Components are REQUIRED, and deferring them was wrong.** 25 rules declare
     components; `aws-access-token` declares
     `components = [{ id = "aws-secret-access-key", within = "5L" }]`. Go reports
     **nothing** for a lone `AKIA…`. The first version of this port reported it.
     Components are now ported and enforced, including the proximity window.
     Differential golden, straight from the Go engine:

     | input | Go |
     |---|---|
     | lone AWS id | NO FINDING |
     | AWS id + secret key adjacent | `aws-access-token`, componentSets=1 |
     | AWS id + secret key 8 lines apart | NO FINDING (window is `5L`) |

     The port now matches all three.

  2. **`MaxDecodeDepth` defaults to 0, not 8.** Go's
     `NewDetectorDefaultConfig` leaves it at the zero value, so the default
     engine performs NO decode passes. The port had defaulted to 8, scanning
     strictly more than the source. Decoding is now opt-in, as upstream.

  3. **Line numbers are 0-BASED.** Go reports `StartLine=0` for a secret on the
     first line of a `DetectString`. The pre-M13 lensr engine reported 1. The
     port is now 0-based; the gate's output changed from `leak.txt:1` to
     `leak.txt:0` accordingly.

  ### Two entropies, deliberately kept different

  `detect.shannonEntropy` counts **runes** but divides by **byte** length
  (`utils.go:125`), while `exprruntime.shannonEntropy` is a pure **byte**
  entropy over a `[256]` table. For ASCII they agree; for multi-byte input they
  do not. The first populates `Finding.Entropy` (what reports show), the second
  backs the `entropy()` filter function (what 363 rules threshold on). Unifying
  them into one "clean" function would silently move both. Pinned by
  `detect_entropy_is_gos_rune_byte_hybrid` (`"éé"` → 0.5 vs 1.0).

  ### Test fixtures corrected rather than the engine weakened

  Four lensr-local fixtures asserted behaviour the real catalogue correctly does
  NOT produce. Each was fixed at the fixture, with the reason recorded:
  * the JWT generator emitted `ey` + random; a real JWT header is base64 of
    `{"alg"…` so it always starts **`eyJ`**, and the rule's keyword is literally
    `eyj` — the samples never reached the rule (Go behaves the same);
  * `corpus_coverage` / `corpus_full_coverage` were generated against the old
    26 rules; **eight** detectors' samples are not format-valid for the real
    patterns (`anthropic` needs 93 chars + `AA`; `openai` needs the embedded
    `T3BlbkFJ` marker; `private-key` needs ≥64 chars of body, not a bare header;
    AWS ids are base32 `[A-Z2-7]`, not `[0-9A-Z]`). Both are now REGRESSION
    guards at a measured baseline rather than an aspirational bar, and
    `tests/real_formats.rs` constructs each type to the catalogue's ACTUAL
    pattern and proves the engine fires — without that companion, re-baselining
    would just be lowering the bar.

  ### Deferred from M13, named not dropped

  Validation (`ValidationPool`, off by default upstream), `Run`/`iter.Seq`
  streaming over a `Source`, baseline, rule timings, SCM links, and the BPE
  tokenizer. Without a tokenizer `tokenRatio` is 0 and `failsTokenEfficiency`
  is false — exactly Go's behaviour when `tokenizerProvider` is nil.

  **Gate integration:** `lensr_git` rebuilt against the new engine (its
  `Finding` is now `report::Finding`, `masked` a free function, line numbers
  i64) and re-smoked end to end — a planted AWS **pair** is caught, a lone id is
  not, matching the source.

## Wave 3 (2026-08-14)

- exprruntime.filter: **code-ported | VERIFIED**. **32 tests green**
  (`cargo test -p exprruntime`). **ZERO external dependencies** — only the
  already-ported `regexp`, `ahocorasick`, `words`, `confidence`.

  **Why hand-written.** Go binds `expr-lang/expr`; no Rust equivalent exists
  (`cel-rust` is a DIFFERENT language, and `celcompat.go` shows CEL is the
  *legacy input* betterleaks rewrites INTO expr, not the target). Porting a
  general-purpose expression language would be enormous — so this is a
  purpose-built recursive-descent evaluator over exactly the language in use.

  **THE GRAMMAR WAS DERIVED FROM THE WHOLE CORPUS, AND THAT MATTERED.**
  PORT-PLAN open question 4 insisted on this rather than a sample. 366 of the
  367 expressions use a tiny language — a call, a numeric comparison, `||`.
  The 367th is the **`generic-api-key` catch-all**, the single most important
  rule in the catalogue, and it uses far more: `let` bindings (including
  `let _ =` for a pure side effect), a ternary, Go-style **slices**
  (`finding["fragment_raw"][a:b]`), arithmetic, and `len`/`min`/`max`. It also
  reads `finding` entries that are NUMBERS (`match_start_idx`,
  `match_line_end_idx`) alongside strings — so `finding` had to be
  `map[string]Value`, not a string map.
  **A sample of the other 366 would have produced a parser that silently
  rejected the catch-all.** The first full-corpus run failed at exactly 1 of
  367, which is how this surfaced.

  Surface implemented: `entropy`, `matchesAny`, `containsAny`, `findMatch`,
  `tokenRatio`, `failsTokenEfficiency`, `setConfidence` — each reachable bare
  AND under `filter.` (the catalogue uses both spellings: 211 `entropy` vs 149
  `filter.entropy`) — plus expr's `len`/`min`/`max`. `&&`, `!`, `==`, `!=` are
  implemented although the catalogue never uses them: they are part of the
  language, and rejecting a valid user config would be a defect.

  **No tiktoken dependency, deliberately.** Go's `tokenizerProvider` may be nil,
  in which case `tokenRatio` returns 0 and `failsTokenEfficiency` returns false.
  The port keeps that injection seam (`trait Tokenizer`), so BPE tokenization
  arrives with M13 (which owns `tiktokenloader.go`) instead of being forced on
  this module.

  **Byte-based entropy, deliberately.** Go indexes `s[i]` over a
  `[256]float64` table — BYTES, not runes, so a multi-byte character
  contributes several symbols. 363 rules compare entropy against a threshold, so
  a rune-based version would silently shift every one of them. Pinned by
  `shannon_entropy_is_byte_based_like_go` (`"é"` → 1.0, not 0.0).

  **Substitution (flagged):** Go's `containsAny` calls the EXTERNAL
  `github.com/rrethy/ahocorasick`, while `detect` uses the bespoke
  `internal/ahocorasick`. The port uses the ported internal matcher for both —
  the contract is "does any term occur", which both answer identically — for one
  fewer dependency.

  **Verified against the real catalogue, not fixtures:**
  `every_catalogue_filter_compiles` parses all **367** expressions;
  `every_catalogue_filter_evaluates_to_a_bool` runs all **365** rule filters to a
  boolean with no unknown-function or arity error; `global_prefilter_skips_known_noise_paths`
  proves the prefilter discriminates (skips `node_modules/…`, `go.sum`, images,
  lockfiles; keeps `src/main.rs`, `internal/auth/token.go`).

## Wave 2 (2026-08-14)

- sources.core: **code-ported | VERIFIED**. 11 tests green (`cargo test -p
  sources`). Zero dependencies. SUPERSEDES the earlier `Attr*`-constants-only
  subset. Ports `source.go`, `fragment.go`, `attribute.go` and the
  `InnerPathSeparator` const from `file.go:22` — the 189 LOC `detect` actually
  needs. Go has NO test file for any of them, so all tests are characterization.
  **Why the split is here:** everything else in `sources` is the SCANNERS (git,
  filesystem, archives, GitHub, GitLab, HuggingFace, S3 — ~7,700 LOC), reached
  only from `cmd` and `detect/deprecated.go`. Stopping at the core is what lets
  `config` and `detect` be ported without dragging in `go-gitdiff`, `fastwalk`,
  `mholt/archives`, `go-github` and an async runtime.
  **Reshape (flagged):** Go's `Attributes map[string]string` has randomized
  iteration order; the port uses `BTreeMap`, so attribute order is
  DETERMINISTIC. Nothing in scope depends on Go's random order and it makes
  report output reproducible — but it is a deliberate divergence, pinned by
  `attributes_iterate_in_sorted_order`.
  **Reshape (flagged):** Go's `FragmentsFunc(fragment, err) error` passes both a
  value and an error; the port uses `Result<Fragment, E>`, making the
  "both set"/"neither set" states unrepresentable. Go's `Source.Fragments` also
  takes a `context.Context`; Rust has no ambient context type, so the parameter
  is dropped rather than faked — cancellation is the implementor's business.
  **Pre-existing, NOT ours:** `go test ./sources/` FAILS upstream on
  `TestGitHub_scanRepo_yieldsFragmentsWithoutMatchingPrefilter`
  (`github_test.go:84`) — a GitHub integration test needing network. None of the
  three files ported here has a Go test.

- config.full: **code-ported | VERIFIED**. **23 tests green** (`cargo test -p
  config`); Go baseline `go test ./config/` → **ok**. SUPERSEDES the two-field
  `config.rule` subset.

  **THIS IS THE 26 → 414 RULE JUMP, and it cost zero of the 14K-LOC Go `rules`
  package.** The catalogue `config/betterleaks.toml` (491,438 bytes, 9,164
  lines, 414 rules) is embedded byte-identical via `include_str!`, exactly as
  Go's `//go:embed` does, and parsed at load. At runtime Go reads that TOML too
  — never the generator functions — so porting the LOADER is the whole job.
  The TOML is signed as an M9 source file: drift there silently changes
  detection, so it is hashed like code.

  **All 414 rules load; all 414 patterns COMPILE; all 414 validate.** The test
  forces engine compilation rather than trusting the facade's laziness,
  precisely so an engine rejection cannot hide until scan time.

  **PORT-PLAN §7's regex risk, now MEASURED — and much smaller than feared.**
  Exactly **2** of 414 patterns were rejected, and NOT for the predicted
  ASCII-vs-Unicode reason: `pypi-upload-token` and `vault-batch-token` (both
  products of `MergeRegexps`) exceeded Rust's default 10 MB compiled-size limit.
  Go's `regexp` has no such limit — it simulates an NFA and never builds the DFA
  tables the limit exists to bound — so the faithful fix is in the facade:
  `regexp`'s stdlib engine now builds with `size_limit(64 MB)`. Dropping the
  limit entirely was rejected; 64 MB clears both while still bounding a
  pathological pattern. **The `\w`/`\b` ASCII-vs-Unicode divergence produced
  ZERO compile failures** — it remains a possible MATCH-behaviour difference for
  M13 to probe differentially, not a load-time one.

  **Discovered while porting:** the `entropy` TOML key is used **zero** times in
  the shipped catalogue. Entropy checking lives inside `filter` expressions as
  `entropy(finding["secret"]) <= N` on **363 rules** — matching rule.go's own
  note that "Deprecated legacy Allowlists, Entropy, and TokenEfficiency are
  translated into this field [Filter]". **Consequence: entropy filtering is
  gated on M10 (the expression evaluator), not on this field.** Likewise
  `tokenEfficiency`, `tags`, `required`, `allowlist(s)` and `extend` are used
  zero times.

  **DEFERRED, deliberately and measured:** `allowlist.go` (178 LOC) and
  `translate_filters.go` (256 LOC) — the deprecated shim rewriting allowlists
  into filter expressions. The allowlist SHAPE is parsed so a user config
  carrying one is not rejected, but the translation is absent. Safe for the
  default path because the catalogue contains zero allowlists; a regression test
  (`shipped_catalogue_uses_no_deferred_features`) FAILS if a future catalogue
  adds any, so the deferral cannot rot silently. Config `extend` is likewise
  parsed but not implemented.

  **Dependencies — 2 JUSTIFIED, both sanctioned:** `toml` + `serde` (std has no
  TOML; serialization formats are a sanctioned category, and Go uses
  `pelletier/go-toml/v2`). **No `semver` crate:** Go uses
  `hashicorp/go-version`, which is LAXER than strict semver and accepts `v1` /
  `v1.2`, so `semver` would reject inputs Go accepts — the comparison is a
  hand-rolled numeric triple instead.
  **`Program` is an opaque one-way handle** (`Option<Arc<dyn Any>>` newtype), so
  `config -> exprruntime` never becomes a dependency edge and PORT-PLAN §3's
  near-cycle stays broken.
  **Note:** `validate_min_version` WARNS, never fails, and is skipped entirely
  on a dev build — an unstamped build has `VERSION == DEFAULT_MSG`, so on the
  default path it is a no-op. Ported faithfully including that short-circuit.

## Modules (earlier run)

**Provenance:** every module is SIGNED to the source commit + per-file SHA-256 in
[`PORT-PROVENANCE.json`](PORT-PROVENANCE.json) (source `github.com/betterleaks/betterleaks`
@ `0b4063d7`). Run `/code:port:drift` to detect source evolution since porting; re-port
only the drifted modules. 15 modules signed (13 verified + `report.template`,
`validate.pool` excluded).

## Modules

- sigv4: **tests-ported | code-ported | VERIFIED** (parity: PASS). 7 tests green
  (`cargo test -p sigv4`): the 6 faithfully-ported Go tests (golden
  `DeriveSigningKey` vector, 5 `URIEncode` cases incl. `unicode-café`, required
  headers, session token, missing-creds error, deterministic signature) PLUS one
  differential golden captured from the Go source (`signAt`) on a novel input
  (query `%2F` sort, multi signed-header incl. spaced value, non-empty body hash,
  eu-west-1) — Rust reproduces the Go `Authorization` byte-for-byte
  (`Signature=81f56978…b45d3a6`). Go baseline `go test ./internal/sigv4/` also green.

- codec: **tests-ported | code-ported | VERIFIED** (parity: PASS). Conductor ran:
  `cargo test -p codec` → **5 passed** (the 3 table passes replaying 18 cases each
  raw/percent/hex = 54 assertions, PLUS a differential golden on 4 NOVEL inputs
  captured from the Go source — which pinned the base64 length/entropy threshold:
  Go leaves short tokens like `YWRtaW4=`/`dmFsaWQtdG9rZW4=` UNDECODED, and the Rust
  port reproduces that + the `JTcz…`→`%73…`→`secret` multi-pass, byte-for-byte).
  `go test ./detect/codec/` baseline green. `cargo clippy` clean. Zero dependencies.
  Ports
  Go `detect/codec` (whole package: decoder, encodings scanner, segment, ascii,
  base64, hex, percent, unicode, start_end). Faithful 1:1: same byte-level segment
  scanner, same decode precedence (percent>unicode>hex>base64), same in-place
  replacement + `decodedShift` position shifting, same overlap-precedence filter,
  same iterate-until-stable loop, same skip-if-empty/invalid + printable-ASCII
  guards. **3 Rust tests** (`decode_raw`, `decode_percent_wrapped`,
  `decode_hex_wrapped`) each replay the full 18-case Go table via a `full_decode`
  loop driver — faithful to `decoder_test.go`'s 20-ish cases × 3 passes (raw /
  `url.PathEscape`-wrapped / `hex.EncodeToString`-wrapped), every expected string
  byte-for-byte (incl. multiline slack case, `U+0061` + `\u`/`\\u` unicode, mixed
  hex+unicode). `url.PathEscape` and `hex.EncodeToString` are hand-rolled in the
  test module. Files: `codec/src/lib.rs`, `codec/src/tests.rs`, `codec/Cargo.toml`
  (edition 2021). A 4th Rust test (`diff_novel_inputs_match_go_golden`) adds the
  conductor's differential goldens. A **5th test** (`segment_functions_match_go_golden`)
  is a CHARACTERIZATION test for the 4 exported segment functions (`tags`,
  `current_line`, `adjust_match_index`, `segments_with_decoded_overlap`) — which had
  NO source test; goldens captured from Go by decoding a real input to segments and
  calling each (incl. every empty-segment early-return path). Closes recheck gap #1.

- words: **tests-ported | code-ported | VERIFIED** (parity: PASS). 2 tests green
  (`cargo test -p words`): the ported 8-case `HasMatchInList` table PLUS a
  differential golden from the Go source on a novel input (`"handshake"`, min_len 3
  → count 4, unique `[hand,hands,handshake,shake]`, ordered matches
  `hand:4|hands:5|handshake:9|shake:5`) — Rust reproduces it exactly, including
  match ORDER. Go baseline `go test ./internal/words/` green. Ported inline by the
  conductor (small graph); fail-first not separately captured (impl+tests written
  together, parity proven by the differential + Go baseline).

- sources: **PARTIAL — `Attr*` key constants | VERIFIED** (compiles + consumed by
  `report::Finding::attr`). Minimal `ATTR_PATH`/`ATTR_FS_SYMLINK`/`ATTR_GIT_SHA`/
  `ATTR_GIT_AUTHOR_NAME`/`ATTR_GIT_AUTHOR_EMAIL`/`ATTR_GIT_DATE`/`ATTR_GIT_MESSAGE`
  string consts — only what `Finding.attr`'s fallback reads. Rest of the large
  `sources` package (fragments, git/fs/scm scanners, `Fragment`) NOT ported. Zero deps.
- config: **PARTIAL — `Rule` subset | VERIFIED** (compiles + consumed by `report`).
  Minimal `config::Rule { rule_id, description }` — only the fields the report
  emitters read. The full `config.Rule` (regex/allowlist/keywords/entropy/required)
  and the rest of the large `config` package are NOT ported. Zero deps.
- report: **PARTIAL — `validation_status` + `Finding` + JSON + CSV + JUnit + SARIF emitters | VERIFIED**
  (parity: PASS). 11 tests green (`cargo test -p report`): `ValidationStatus`
  characterization; `write_json_simple` (matches the Go fixture
  `testdata/expected/report/json_simple.json`); `write_json_empty`; and a
  **differential golden on a RICH finding** captured from the Go source
  (`json.Marshal`) — populating the omitempty + nested fields the Go test leaves
  empty (`MatchContext`, `CaptureGroups`, `Attributes`, `Tags`, `RequiredSets` with
  a component, `ValidationStatus`/`Reason`, `ValidationMeta` with `any` values
  403/false) — reproduced byte-for-byte. Go baseline `go test ./report/ -run
  TestWriteJSON` green. `ValidationStatus`: Go `type ValidationStatus string`
  (arbitrary-string-capable) → Rust newtype `ValidationStatus(Cow<'static,str>)`,
  NOT a closed enum. **Finding: only the STRUCT + JSON serialization ported** — its
  methods (`Redact`/`MaskSecret`/`BuildRequiredSets`/`Attr`/`SetFingerprint`/
  `ToExprMap`) are NOT. **Other emitters** (csv/sarif/junit/template) NOT ported —
  coupled to `sources`/`config`/`internal/color`/`text/template`+`go-sprout` (a
  template parity wall). **CSV emitter** (`csv.go`): ported with Go's `encoding/csv`
  quoting rules HAND-ROLLED (no `csv` crate — zero new dep); 3 CSV tests incl. the
  Go fixture `csv_simple.csv` + a quoting differential (comma / doubled-quote /
  leading-space / embedded-newline / conditional Link+MatchContext columns)
  captured from the Go source, matched byte-for-byte (after line-ending
  normalization, as the Go test does). Go baseline `go test ./report/ -run
  TestWriteCSV` green. **JUnit emitter** (`junit.go`): ported with **`quick-xml`**
  (sanctioned XML format lib — operator 2026-07-12 OK'd format libs). Nested
  `testsuites>testsuite>testcase>failure`; each `<failure>` chardata is the
  JSON-marshaled `Finding` (REUSES the crate's `Finding` serde serialization, like
  Go's `getData`→`json.MarshalIndent`). 2 tests vs the Go fixtures
  `junit_{simple,empty}.xml`, compared by parsing XML back to structs +
  canonicalizing the embedded JSON (numbers → f64) — mirrors the Go test's
  `xml.Unmarshal` + `normalizeJunitJSONPayloads`. Go baseline `go test ./report/
  -run TestWriteJunit` green. **SARIF emitter** (`sarif.go`): ported with
  `serde_json` — the Go test does a **BYTE-EXACT** string compare (not semantic), so
  the wire structs are declared in Go's exact field order and serde's single-space
  `PrettyFormatter` reproduces Go `encoding/json` byte-for-byte. Consumes a minimal
  `config::Rule` (cross-crate). 2 tests: vs the Go fixture `sarif_simple.sarif` + a
  differential (empty `rules`→`[]`, symlink uri, `contextRegion`, no-commit message
  branch) — byte-for-byte. Go baseline `go test ./report/ -run TestWriteSarif` green.
  **`Finding` methods** (`finding.go`): ported `MaskSecret`, `Redact`,
  `BuildRequiredSets` (+ `cartesianFindings`), `Attr` + **all 14 `finding_test.go`
  tests** (report crate now **25 tests**). `MaskSecret` uses `f64::round_ties_even`
  = Go `math.RoundToEven` (banker's rounding), char-based (multibyte-UTF8 safe).
  `Attr` falls back to deprecated fields via `sources::ATTR_*` (cross-crate). Still
  DEFERRED (no test / out-of-scope consumers — reachable via the `pub` fields):
  `SetFingerprint`, `ToExprMap`, `SetExprContext`, `Print`, `locateMatch`,
  `sortedMapKeys`, `printPretty`, `SetAttr`/`SetAttributes`/
  `SyncDeprecatedSourceFields`/`Attribute`. Closes recheck gap #2.
  **Recheck polish (B–E) closed:** ported the Go `Reporter` INTERFACE as a Rust
  `pub trait Reporter { fn write(&mut dyn Write, &[Finding]) }` (all 4 emitters impl
  it; emitter `write` methods now take `&mut dyn Write` for object-safe dispatch) +
  a `dyn_reporter_dispatch` test; ported the `report.go` consts `CWE`/
  `CWE_DESCRIPTION`/`STDOUT_REPORT_PATH`; ported `report_test.go` `TestWriteStdout`
  (`write_stdout_produces_output`). **report crate now 27 tests.**
- validate: **PARTIAL — `result.go` ported | VERIFIED** (parity: PASS). 3 tests green
  (`cargo test -p validate`): ported `TestBetterStatusPriority` +
  `TestParseResultMapNormalizesStatus`, PLUS a differential — the full **7×7
  `BetterStatus` matrix (49 cells)** captured from the Go source, reproduced exactly.
  Consumes the ported `report::ValidationStatus` via a path dependency (cross-crate
  type identity). Go baseline `go test ./internal/validate/ -run
  'TestBetterStatusPriority|TestParseResultMapNormalizesStatus'` green.
  **`pool.go` + `cache.go` EXCLUDED** — blocked on unported `internal/exprruntime`
  (expr-lang runtime), `report.Finding`→`sources`, and `singleflight`. Zero
  third-party deps (only the intra-workspace `report` path dep).

## Dependencies (std-first log)

- `sha2` = "0.10", `hmac` = "0.12" (RustCrypto) — **justified & ADDED** to
  `sigv4/Cargo.toml`: Rust std has no SHA-256 or HMAC; hand-rolling crypto is out
  of scope and unsafe. Alternative considered: `ring` (heavier, C/asm build).
  Chosen `sha2`+`hmac` (pure-Rust, minimal). Used as `Hmac<Sha256>` + `Sha256`.
  NOTE: crates.io fetch is a normal build step; if the network is unavailable the
  `cargo` fetch will fail — that is the only external requirement.
- hex encoding — **none added** (hand-rolled).
- URL/query parsing — **none added** (hand-rolled minimal split + percent-decode).
- CSV (`encoding/csv`, report) — **none added** (Go's `fieldNeedsQuotes` rules
  hand-rolled BEFORE the format-lib policy; still valid, kept).
- `quick-xml` = "0.37" (serialize) (report) — **justified & ADDED**: Rust std has no
  XML; `report/junit.go` is `encoding/xml`. Per the operator's 2026-07-12 policy,
  **serialization-format libraries are a sanctioned dependency category** (JSON/XML/
  CSV/TOML/YAML) — prefer the crate over hand-rolling the format. Alternative
  considered: `serde-xml-rs` (chose quick-xml, the de-facto standard).
- `flate2` = "1.0" (words) — **justified & ADDED**: Rust std has no gzip/DEFLATE;
  the source embeds a gzip'd NLTK wordlist (`//go:embed words.txt.gz` +
  `compress/gzip`). Hand-rolling DEFLATE is out of scope. Alternative considered:
  `miniz_oxide` (lower-level; flate2 wraps it). Used only to decompress the
  embedded asset once at load. Embedded asset `words.txt.gz` copied byte-identical.
- `serde` = "1" (derive), `serde_json` = "1" (report) — **justified & ADDED**: Rust
  std has no JSON; `report/json.go` is `encoding/json`. serde+serde_json is the pack's
  one sanctioned JSON default. Alternative considered: hand-rolling a JSON encoder
  (error-prone for the full Finding shape + escaping) — rejected. Go `encoding/json`
  field naming reproduced via explicit `#[serde(rename)]`; `omitempty` →
  `skip_serializing_if`; `json:"-"`/unexported → `#[serde(skip)]`.
- **codec — NONE ADDED (zero deps).** base64 (`encoding/base64`), hex
  (`encoding/hex`), percent (`net/url`), unicode (`U+`/`\u`) all hand-rolled in
  `codec/src/lib.rs`. The base64 decoder reproduces Go `StdEncoding` (padded) then
  `RawURLEncoding` (unpadded) `decodeQuantum` semantics exactly. No `base64`,
  `hex`, `url`, `percent-encoding`, or `regex` crate pulled. `regexp` NOT needed —
  Go already replaced its regex with a hand-written byte scanner (`findEncodingMatches`).

## Deviations / gaps

- **Signature reshape:** Go `Sign(*http.Request, ...)` → Rust `sign(&mut Request, ...)`
  with a port-local `Request` type (Rust std has no `http.Request`). Behavior
  (headers set, canonicalization, signature) is 1:1; the container type differs.
- **`*http.Request` reshape (confirmed):** Go `Sign(*http.Request, ...)` →
  Rust `sign(&mut Request, body: Option<&[u8]>, region, service, creds)` with a
  port-local `Request` (Rust std has no HTTP type). `Request::new(method, url)`
  hand-parses `scheme://host/path?query`; headers are a case-insensitive
  multi-value list (`set_header` replaces = Go `Header.Set`; `header` returns the
  first value or `""` = Go `Header.Get`). Canonicalization, header-selection
  (host, x-amz-*, content-*; skip host/authorization), whitespace-collapse,
  query key+value sort with `URIEncode(_, true)`, path with `URIEncode(_, false)`,
  Authorization format, and constants are byte-for-byte 1:1.
- **`time.Time` reshape:** Go `signAt(now time.Time)` → Rust `sign_at(now: Timestamp)`
  where `Timestamp{year,month,day,hour,minute,second}` formats `20060102T150405Z`
  / `20060102`; `Timestamp::now()` = `time.Now().UTC()` via std `SystemTime` +
  Howard Hinnant `civil_from_days` (no calendar crate).
- **hex / URIEncode / URL+query parse / percent-decode:** hand-rolled, **no crate**
  (`hex`, `url`, `percent-encoding` NOT pulled), per glossary. `URIEncode` iterates
  bytes so `café` → `%C3%A9`.
- **codec — `logging.Trace()...` deliberately DROPPED** (the only internal dep, in
  `findEncodedSegments`). Non-observable debug tracing; no test asserts it. A code
  comment marks the omission site in `find_encoded_segments`. Not a parity break.
- **codec — latent UTF-8 slice assumption (flagged, not a test failure).** `decode`
  slices `&data[m.start..m.end]` as `&str`. Go slices raw bytes (`string` = bytes)
  and never panics on a mid-rune boundary. Analysis: the scanner only starts/ends
  segments at ASCII trigger bytes (`%`, `U+`, `\u`, `[A-Za-z0-9_/+\-]` runs) and
  skips multibyte continuation bytes one-by-one via the `i += 1` fallthrough, so a
  segment boundary can never split a UTF-8 char — all test inputs (and realistic
  inputs) are safe. If a future input ever placed a segment boundary mid-rune, the
  Rust slice would panic where Go would not; switch to byte slices + `from_utf8` if
  that ever surfaces. `bytes_to_string` also has a lossy fallback (never taken for
  these inputs). Per the "unportable → flag, never fake" rule.
- **codec — decoder cache sharing.** Go's `TestDecode` shares ONE `Decoder`
  (`decodedMap` cache) across all 3 passes; the Rust port uses a fresh `Decoder`
  per `#[test]`. The cache is a pure, context-free function of the encoded string
  (`decode(enc)`), so shared vs fresh is behaviorally identical — no parity impact.
- **validate — Go `any` reshape.** Go `interface{}` → Rust `Value` enum (bounded to
  the parsed shapes). Faithful for the tested paths; Go's open `any` is not fully
  representable. `parse_result`'s error path uses Go `%T` reflection type names —
  no exact Rust analog, so `go_type_name` APPROXIMATES them (flagged). `Result` →
  `ValidationResult` (prelude-shadow avoidance).
- **validate — `pool.go`/`cache.go` excluded** (dependency-ordering): blocked on
  `internal/exprruntime`, `report.Finding`→`sources`, `singleflight`. This is the
  analyst's leaf-first discipline — the untested-here units are named, not skipped.
- **report JSON — Go-vs-serde number formatting.** Go `encoding/json` prints a whole
  float as `0` (e.g. `Entropy float32` 0 → `0`); serde_json prints `0.0`. The Go test
  compares by `json.Unmarshal` into `any` (all numbers → `float64`), so the diff is
  masked. The Rust test replicates that exactly (`normalize_numbers` coerces every
  JSON number to `f64` before comparing) — faithful to the test's contract, flagged.
- **report — `Fragment` is a STUB.** The full `sources.Fragment` is not ported; the
  `Finding.fragment` field is `omitempty` and always `None` in scope. Finding's
  METHODS are not ported (JSON emitter needed only the struct). Flagged.
- **report SARIF — nil-slice → null edge.** Go emits a nil `Properties.Tags` (and a
  nil `rules`) as JSON `null`; Rust `Vec` can't be nil so it always emits `[]`. Go's
  SARIF code already forces `rules` to `[]` (its `hasEmptyRules` workaround), which
  Rust matches naturally; but a nil-`Tags` finding would diverge (Go `null` vs Rust
  `[]`). Test findings have non-nil tags, so unaffected — flagged (a facet of the
  general Go-slice-nil-vs-empty → Rust-`Vec` reshape).
- **config — `Rule` is a SUBSET** (`rule_id` + `description` only). The full
  `config.Rule` and `config` package are not ported. Flagged.
- **report `Redact` — Go-pointer-aliasing → Rust-ownership reshape.** Go's `Redact`
  dedups by `*RequiredFinding` pointer because Cartesian sets alias the SAME finding
  and partial masking must apply once. Rust `components: Vec<RequiredFinding>` is
  by-value (no aliasing), so each component is naturally masked exactly once and the
  dedup is unnecessary. `TestRedact_SharedPointerDedup` ported to two sets each
  holding an equivalent by-value component (both → `ab...`). Flagged.
- **sources — `Attr*` constants only** (subset). The rest of `sources` is not ported.
- **report `Reporter` — Go `io.WriteCloser` → Rust `&mut dyn Write`.** Go's
  `Reporter.Write` takes an `io.WriteCloser`; the emitters never call `Close`, so the
  port uses `&mut dyn Write` (object-safe, enables `dyn Reporter` dispatch like Go's
  interface). The `Close` half of `WriteCloser` has no consumer here — flagged.
- **validate `parse_result_map`** now PRIVATE (Go's `parseResultMap` is unexported) —
  recheck item E closed.
- **report `template` emitter — EXCLUDED (hard unit, unportable 1:1).** `template.go`
  renders USER-PROVIDED Go `text/template` files (`.tmpl`) through the Sprig function
  library (`go-sprout/sprout/sprigin`, 100+ funcs) — `{{ .Field }}`, `{{ range }}`,
  pipelines like `{{ now | date "2006-01-02" }}`. No Rust template engine parses Go
  template syntax + Sprig, and `template_test.go` is byte-exact against those exact
  `.tmpl` fixtures. A faithful 1:1 port would require reimplementing Go's entire
  `text/template` runtime + Sprig in Rust (a whole Go subsystem) — out of scope; a
  different Rust engine (minijinja/tera) would NOT render the Go-syntax templates, so
  it can't be faithful. FLAGGED, not force-ported. (Its sibling behavior — dangerous-
  func blocking `env`/`expandenv`/`getHostByName` — is likewise Go-template-runtime
  specific.)
- Full-repo port is OUT OF SCOPE for this run (regex-engine parity wall via
  regexp2/go-re2; ~41K LOC). This run validates the porting pipeline only.

## Verification (RESOLVED)

The porting subagent had no exec tool, so the conductor ran verification:
- `cargo test -p sigv4` → **7 passed / 0 failed** (incl. AWS golden vector + differential).
- `go test ./internal/sigv4/` → **ok** (parity baseline).
- `cargo clippy -p sigv4 --all-targets` → 1 cosmetic warning only
  (`manual_pattern_char_comparison` at `lib.rs:147` — style, not a defect; deferred).

### Known latent divergence (flagged, untested — NOT a test failure)
`collapse_whitespace` rebuilds header values byte→`char` (`b.push(c as char)`),
which for **non-ASCII bytes** would differ from Go's raw-byte string handling.
SigV4 header values are ASCII in practice, so all tests are unaffected; flagged
here per the "unportable → flag, never fake" rule. Fix if any non-ASCII header
value ever needs signing.

## sources.archive — rar (2026-08-14): **code-ported | tests green**

Closes the last named format gap. `rar` was previously RECOGNISED AND REFUSED —
identified by magic and by `.rar`, logged, and then skipped — so a secret inside
a committed `.rar` was reported as nothing rather than as unscanned. The earlier
entries above that list "7z / rar / bz2 / xz" as still-refused formats are
HISTORY; 7z, bz2, xz, zstd, brotli, lz4 and now rar all decode.

Dependency: `rars` 0.6.0 — pure Rust, so the build still needs no C toolchain,
which is why it beat the `unrar` C-binding crate PORT-PLAN originally listed.
It describes its own status as "kinda works", so the port does not trust it: the
test WRITES a real RAR 1.5 store-only archive with the crate's own writer and
reads it back through `extract`, asserting one member out, the right name, and
byte-exact content. RAR 1.5 specifically, because the 1.3/1.4 writer emits a
different signature that the scanner's magic check would never route here.

FALSIFIED: neutering the per-entry writer so it accepts bytes and discards them
fails `a_secret_inside_a_rar_is_found` with `left: []` against the 31 expected
bytes. Reverted.

LIMIT of that evidence, stated rather than implied: writer and reader are the
same crate, so a bug both halves share is invisible to this test. What it does
catch is the decoder going silent or corrupting content — the regression that
would let a secret through.

Behaviour matches the zip/tar readers: a member using a feature the decoder
lacks warns and keeps the members that DID decode, rather than discarding the
archive; entry names are `from_utf8_lossy` because a RAR name is not guaranteed
UTF-8 and refusing one would drop a file that may hold a secret; a corrupt
archive is an ERROR, not an empty result, since empty would read as "this
archive held nothing".

## --regex-engine and --workers now ACT (2026-08-14): **code-ported | tests green**

Two of the three flags that were accepted-but-inert now do the work. Coverage
moved 83.1% → 91.3% fully ported; NOT PORTED is down to 23 LOC, both deliberate.

**`--regex-engine stdlib` accepted.** It used to be refused as "not available in
this build", on the assumption it named a different matcher. It does not. Go's
two engines are the SAME semantics: `stdlib` is Go's own `regexp` package and
`re2` is `go-re2`, which exists as a drop-in performance replacement for it —
`regexp/re2/re2.go` wraps `gore2.Compile` and satisfies the same
`internal.CompiledRegexp` interface `*regexp.Regexp` does. The flag picks an
IMPLEMENTATION, not a dialect; neither backtracks, neither has lookaround. Rust
`regex` is that same lineage, so one engine serves both values faithfully. The
only observable difference in Go is a debug line, `using %s regex engine`
(root.go:190), which the port now emits with the selected name. Anything else is
still rejected with Go's message, now listing both valid values.

**`--workers` fans S3 object fetches out.** Go `s3.go:299`,
`errgroup.SetLimit(workers)`, default 16 (`s3DefaultWorkers`), 0 meaning the
default rather than "no workers". The port fetched serially and warned that the
flag did nothing — an accepted flag that does nothing is the quietest kind of
wrong. Objects are now fetched in chunks of `workers` via scoped threads, so at
most that many bodies are resident, the same bound Go's limited errgroup gives.

⚠ DELIBERATE DIVERGENCE, in the direction of determinism: Go's goroutines call
`yield` themselves, so its fragment order follows whatever the network returns.
This port fetches concurrently and EMITS IN LISTING ORDER. A report whose order
changes run to run is one an operator cannot diff.

FALSIFIED, both halves. Pinning `effective_workers` to 1 fails
`workers_fetch_concurrently` with "peak in-flight was 1 — the fetches ran one at
a time". Reversing the emit zip fails
`fragments_are_emitted_in_listing_order_not_arrival_order` AND the pre-existing
`a_failed_object_fetch_is_survived`, so the ordering is load-bearing rather than
incidental. The fake applies a DESCENDING per-key delay, so the first-listed
object is the slowest — an emit-on-arrival implementation would produce the exact
reverse and the assertion is not vacuous. Both reverted.

RIPPLE, worth naming because it reached three crates: sharing the source across
fetch threads required `Sync` on `sources::SkipFunc`, on `s3::Objects`, and on
the three injectable hooks of `transport::RetryingClient` (`sleep`, `now`,
`decider`). Nothing in production code was affected — the real implementations
are stateless. Two TEST doubles were, and had to move from `Rc<RefCell<_>>` to
`Arc<Mutex<_>>`: the transport wait-recorder and the S3 fake's request log. That
is the bound doing its job at compile time instead of at runtime.

STILL PARTIAL, and staying that way deliberately:
- `cmd/diagnostics.go` cpu/mem/trace/http — Go `runtime/pprof` and
  `net/http/pprof`. There is no Rust analog that produces a profile
  `go tool pprof` can read, and emitting a differently-shaped file under the
  same flag would be worse than the current refusal-by-name.
- `cmd/root.go` `--experiments` — Go registers it and never reads it (one
  occurrence in the whole tree, its own registration). The port warns rather than
  accepting silently.
- `internal/exprruntime/runtime.go` — `expr.Compile`/`Env` replaced by the
  port's own engine. Architectural, not a gap.
- `detect/deprecated.go` — the wrappers Go itself marks Deprecated
  (`DetectSource`, `Detect`, `DetectContext`, `AddFinding`, `Findings`,
  `NewDetector`). `FilterByStatus`, the one live function in the file, IS ported.
  Shipping a brand-new crate with day-one deprecated shims for zero consumers is
  debt, not parity — recorded as a decision rather than an oversight.

## Coverage 91.3% → 98.6%, NOT PORTED → 0 (2026-08-14)

Four items closed. One file remains PARTIAL, deliberately and finally.

**`regexp/re2/re2.go` + `regexp/internal/compiledregexp.go` — PORTED.** These
were the last 23 LOC of NOT PORTED, both marked "DELIBERATE: the WASM RE2
backend; Rust regex is the same lineage". That reasoning was backwards: identical
semantics is why they port CLEANLY, not why they should be dropped.
`internal.CompiledRegexp` already existed here as the `CompiledRegexp` trait, so
only `re2.RE2` was genuinely missing. It is now `regexp::Re2`, delegating to the
same backend `Stdlib` uses and reporting `"re2"` from `Engine::version`. The CLI
goes through `regexp::set_engine`, the same indirection Go uses at
`cmd/root.go:162-166`, so the `using %s regex engine` debug line reports what the
facade will actually use rather than what the flag parser decided a moment ago.
The mapping is tested through `select_regex_engine`, which returns the engine
instead of installing it — the facade is process-global, and a test asserting
through it would race every other test running a scan in the same process.

**`SlowWarningThreshold` — PORTED, and it was a LIVE-path gap, not a deprecated
one.** `detect/detect.go:548-558` arms a `time.AfterFunc` around every fragment
inspection so a fragment that is taking too long says so WHILE it is still
running. That is the entire point: it tells an operator staring at a motionless
scan which file is responsible. This port had nothing. It now arms a thread,
gated on Go's own `logger.GetLevel() <= zerolog.DebugLevel` — a guard that is a
REQUIREMENT here rather than an optimisation, since a thread costs far more than
Go's timer heap. At the default info level nothing is spawned. The threshold is a
settable global because Go declares it in a `var` block, not a `const` one.

FALSIFIED: dropping the cancellation flag makes the drop path wait the full
threshold — `drop waited 30.0160885s — the timer is not being stopped`. That is
the bug this design could plausibly have had, and it would be far worse than the
missing warning: every fragment on a debug scan would block for five seconds and
the scan would appear hung. Removing the debug guard fails the arming test at
`Info`. Both reverted.

**`cmd/root.go --experiments` — divergence CLOSED.** Go registers the flag and
never reads it (one occurrence in the tree, its own registration), so it does
nothing in Go and now does nothing here. The port used to WARN, which meant it
wrote a stderr line Go does not — a real observable divergence that would show up
in any script diffing the two outputs. The note moved to debug: nothing at the
default level, still answerable for anyone who asks. Silently swallowing it, Go's
actual behaviour, would leave "did that flag do anything?" unanswerable.

**`detect/deprecated.go` — PORTED as `detect::LegacyDetector`.** Go hangs
`DetectSource`, `AddFinding`, `Findings`, `addCommit` and `shouldVerbosePrint`
off `*Detector`, with their state in the same struct the live scan uses — its own
comment on `commitMap` says those fields are "used only by this code path". This
port's `Detector` is deliberately `&self` and shareable, because `detect` is
called from several threads at once (S3 `--workers`, parallel git) and the CLI
owns accumulation. Six accumulator fields on the hot struct to serve an API with
no caller is a tax on every live scan, so the state lives in a borrowing type
instead. Every observable behaviour is reproduced: the gate ORDER in
`AddFinding`, both fingerprint shapes, ignore/baseline/confidence, the commit
SET, `shouldVerbosePrint` (which is NOT the live path's rule — `cmd/directory.go`
prints everything under `--verbose` and filters the report later), and the
`"%d commits scanned."` line only this path emits.

NOT reproduced, flagged: Go fans findings through a buffered channel and a
consumer goroutine to join two producers. Here the routing is direct. That is a
mechanism, not an observable — same findings, same order, same counts.

A CAUGHT MISTAKE worth recording, because it is the recurring one. The first
draft of the two ignore-fingerprint tests fed `Detector::detect` output into
`add_finding`. `detect` ALREADY applies the ignore list, so both tests passed no
matter what `add_finding` did — deleting the commit-qualified check outright left
them green. Rewriting them around hand-built findings made them fail on that
deletion, which is the only reason they are worth having. Falsification is what
found this; the tests looked fine.

**STILL PARTIAL, and this is the final answer: `cmd/diagnostics.go` cpu / mem /
trace / http.** `rules` and `rules-csv` are ported byte-for-byte. The other four
are `runtime/pprof` and `net/http/pprof`, and they are the porting-skill's
"unportable → flag, never fake" case rather than unfinished work:

- **cpu** needs sampling profiling. The `pprof` crate is Unix-only (signals and
  `perf`); on Windows it means `SuspendThread` + `StackWalk64` per sample.
- **mem** needs allocation-site attribution, which in Rust means capturing a
  backtrace per allocation — prohibitive, and not what Go's heap profile is.
- **trace** is Go's execution tracer: goroutine scheduling, GC phases, syscall
  blocking. There is no analog, because there is no Go runtime.
- **http** serves the three above. With nothing to serve it is an empty endpoint.

The output is not a log file, it is a gzipped `profile.proto` that a user loads
into `go tool pprof` and draws conclusions from. Emitting an empty or fabricated
one under the same flag would be actively worse than refusing — the refusal names
the mode and says what IS supported, and `go_runtime_profilers_are_refused_by_name`
pins that.

## CI, and the bug writing it found (2026-08-14)

**`.github/workflows/betterleaks-rs.yml`** ports Go's `test.yml` — build,
validate the shipped catalogue under EACH regex engine, test. Differences, all
deliberate: Windows only rather than `[ubuntu-latest, windows-latest]` (Windows
is the platform this project finishes first; a Linux leg is a one-line addition
when that call is made, and the port is portable Rust with no C toolchain);
`push` limited to `main` plus `pull_request` and `workflow_dispatch` rather than
Go's every-branch, because every run spends the owner's Actions minutes and the
owner asked for that spend to stay deliberate; and no `--race`, because Rust has
no such flag — the compiler rejects the code Go's race detector looks for. That
is a step the language already performed, not a dropped one.

Go's `release.yml` is NOT ported: goreleaser + QEMU + buildx + GHCR + cosign is
packaging and distribution, not porting, and a signed multi-arch container of a
scanner nobody has decided to publish is machinery around the product rather
than the product.

**AND WRITING IT FOUND A DEAD COMMAND.** Running the workflow's own step
locally, before committing it:

```
$ cargo run -p cli -- config check config/assets/betterleaks.toml
thread 'main' has overflowed its stack
exit: -1073741571
```

`config check` compiles all 414 rules' filter and validation expressions — the
same recursion the scan path needs its 16 MiB stack for — but it was dispatched
straight from `main`, which gets 1 MiB on Windows. The comment directly above it
said it "gets one anyway". It did not. A comment described an intention nobody
implemented, and the command it guarded was completely dead on the catalogue this
project SHIPS, while 909 tests passed.

This is the SECOND time this exact failure has landed in this port, in the same
place, for the same reason: cargo runs tests on spawned threads with a far larger
stack than `main`, so no in-process test can see it. Both paths now go through
one `on_a_deep_stack` helper, and both are covered by SUBPROCESS tests in
`cli/tests/binary_smoke.rs` — a subprocess is the only thing that gets the real
`main` stack.

The fallback that ran on `main` when the thread could not be created is gone
too. It could not work — the catalogue does not fit in 1 MiB — so it turned a
resource hiccup into a stack-overflow crash with no connection to the warning
that preceded it. It now fails with the reason named.

FALSIFIED: reverting `config` to the main stack fails
`the_binary_checks_the_shipped_catalogue_without_overflowing_main` with
`exited Some(-1073741571)` and `thread 'main' has overflowed its stack`.
Reverted.

Output matches Go byte for byte under both engines:
`OK: 414 rules (186 with validation, 228 without validation)`.

Lesson, recorded because it generalises: the CI workflow was worth writing for
what it made me RUN, not for what it will run later. Every command a workflow
names has to be executed locally first — otherwise the workflow is a claim about
commands nobody has tried.

## PORT-PROVENANCE.json re-signed (2026-08-14)

`/unravel:port:status` found the manifest STALE. The source had not moved — all
95 signed hashes matched `6cf4f1a29160b68be7c6390599b9b773234e5a43` and the tree
was clean — but the manifest under-reported the port in two ways:

* **30 Go production files were unsigned**: the whole
  `internal/exprruntime/bindings_*` validation surface, `celcompat.go`,
  `validation_limits.go`, `detect/tiktokenloader.go`, `detect/rule_timings.go`,
  `sources/parallel_git.go`, `regexp/re2/re2.go`, `main.go`, and eleven `cmd/`
  files. Everything the last six commits landed.
* **Two modules were marked `excluded` that are ported and tested**:
  `report.template` (gtmpl + sprig) and `validate.pool`.

That is not cosmetic. `/unravel:port:drift` re-hashes only what the manifest
lists, so an upstream change to any of those 30 files would have gone
undetected, and the manifest would have reported UP-TO-DATE while a third of the
source tree was unwatched. A drift check that cannot see a file is worse than no
drift check, because it answers.

Re-signed: **50 modules, 132 source files, 0 excluded**, all at the same commit.
New module entries — `exprruntime.bindings`, `.validation`, `.cloud`,
`.celcompat`, `detect.tokenizer`, `.rule_timings`, `.deprecated`,
`sources.parallel_git`, `cli.commands` — plus `regexp` gaining `re2/re2.go` and
`detect/deprecated.go` moved out of `detect.ignore`, where it had been filed for
`FilterByStatus` alone, into its own module now that `LegacyDetector` ports the
whole file.

Verified four ways after signing: every hash matches the source; **zero** of the
97 Go production files unsigned; every `target_files` path exists in the Rust
tree (this caught two invented filenames — the string bindings live in
`bindings_filter.rs`, not a `bindings_strings.rs` I had assumed); and the
re-sign is idempotent, so running it twice cannot duplicate a path.

FOUR files are deliberately signed under TWO modules each — `config/config.go`
(allowlist + full), `detect/detect.go` (core + ignore), `sources/file.go`
(archive + file), `internal/httpclient/transport.go` (httpclient + transport).
That is correct rather than a defect: one Go file feeds two Rust modules, and a
change to it should flag both.

