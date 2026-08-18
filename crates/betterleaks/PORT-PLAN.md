# PORT-PLAN — betterleaks (Go) → betterleaks-rs, remaining work

Produced by `unravel-port-analyst` (read-only) against
`C:\Users\dyamm\Downloads\betterleaks`. Scope confirmed by the operator:
**EVERYTHING — 1:1 full repo.** Companion to `PORT-TRACK.md` (ledger),
`PORT-GLOSSARY.md` (shared naming/type decisions) and `PORT-PROVENANCE.json`
(source signing).

## 0. Two blockers found before any porting

**(a) The signing baseline has moved.** `PORT-PROVENANCE.json:3` signs to
`0b4063d7990e0ab6366a5b4eb58789584af5f945`; the source tree's actual HEAD is
**`6cf4f1a29160b68be7c6390599b9b773234e5a43`** (`.git/HEAD:1` →
`.git/refs/heads/main:1`). All 15 signed modules must be drift-checked and the
file re-anchored before Wave 1. License is **MIT** (`LICENSE:1-3`) — no legal
blocker.

**(b) The workspace `detect` crate is NOT a port.** It is a workspace member
(`Cargo.toml:3`) but absent from `PORT-PROVENANCE.json`. `detect/src/rules.rs`
carries **26 rules** vs the Go source's **414** (`config/betterleaks.toml`,
`^\[\[rules\]\]` = 414) — 6.3% coverage. `detect/src/lib.rs:259-278` carries a
**lensr-local `lensr:known [crc32]` extension** that does not exist upstream, and
honors only `gitleaks:allow` while Go honors `betterleaks:allow` first
(`detect/detect.go:57`). M13 is therefore a **replace**, and the lensr extension
must survive as a documented deviation layered on top of the faithful port.

## 1. The three decisions

### (a) `cmd/generate/config/rules` = DATA. Port the generator, not the 255 files.

- `cmd/generate/config/main.go:20` —
  `//go:generate go run $GOFILE ../../../config/betterleaks.toml`. 417 `rules.*`
  call sites in `main.go`, rendered through `rules/config.tmpl` (`main.go:17`)
  into TOML.
- `config/config.go:22` — `//go:embed betterleaks.toml`. **Runtime reads the
  TOML, never the Go rule functions.** Nothing under `detect/` imports `rules`
  (`detect/detect.go:20-30`).
- Each rule file is a struct literal plus test vectors: `rules/aws.go:12-47`
  (struct), `:50-62` (tps/fps), `:63` `return utils.Validate(r, tps, fps)`.
  `utils/validate.go:17-40` runs those assertions **at generation time** via a
  single-rule `detect.Detector`.

**Decision — Option 2, two tiers.** *Tier A (required):* copy
`config/betterleaks.toml` byte-identical, `include_str!`, port `config` to parse
it → **414/414 rule parity, 0 of 14K LOC ported**. *Tier B (optional, Wave 7):*
port the generator (~1,391 LOC) and mine the 255 files' `tps`/`fps` literals as a
**Rust test fixture**, not as code. Porting all 255 as Rust functions buys nothing
the TOML does not already carry. Caveat: `GenerateSemiGenericRegex` /
`GenerateUniqueTokenRegex` (`utils/generate.go:34-51,69-78`) compute patterns, but
those are already expanded in the emitted TOML.

### (b) `sources` — `detect` needs ~189 lines; the rest is `cmd`-only.

Non-test `detect` code references only `sources.Fragment`, `sources.Source`,
`sources.SkipFunc`, `sources.Attr*`, `sources.InnerPathSeparator`. `sources.Git` /
`sources.Files` / `NewGitLogCmd` / `ResolveRemote` appear **only** in
`detect_test.go` and `detect/deprecated.go`.

Core = `source.go` (21) + `fragment.go` (46) + `attribute.go` (121) + the const at
`file.go:22` = **189 LOC, no third-party deps**. Scanners and their forced deps:

| Sub-unit | LOC | Go dep (line) | Rust equivalent |
|---|---|---|---|
| `common.go` | 224 | `mholt/archives` (`:16`) | multi-crate assembly (no single equivalent) |
| `file.go` | 384 | `h2non/filetype` (`:14`), archives (`:15`) | **`infer`** + the above |
| `files.go` | 204 | `fastwalk` (`:12`), `semgroup` (`:13`) | **`ignore`** (parallel walker) |
| `scm/` | 255 | — | std |
| `git.go` + `parallel_git.go` | 888 | `go-gitdiff` (`git.go:23`), errgroup | **`patch`** ⚠ + `std::process::Command` |
| `github.go` | 1,956 | `go-github/v72` (`:18`), `githubv4` (`:19`) | **`octocrab`** (async → tokio) |
| `gitlab.go` / `huggingface.go` | 1,657 / 1,200 | plain REST | `ureq` / `reqwest` |
| `s3.go` | 857 | errgroup + **`internal/sigv4` (PORTED)** | — |

**Git access is a subprocess, not a library** — `exec.CommandContext(ctx,"git",…)`
at `git.go:119,121,228,230,301,558`, `parallel_git.go:149,197,247,276`,
`scm/clone.go:81`. A faithful port shells `git`; do **not** substitute `git2` /
`gix`.

### (c) `internal/exprruntime` — split it. The filter half is mandatory; the validation half is genuinely hard and IS gateable.

**No Rust equivalent of `expr-lang/expr` exists.** `cel-rust` is a different
language — and `celcompat.go:21` (`RewriteCELCompat`) proves CEL is the *legacy
input* betterleaks rewrites **into** expr. `rhai` / `evalexpr` are also different
languages.

But the required surface is tiny. `runtime.go:243,245` compile filter/prefilter
with `expr.AsBool()` — boolean expressions, not scripts. `baseBindings`
(`runtime.go:468-487`) + `bindings_filter.go:24-29` + `runtime.go:507` expose
exactly: `attributes`, `get`, `filter.setConfidence`, `matchesAny`, `containsAny`,
`entropy`, `findMatch`, `tokenRatio`, `failsTokenEfficiency`. Scanning the shipped
TOML, those **8 names are the only functions the default config ever calls**.

Scale: `filter =` appears **366×**, plus the global `filter`
(`betterleaks.toml:54`) and `prefilter` (`:23`) → **368 expressions on the hot
detection path** (`detect/detect.go:1068-1072`). **Not optional.**

Validation is different and **off by default** (`detect/detect.go:39-41`: *"Zero
value means validation is disabled"*). TOML key is `validate` (**381
occurrences**, e.g. `:98`); it binds ~4,000 LOC of AWS/Azure/GCP/HTTP/crypto
bindings + `validation_limits.go` (424) + the full expr language
(`expr.WithContext("ctx")`, `runtime.go:249`).

**Decision:** M10 `exprruntime.filter` = **purpose-built recursive-descent boolean
evaluator in Rust** (L effort, mandatory). M11 `exprruntime.validation` =
**excluded from core, feature-gated `validation`, default-off** (XL).
Falsification hook: compile all 368 shipped expressions and diff against Go
`EvalFilter`.

## 2. Module graph, topological (31 remaining; **29 code modules** — the progress denominator)

Satisfied nodes: the 13 verified (`sigv4`, `words`, `codec`, `validate.result`,
`report.{validation_status,finding,reporter,json,csv,junit,sarif}`, `config.rule`
SUBSET, `sources.attr` SUBSET).

**Wave 1 — leaves, 7-way parallel:** M1 `version` (7 LOC, **no tests**) · M2
`logging` (39, **no tests**) · M3 `color` (65, **no tests**) · M4 `confidence`
(60, T=1) · M5 `ahocorasick` (199, T=5) · M6 `regexp.facade` (200, T=3) · M7
`contextwindow` (411, T=4).

M5: **port the bespoke matcher, do not substitute `aho-corasick`** —
`matcher.go:6-8` imports only `unicode`/`utf8`; the API is
`Compile(patterns, foldASCII)` (`:41`) + `Visit(text, fn)` (`:99`) with an
early-abort contract the crate does not reproduce. M6: `regexp/re2` (13 LOC) +
`regexp/internal` (12 LOC) → **exclude** (optional WASM engine, identical
semantics).

**Wave 2 —** M8 `sources.core` (189, **no tests**, supersedes the `Attr*` subset)
→ M9 `config.full` (1,386 LOC: `config.go` 732, `rule.go` 180, `allowlist.go` 178,
`translate_filters.go` 256, `utils.go` 40; **T=29**; supersedes the `Rule` subset;
carries the embedded catalog). **L.**

**Wave 3 —** M10 `exprruntime.filter` (~1,095 LOC, T=13) **L** ‖ M14 `httpclient`
(735, T=12) **M**.

**Wave 4 —** **M13 `detect.core`** (1,897 LOC: `detect.go` 1,264 + `utils.go` 268
+ `rule_timings.go` 145 + `baseline.go` 81 + `location.go` 80 +
`tiktokenloader.go` 59; **T=26**, `detect_test.go` alone is 3,283 lines) **XL** ‖
M12 `validate.pool` (~200, T=6) **M** — the PORT-TRACK exclusion is now unblocked.

**Wave 5 —** M15 `scm` (255, T=3) ‖ M16 `file`+`common` (608, T=4) ‖ M17
`files`+`stdin` (243, T=1) ‖ M18 `s3` (857, T=10) ‖ M19 `git` (888, **tests
commented out** at `git_test.go:27,32,81`) ‖ M20 `gitlab` (1,657, T=20) ‖ M21
`huggingface` (1,200, T=13) → M22 `github` (1,956, T=31, **XL**, last — async
blast radius).

**Wave 6 —** M23 `report.print` (906, **no tests**) ‖ M24 `report.finding.rest`
(~120) ‖ M25 `detect.deprecated` (245, **no tests**) → M26 `cmd.cli` (2,580, T=6).

**Wave 7 (optional) —** M27 `base` (259, T=5) ‖ M28 `utils` (531, T=2) ‖ M29
`secrets` (50, **no tests**) → M30 `main` (551, **no tests**); M31 `rules` =
fixtures only.

**Critical path: M6 → M9 → M10 → M13.** Highest-leverage single change: **M9 plus
the embedded TOML**, lifting rule coverage 26 → 414 without porting the 14K-LOC
`rules` package.

## 3. Cycles

**None.** Verified: `config`→`exprruntime` has no back-edge; the generator
(`utils/validate.go:12` → `detect` → `config`) is a separate `main`;
`detect`→`validate` has no back-edge; `sources`→{logging, httpclient, scm, sigv4}
has none. Two *near*-cycles handled by splitting: `detect`↔`sources` (M8 core
first, M25 shim last) and `config`↔`exprfilter` (keep `Program` an opaque one-way
handle).

## 4. Dependency candidates (new decisions flagged)

std: TTY (`std::io::IsTerminal`, replaces `go-isatty`), git subprocess,
errgroup/semgroup (`std::thread::scope` + counting semaphore).

Well-known crates: regex→**`regex`** · TOML→**`toml`** · walk→**`ignore`** ·
filetype→**`infer`** · BPE→**`tiktoken-rs`** · diff→**`patch`** ⚠ · CLI→**`clap`**
v4 · log→**`tracing`** · semver→**`semver`** ⚠ (go-version is laxer;
`betterleaks.toml:19-20` uses `v8.25.0`) · HTTP→**`ureq`** (blocking, matches Go's
sync model) or `reqwest` — **NEW DECISION** · GitHub→**`octocrab`** +
`graphql_client` (async→tokio) · reggen→`rand_regex` · archives→**no single
crate**: `zip`+`tar`+`flate2`+`xz2`+`zstd`+`bzip2`+`sevenz-rust2`+`unrar` (format
set confirmed by `go.mod:32-55`).

Port (no crate): `ahocorasick`, `regexp` facade, CSV (done).

**Hard units with NO crate:** `expr-lang` (§1c) and Go `text/template` + Sprig
(§6).

Nothing was added to any `Cargo.toml` by the analyst.

## 5. Non-code artifacts

- `detect/assets/cl100k_base.tiktoken.gz` (`tiktokenloader.go:13`) → copy
  byte-identical, `include_bytes!`, `flate2`, parse `base64 rank` lines
  (`:36-51`) into ranks, feed `tiktoken-rs` from them (never download a vocab).
- `internal/words/words.txt.gz` (`words.go:11`) → **done**.
- **`config/betterleaks.toml`** (9.6K lines, 414 rules; `config.go:22`) → copy
  byte-identical, `include_str!`, **sign it as an M9 source file** — drift here
  silently changes detection.
- `//go:generate` (`main.go:20`) → keep the Go generator upstream and vendor its
  output (Tier A), or a Rust `xtask` (Tier B). `config.tmpl` is *our* template, so
  `minijinja`/`askama` is acceptable there (unlike the user-supplied report
  templates).
- `testdata/` — **216 files**: 34 config TOMLs (M9), 8 report goldens, 13 archives
  (M16), 3 baselines, git repos, 2 `.tmpl` (excluded), `.windowspaths`.
- **`testdata/repos/*/dotGit`** — the Go tests rename `dotGit`↔`.git` around each
  test (`detect_test.go:1737-1738,1822-1823,2904`). The Rust harness must
  reproduce the rename + restore. Easy to silently drop.
- **Build tags: NONE** — `^//go:build` has **0 matches** repo-wide. Only 3
  `//go:embed` sites total.
- Platform code: 6 `runtime.GOOS=="windows"` sites (`sources/common.go:25`,
  `git.go:41`, `scm/clone.go:153` + 3 test) → `cfg!(windows)`.

## 6. Hard / excluded

`report/template.go` — **excluded, confirmed and carried forward** (user-supplied
Go `text/template` through Sprig, `go.mod:12`; `template_test.go` is byte-exact
against the `.tmpl` fixtures; a different engine renders different output, i.e.
not a port). Plus: M11 validation (feature-gated), `regexp/re2` +
`regexp/internal`, M31 `rules` (reclassified as data), M22 `github` (GraphQL +
async), M19 `git` (forked diff parser + tests commented out), M16 archives, M23
print (906 LOC, zero tests).

**Reshape, NEW DECISION:** `detect.Run` returns `iter.Seq[Result]`
(`detect.go:497`) — recommend `impl Iterator<Item=Result>` over an
`mpsc::Receiver` (preserves streaming). Go `any` in filter maps → reuse the
existing `validate::Value` precedent.

## 7. Regex parity — verified

Confirmed: `regexp/regexp.go:91` `syntax.Parse(str, syntax.Perl)` gates every
pattern; `:78` `currentEngine = Stdlib{}`; `dlclark/regexp2` (`go.mod:37`) is
unreferenced.

**Bypass audit:** 6 non-test files import stdlib `"regexp"` directly —
`report/print_pretty.go:6`, `sources/scm/clone.go:10`, `sources/git.go:15`,
`exprruntime/celcompat.go:5`, `exprruntime/bindings_azure.go:15`,
`internal/contextwindow/contextwindow.go:6`. All stdlib RE2, so Rust `regex`
remains correct for all of them. Nothing imports `go-re2` outside
`regexp/re2/re2.go`.

**Accepted constructs:** `[[:alnum:]]` (`:247`), `(?P<name>)` (`:866`, `:6571`),
`\z` (`:6934`,`:8136`,`:8392`), `\x60`, inline flags. No `\p{}`, `(?U)`, `\A`,
lookaround, or backrefs.

**⚠ Silent-semantic divergences (reported, not solved):**

1. **ASCII-vs-Unicode Perl classes — dominant risk.** Go's `\w`/`\d`/`\s`/`\b` are
   ASCII; Rust's are Unicode by default. **371 TOML lines contain `\b` or `\w`** —
   and the corpus deliberately tests non-ASCII (the AWS false positive
   `msgstr "Näytä asiakirjamallikansio."`, `rules/aws.go:59`). Selective
   `(?-u:…)` rewriting is safer than a blanket `RegexBuilder::unicode(false)`.
2. **`\S` cannot be de-Unicoded** — `(?-u:\S)` matches non-ASCII bytes and Rust
   **rejects** it in a UTF-8 `Regex`. Exactly 5 sites
   (`betterleaks.toml:270,1876,2971,6720,7587`); **no `\W`, `\D`, or `\B`
   anywhere**. Those 5 keep Unicode `\S`, diverging only on exotic whitespace
   (U+00A0, U+2028).
3. Three merged mega-patterns (`:1876,4730,5808`, from `MergeRegexps`,
   `utils/generate.go:53-61`) may exceed Rust's default 10 MB compile-size limit —
   unmeasured.
4. Empty-match iteration semantics (`FindAllStringIndex(-1)` vs `find_iter`) —
   verify against `regexp_test.go` (T=3).

## 8. No-test modules (donor-augmentation list)

M23 `report.print` (**906**) · M25 `detect.deprecated` (245) · M8 `sources.core`
(189) · M3 `color` (65) · M2 `logging` (39) · M1 `version` (7) · M30
`generate.main` (551) · M29 `generate.secrets` (50) · within M13:
`rule_timings.go` + `tiktokenloader.go` (204).

**Weakly tested:** M19 `sources.git` (888 LOC, tests commented out) · M31 `rules`
(255 files, T=2) · M17 (T=1/243) · M16 (T=4/608).

## 9. Effort roll-up

S=9 modules (~1,100 LOC) · M=10 (~4,300) · L=8 (~10,000) · XL=2 (~3,850) ·
excluded/data=2 (~18,100). **~19,250 Go LOC remaining to port**, with comparable
test LOC.

## 10. Open questions (not guessed)

1. **Which** signed files actually drifted between `0b4063d7` and `6cf4f1a2` — no
   shell/hash tool available to the analyst this session.
2. Byte length of the three mega-patterns vs Rust's compile-size limit (the grep
   omitted the lines as too long).
3. How far `gitleaks/go-gitdiff` diverges from standard unified diff (the fork
   lives in the module cache, not in-tree) → whether `patch` is a drop-in.
4. The **full operator/literal grammar** across all 368 expressions — the 8-function
   surface is confirmed, but not every `?.`/`??`/`in`/method form was enumerated.
   M10's grammar must be derived from parsing all 368, not from that sample.
5. `tps`/`fps` corpus size across the 255 rule files (only `aws.go` was read) →
   Tier B sizing is an estimate.
6. Observable surface of `internal/color` / `logging` beyond their signatures.
7. `iter.Seq` cancellation semantics — how `ctx` cancel interacts with `yield`'s
   return value was not traced end-to-end.
8. Whether the `detect` crate has consumers **outside**
   `dependencies/betterleaks-rs` in `lensr_git` (M13 replaces it).
9. `sources/github.go`'s GraphQL query count/shape — the real driver of M22's cost
   — unmeasured (only its import block was read).
