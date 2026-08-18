# PORT-GLOSSARY — betterleaks (Go) → betterleaks-rs (Rust)

Shared target type-name map + naming/error-style decisions. Every `code-port-tdd`
reads this before porting and appends any new shared decision. Keep modules coherent.

## Workspace layout

- Go module `github.com/betterleaks/betterleaks` → Cargo **workspace** `betterleaks-rs`.
- Each Go `internal/<pkg>` → a workspace **member crate** of the same name (e.g.
  `internal/sigv4` → crate `sigv4`). Private-by-default matches Go `internal/`.

## Naming conventions

- Go exported `CamelCase` fn/const → Rust `snake_case` fn / `SCREAMING_SNAKE` const,
  `pub`. Go unexported → private (no `pub`).
- Go `CamelCase` type → Rust `CamelCase` type (unchanged).
- Preserve the exact wire/observable strings (header names, algorithm labels,
  hex digests) byte-for-byte — those are the parity contract.

## Error style

- Go `error` return → Rust `Result<T, E>`. For a leaf module with one failure mode,
  use `Result<T, SigV4Error>` where `SigV4Error` is a small `enum` implementing
  `std::error::Error + Display` (NO `thiserror` crate — hand-write the impls; it's
  a few lines and keeps us dependency-free).
- Preserve the exact Go error text (e.g. `"sigv4: missing access key or secret"`)
  in `Display` so behavior is 1:1 observable.

## Dependency decisions (std-first log)

- **hex encoding** (`encoding/hex`): NO crate — hand-roll lowercase-hex
  (`{:02x}`)-style helper. Trivial, in-scope, keeps std-first.
- **URL / query parsing** (`net/url` via `net/http`): NO crate — hand-roll the
  minimal `scheme://host/path?query` split + percent-decode needed by the tests.
  Do NOT pull `url`.
- **crypto** (`crypto/sha256`, `crypto/hmac`): **JUSTIFIED crate** — Rust std has
  no SHA-256/HMAC, and hand-rolling crypto is out of scope + unsafe. Use
  `sha2` + `hmac` (well-established RustCrypto). Log in PORT-TRACK.md.

## words module decisions (appended)

- Go `words.Result` → Rust **`MatchResult`** (NOT `Result` — that would shadow the
  Rust prelude `Result<T,E>`; renamed as a form-only idiom adaptation). Fields:
  `word_count: usize`, `unique_words: Vec<String>`, `matches: Vec<Match>`.
- Go `words.Match{Word, Len}` → Rust `Match { word: String, len: usize }`.
- Go `HasMatchInList(word, minLen) []Result` (nil or len-1 slice) → Rust
  `has_match_in_list(word: &str, min_len: usize) -> Vec<MatchResult>` — **empty Vec
  = Go nil**, otherwise a single-element Vec (reshape logged in PORT-TRACK.md).
- **`compress/gzip`**: Rust std has NO gzip/DEFLATE → **JUSTIFIED crate `flate2`**.
- **`//go:embed words.txt.gz`** → `include_bytes!("../words.txt.gz")` (asset copied
  byte-identical into the crate; parity of matching depends on it).
- `sync.Once` lazy load → `std::sync::OnceLock<HashSet<Vec<u8>>>`. Dictionary stored
  as line **bytes** so substring lookup is exact-byte like Go's `map[string]` on a
  byte slice. `strings.ToLower` → `str::to_lowercase`.

## codec module decisions (appended)

- Crate `codec` (workspace member). Ports Go `detect/codec` — a multi-pass
  in-place decoder that finds & decodes base64 / hex / percent / unicode segments
  in text, iterating until stable.
- **`logging.Trace()...`** (only internal dep, in `findEncodedSegments`) → **drop /
  no-op** in Rust. Debug tracing is not observable behavior; the tests never assert
  it. FLAG in the ledger (a deliberately-omitted non-behavioral call).
- **base64**: Go uses `encoding/base64` (Std + RawURL, padded & unpadded — see the
  url-safe `-`/`_` and no-`=` test cases). Rust std has NO base64 → **hand-roll the
  decode** (fixed 40-line algorithm; std-first rung 2, in-scope). Do NOT pull a
  base64 crate. Match Go's std detection: try standard then URL-safe, padded/raw.
- **hex** (`encoding/hex`) → hand-roll (reuse the lowercase-hex pattern; sigv4's
  `hex_encode` lives in a different crate — re-implement locally or a tiny shared
  helper; do NOT add a `hex` crate).
- **percent** (`net/url` PathEscape/unescape) → hand-roll percent decode.
- **unicode** (`U+XXXX`, `\uXXXX`) → hand-roll per the source's `unicode.go`.
- `Decoder.decodedMap` cache → `HashMap<String, String>`. `EncodedSegment`,
  `startEnd`, `overlaps`, `toOriginal` → Rust structs/methods (faithful).
- Public API: `Decoder::new()`, `Decoder::decode(&mut self, data: &str,
  predecessors: &[EncodedSegment]) -> (String, Vec<EncodedSegment>)` mirroring Go's
  `Decode(data, predecessors) (string, []*EncodedSegment)`. The test driver loops
  `decode` until it returns zero segments.

## codec module — LOCKED (ported, pending conductor verification)

- **Crate `codec`, edition 2021, ZERO dependencies** (base64 + hex + percent +
  unicode all hand-rolled). One `src/lib.rs` + `src/tests.rs` (`#[cfg(test)] mod
  tests`).
- **Public API produced** (consumers use these exact names):
  - `Decoder { }` with `Decoder::new() -> Decoder` and `decode(&mut self, data:
    &str, predecessors: &[EncodedSegment]) -> (String, Vec<EncodedSegment>)`.
  - `EncodedSegment` — opaque `pub struct` (all fields private, like Go's
    unexported fields). Stores `predecessors: Vec<EncodedSegment>` **by value**
    (owned clone) — not a pointer graph — preserving `toOriginal` recursion.
  - Free fns (port of `segment.go` exports): `tags(&[EncodedSegment]) ->
    Vec<String>`, `current_line(&[EncodedSegment], &str) -> String`,
    `adjust_match_index(&[EncodedSegment], &[i64]) -> Vec<i64>`,
    `segments_with_decoded_overlap(&[EncodedSegment], i64, i64) ->
    Vec<EncodedSegment>`.
- **`startEnd` → private `StartEnd { start: i64, end: i64 }`** (i64 because
  `sub`/`overflow` go negative in `toOriginal` metadata math; slice sites cast to
  `usize` and are always non-negative).
- **encodingKind bit flags** → `const PERCENT_KIND=1, UNICODE_KIND=2, HEX_KIND=4,
  BASE64_KIND=8` (i64). `String()`/`kinds()` ported via `f64::log2` / `2i64.pow`.
- **base64 hand-roll**: `base64_decode(src, map, pad)` is a faithful port of Go
  `encoding/base64` `decode`/`decodeQuantum`; called as `StdEncoding` (map=std
  alphabet, `pad=Some(b'=')`) then `RawURLEncoding` (map=url alphabet, `pad=None`).
  Returns `None` on any `CorruptInputError`. Alphabets are `const` decode maps
  built by a `const fn`.
- **Test helpers hand-rolled (no crates):** `hex_encode_to_string` (lowercase),
  `path_escape` (Go `net/url.PathEscape` = `escape` in `encodePathSegment` mode:
  escape all non-`[A-Za-z0-9\-_.~]` except the reserved-not-escaped set
  `$&+:=@`; escape reserved `/;,?`).

## report / validate decisions (appended)

- Go `report.ValidationStatus` (`type ValidationStatus string`, arbitrary-string
  capable) → Rust crate `report`: `ValidationStatus(Cow<'static,str>)` newtype with
  `const NONE/VALID/NEEDS_VALIDATION/INVALID/REVOKED/UNKNOWN/ERROR`, `from_string`,
  `as_str`, `Display`. NOT a closed enum (validate builds one from dynamic input).
- Crate `validate` depends on crate `report` via a **path dependency**
  (`report = { path = "../report" }`) — cross-crate type identity; reuse
  `report::ValidationStatus`, never re-port it.
- Go `validate.Result` → `validate::ValidationResult` (prelude-shadow). Go `any` →
  `validate::Value` enum (Str/Bool/Int/Float/Null/List/Map/MapAny). `%T` reflection
  name → `go_type_name` APPROXIMATION (flagged). `pool.go`/`cache.go` excluded
  (blocked on `exprruntime`/`sources`/`singleflight`).

## report JSON-emitter decisions (appended)

- **JSON = justified `serde` + `serde_json`** (Rust std has no JSON). Reproduce Go
  `encoding/json` semantics with attributes, NOT idiomatic serde defaults:
  - Go uses the exact PascalCase field name as the key → explicit
    `#[serde(rename = "RuleID")]` etc. on EVERY field.
  - `json:",omitempty"` → `#[serde(skip_serializing_if = ...)]` (`String::is_empty`,
    `HashMap::is_empty`, `Vec::is_empty`, `Option::is_none`, `is_status_none`).
  - `json:"-"` + unexported → `#[serde(skip)]`.
  - `SetIndent("", " ")` → `PrettyFormatter::with_indent(b" ")` + trailing `\n`.
- Go `map[string]any` (Finding.ValidationMeta) → `HashMap<String, serde_json::Value>`
  (JSON-native `any`; distinct from `validate::Value`, whose context is not JSON).
- **Number-formatting parity:** Go prints whole floats as `0`, serde as `0.0`. The
  Go JSON test compares via `Unmarshal`-to-`any` (float64 coercion), so tests
  coerce all numbers to `f64` (`normalize_numbers`) before comparing — matches the
  test's contract. Flagged.
- `ValidationStatus` gains `#[derive(Serialize)] #[serde(transparent)]` (serializes
  as its inner string) — additive; `validate` unaffected.
- **CSV = hand-rolled, NO crate** (`csv.rs`). Reproduce Go `encoding/csv`
  `fieldNeedsQuotes` EXACTLY: quote iff non-empty AND (`\.`, OR contains
  `,`/`"`/CR/LF, OR first rune is whitespace); double embedded `"`; join with `,`;
  terminate records with `\n`. Empty findings → write nothing. (Predates the
  format-lib policy; still valid.)
- **POLICY (operator, 2026-07-12): serialization-format libraries are SANCTIONED**
  (JSON/XML/CSV/TOML/YAML). Prefer the crate over hand-rolling a format. Applied:
  JSON→`serde_json`, XML→`quick-xml`. std-first still governs non-format logic.
- **JUnit XML = `quick-xml` (serde)** (`junit.rs`). Structs mirror Go's xml tags:
  attrs via `#[serde(rename = "@attr")]`, chardata via `#[serde(rename = "$text")]`.
  `<failure>` chardata REUSES `Finding`'s serde JSON (tab-indented) = Go `getData`.
  Test compares by `quick_xml::de::from_str` round-trip + JSON-number canonicalization.
- **SARIF = `serde_json`, BYTE-EXACT** (`sarif.rs`). The Go test does a string compare,
  so wire structs are declared in **Go field order** (serde serializes in decl order)
  and use single-space `PrettyFormatter` + trailing `\n` = Go `SetIndent("", " ")` +
  `Encode`. Consts `DRIVER="betterleaks"`, `VERSION="v8.0.0"`. Consumes `config::Rule`.
- **`config` crate** = minimal `Rule { rule_id, description }` subset (Go `config.Rule`),
  consumed by `report` via a path dependency. Rest of `config` deferred.
- **`sources` crate** = minimal `ATTR_*` `&str` key constants (Go `sources.Attr*`),
  consumed by `report::Finding::attr` via a path dependency. Rest of `sources` deferred.
- **`Reporter` trait** (`reporter.rs`): Go `report.Reporter` interface → `pub trait
  Reporter { fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> }`,
  impl'd by all 4 emitters (delegating to their inherent `write`). Emitter `write`
  methods take `&mut dyn Write` (Go `io.WriteCloser` → `&mut dyn Write`; no `Close`).
  Consts `CWE`/`CWE_DESCRIPTION`/`STDOUT_REPORT_PATH` ported here.
- **`Finding` methods** (`finding.rs`): `mask_secret` uses `f64::round_ties_even` =
  Go `math.RoundToEven` (char-based, multibyte-UTF8 safe); `Finding::redact` masks
  by-value components ONCE (no pointer dedup — see the reshape); `Finding::attr`
  matches `sources::ATTR_*` `&str` consts via `k if k == …` arms; `build_required_sets`
  ports the Cartesian product (empty → empty Vec).

## Shared type identities (append as ported)

- `sigv4::Credentials { access_key, secret_key, session_token }` — Go
  `Credentials{AccessKey, SecretKey, SessionToken}`. `session_token` empty ⇒ omitted.
- `sigv4::Request` — port-local minimal HTTP request (Go took `*http.Request`,
  which Rust std lacks). Fields: `method`, `host`, `path`, `raw_query` (raw string),
  + a private case-insensitive multi-value header list. `Request::new(method, url)`
  hand-parses `scheme://host/path?query`. `set_header(name, value)` = Go
  `Header.Set` (replaces); `header(name) -> String` = Go `Header.Get` (first value
  or `""`). `sign(&mut req, ...)` mutates headers in place, mirroring Go's `Sign`.
- `sigv4::Timestamp { year: i64, month/day/hour/minute/second: u32 }` — replaces
  Go's `time.Time` arg to `signAt`. `Timestamp::now()` = `time.Now().UTC()`.
  Formats `20060102T150405Z` / `20060102`. Derived via std `SystemTime` +
  `civil_from_days` (Howard Hinnant) — no `chrono`/`time` crate.
- `sigv4::SigV4Error` — hand-written `enum` (one variant `MissingCredentials`)
  impl `Display` (text `"sigv4: missing access key or secret"`) + `std::error::Error`.
  NO `thiserror`.
- Public API surface (for consumers): `sign(&mut Request, Option<&[u8]>, region,
  service, Credentials) -> Result<(), SigV4Error>`, `derive_signing_key`,
  `hmac_sha256`, `sha256_hex`, `hex_encode`, `uri_encode`, consts `ALGORITHM`
  (`"AWS4-HMAC-SHA256"`) + `EMPTY_PAYLOAD_SHA`. `sign_at` (injected `Timestamp`)
  is crate-private (test-only, like Go's unexported `signAt`).
