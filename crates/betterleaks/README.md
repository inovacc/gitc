# betterleaks-rs

A faithful **1:1, test-first, standard-library-first** Rust port of selected
modules from [betterleaks](https://github.com/betterleaks/betterleaks) (Go), a
gitleaks-family secret scanner. Produced with the Isomorph code-porting suite
(`/code:port:go2rust`).

> **Scope:** this is a *pilot* port, not a full one. betterleaks is ~41K LOC with
> a hard parity wall (lookahead/backreference regex via `regexp2` + RE2-in-WASM
> via `go-re2`, which Rust std/`regex` cannot reproduce). This workspace ports
> self-contained leaf modules to validate the porting pipeline end-to-end.

## Ported modules

| Crate | Source (Go) | Status | Parity evidence |
|-------|-------------|--------|-----------------|
| `sigv4` | `internal/sigv4` | ✅ verified | 7/7 tests incl. the canonical AWS golden vector + a differential golden captured from the Go source on a novel input, matched byte-for-byte |
| `words` | `internal/words` | ✅ verified | 2/2 tests: the ported 8-case table + a differential golden (`"handshake"`) matched exactly, incl. match order |
| `codec` | `detect/codec` | ✅ verified | 4/4 tests: the 18-case decoder table × raw/percent/hex (54 assertions) + a differential golden on novel inputs pinning the base64 threshold + multi-pass. **Zero dependencies** |
| `report` | `report` (`validation_status`, `Finding` + methods, `Reporter` trait, JSON + CSV + JUnit + SARIF emitters) | ✅ verified | 27/27 tests: `ValidationStatus`; JSON/CSV/JUnit/SARIF (fixture + differential each); `Finding` methods (14 `finding_test.go` tests); the `Reporter` trait (`dyn` dispatch). **`serde_json`** + **`quick-xml`**; CSV hand-rolled. `template` excluded (hard unit) |
| `config` | `config` (`Rule` subset) | ✅ verified | Minimal `Rule { rule_id, description }` consumed by SARIF. Rest of `config` deferred. Zero deps |
| `sources` | `sources` (`Attr*` consts) | ✅ verified | Minimal attribute-key consts consumed by `Finding::attr`. Rest of `sources` deferred. Zero deps |
| `validate` | `internal/validate` (`result.go`) | ✅ verified | 3/3 tests: ported `BetterStatus` + `parseResultMap` + a **49-cell `BetterStatus` differential** from the Go source. Consumes `report::ValidationStatus`. `pool`/`cache` excluded (blocked on `exprruntime`). Zero deps |

See `PORT-TRACK.md` (ledger) and `PORT-GLOSSARY.md` (shared type/naming/error decisions).

## Build & test

```
cargo test            # whole workspace
cargo test -p sigv4   # one crate
```

## Provenance & drift

Every module is **signed** to the source commit + per-file SHA-256 in
[`PORT-PROVENANCE.json`](PORT-PROVENANCE.json) (source `betterleaks` @ `0b4063d7`).
Because the source keeps moving, run **`/code:port:drift`** after pulling new source:
it re-hashes each module's source files against the manifest and flags any that
**drifted** (source changed since porting), so only the altered code is re-ported.
15 modules signed (13 verified + 2 excluded hard units).

## Std-first

No gratuitous dependencies. Crates added, each justified: `sha2` + `hmac`
(SHA-256/HMAC, for `sigv4`), `flate2` (gzip, for `words`), and — for `report`'s
emitters — `serde` + `serde_json` (JSON) and `quick-xml` (XML). Serialization-format
libraries (JSON/XML/CSV/TOML/YAML) are a sanctioned dependency category; everything
else stays std-first — hex/URI/URL-query/percent/calendar math, the dictionary walk,
the whole `codec` decoder, and the CSV quoting are all hand-rolled in std. Every
dependency decision is logged in `PORT-TRACK.md`.

## License

Faithful ports preserve the upstream license — see betterleaks' `LICENSE`.
