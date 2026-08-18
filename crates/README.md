# dependencies/

**Rule (MANDATORY):** every non-registry dependency of `lensr_git` — ports, forks,
or any source we carry ourselves — lives **here**, under
`apps/lensr_git/dependencies/<name>/`, and is referenced with a **relative** path
dep (`{ path = "dependencies/<name>/..." }`) — never an absolute path, `../`, or
another drive. Vendor source-only (no upstream `.git/`/`target/`), keep it a
library (no binaries), and document it below. Plain crates.io crates (`regex`,
`flate2`, …) stay normal version deps and are NOT vendored. Full rule:
`../REQUIREMENTS.md` § 6.

Vendored **library** dependencies of `lensr_git` (source only — no binaries).

- **`betterleaks-rs/`** — the Rust port of the betterleaks/gitleaks family. A Cargo
  workspace of library crates (`codec`, `config`, `detect`, `report`, `sigv4`,
  `sources`, `validate`, `words`). `lensr_git` consumes its **`detect`** crate (the
  secret-detection engine) as the gate's scanner via a path dependency
  (`Cargo.toml` → `detect = { path = "dependencies/betterleaks-rs/detect" }`). The
  other crates are the rest of the port, kept for future gate features (report
  emitters, validation, …). Built as libraries; nothing here is an executable.
