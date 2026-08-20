# References — secret detection & git history rewriting

Curated external tools relevant to gitc's forensic model. gitc logs git argv
and environment **raw and unredacted** by design (see the design spec and
README), so secrets *can* land both in a repository's history and in gitc's own
audit DB. These tools are the companion detect → remove toolchain for that
risk. Each entry notes what it is, how it relates to gitc, and the canonical
usage.

## git-filter-repo — history rewriter (remove secrets/files from all history)

- **Repo:** https://github.com/newren/git-filter-repo
- **Tutorial:** https://andrewlock.net/rewriting-git-history-simply-with-git-filter-repo
- **What:** The modern, recommended replacement for `git filter-branch`. A
  single-file Python script — install by dropping `git-filter-repo` onto your
  `$PATH`. Rewrites entire history: move files into subdirs, delete paths,
  replace text/credentials across every commit.
- **Canonical usage:**
  - Remove a file from all history: `git filter-repo --path secrets.env --invert-paths`
  - Replace secret strings everywhere: `git filter-repo --replace-text banned.txt`
- **Relevance to gitc:** the primary remediation when a real secret was
  committed to a repo gitc audited. gitc records *that* it happened; filter-repo
  removes it from history. Git itself now points users here over `filter-branch`.

## BFG Repo-Cleaner — fast, simple history cleaner

- **Repo:** https://github.com/rtyley/bfg-repo-cleaner
- **Docs:** https://rtyley.github.io/bfg-repo-cleaner/
- **What:** A simpler, much faster (10–720×) alternative to `git filter-branch`
  for the common cases: stripping big blobs and removing passwords/credentials.
  Written in Scala, runs on the JVM (a single `bfg.jar`).
- **Canonical usage:**
  - `bfg --replace-text banned.txt repo.git` (redact matched strings to `***REMOVED***`)
  - `bfg --strip-blobs-bigger-than 1M repo.git`
- **Relevance to gitc:** the low-friction option for the two most common
  cleanups (secrets, oversized blobs). git-filter-repo is more general; BFG is
  faster for its narrower scope. Pick BFG for quick credential purges,
  filter-repo for anything structural.

## gitleaks — secret detection (Go)

- **Repo:** https://github.com/gitleaks/gitleaks
- **What:** A widely used SAST tool for detecting hardcoded secrets (API keys,
  tokens, passwords) in git repos, directories, and stdin. Written in Go;
  TOML-configurable rules (`useDefault` + custom rules), multiple report
  formats. Scanning modes: `git`, `dir`, `stdin`.
- **Canonical usage:**
  - Scan history: `gitleaks git .`
  - Scan a directory/working tree: `gitleaks dir .`
  - Pre-commit hook via `.pre-commit-config.yaml` (repo `gitleaks/gitleaks`),
    bypass with `SKIP=gitleaks git commit ...`.
- **Relevance to gitc:** the *detection* half. Because gitc's audit log captures
  secrets verbatim, gitleaks is the natural pre-flight (catch secrets before
  they are committed/audited) and post-hoc scanner. Being Go, it is also the
  most plausible candidate for direct integration into gitc (library or
  subprocess) — see backlog.
