//! History-scrub / remediation engine — a Rust port of git-filter-repo's
//! fast-export/fast-import rewrite pipeline. Purges file paths and redacts blob
//! text by rewriting a repo's history through `git fast-export` → in-stream
//! filter → `git fast-import`.
//!
//! Behind the off-by-default `scrub` cargo feature so the base gate binary (the
//! hot path — every git invocation routes through the gate) keeps its lean supply
//! chain: `regex` and the rewrite code compile only when `scrub` is enabled.
//!
//! Structured as a clean module DAG. Leaves: [`bytesutil`], [`idmap`],
//! [`pathquoting`], [`gitutils`]; stream model + rules: [`records`], [`pathspec`],
//! [`sanity`], [`cleanup`]; transforms: [`parser`], [`pathfilter`], [`replacetext`],
//! [`commitfilter`], [`blobfilter`]; orchestrator: [`pipeline`].

// Some `pub` items are consumed only by the CLI seam that will wire `git scrub`,
// not yet present — suppress dead-code noise; every item is exercised by tests.
#![allow(dead_code)]

pub mod blobfilter;
pub mod bytesutil;
pub mod cleanup;
pub mod commitfilter;
pub mod gitutils;
pub mod identity;
pub mod idmap;
pub mod parser;
pub mod pathfilter;
pub mod pathquoting;
pub mod pathspec;
pub mod pipeline;
pub mod records;
pub mod replacetext;
pub mod sanity;
