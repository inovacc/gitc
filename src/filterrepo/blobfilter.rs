//! Redact blob text (Rust port of git-filter-repo's _tweak_blob substitution core).
//!
//! Applies a [`ReplaceRules`] set to a blob's data in place (the substitution core
//! of git-filter-repo's `_tweak_blob`). Binary blobs (a NUL byte within the first
//! 8 KiB) are left untouched; text blobs get the literal substitutions in order,
//! then the regex substitutions in order (replacements are literal — no backref
//! expansion). Deterministic, no I/O.

use super::records::Blob;
use super::replacetext::ReplaceRules;

/// How much of a blob is inspected for a NUL byte (git-filter-repo's 8 KiB check).
const BINARY_SCAN_LIMIT: usize = 8192;

/// Apply `rules` to `blob`'s data in place.
pub fn replace_blob_text(blob: &mut Blob, rules: &ReplaceRules) {
    if rules.empty() {
        return;
    }
    if is_binary(&blob.data) {
        return;
    }

    for lit in &rules.literals {
        blob.data = replace_all_bytes(&blob.data, &lit.from, &lit.to);
    }
    for rr in &rules.regexes {
        // Literal replacement — unlike Python's re.sub we do NOT expand
        // backreferences in replace-text replacements (matches `ReplaceAllLiteral`).
        blob.data = rr
            .re
            .replace_all(&blob.data, regex::bytes::NoExpand(&rr.to))
            .into_owned();
    }
}

/// Whether `data` looks binary: a NUL byte within the first [`BINARY_SCAN_LIMIT`].
fn is_binary(data: &[u8]) -> bool {
    let limit = data.len().min(BINARY_SCAN_LIMIT);
    data[..limit].contains(&0)
}

/// Replace every non-overlapping occurrence of `from` in `hay` with `to` (Go
/// `bytes.ReplaceAll`). `from` is never empty here (replacetext skips empty literals).
fn replace_all_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if i + from.len() <= hay.len() && &hay[i..i + from.len()] == from {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filterrepo::replacetext::{parse_replace_rules, ReplaceRules};

    fn rules(input: &str) -> ReplaceRules {
        parse_replace_rules(input.as_bytes()).expect("parse")
    }

    #[test]
    fn literal_and_regex() {
        let r = rules("mod==>modified-by-gremlins\nregex:se+cret\n");
        let mut blob = Blob {
            data: b"this mod has a seecret value".to_vec(),
            ..Default::default()
        };
        replace_blob_text(&mut blob, &r);
        assert_eq!(
            blob.data,
            b"this modified-by-gremlins has a ***REMOVED*** value".to_vec()
        );
    }

    #[test]
    fn binary_untouched() {
        let r = rules("mod==>X\n");
        let original = b"mod\x00mod".to_vec();
        let mut blob = Blob {
            data: original.clone(),
            ..Default::default()
        };
        replace_blob_text(&mut blob, &r);
        assert_eq!(blob.data, original, "binary blob must not be modified");
    }

    #[test]
    fn empty_rules_noop() {
        let mut blob = Blob {
            data: b"unchanged".to_vec(),
            ..Default::default()
        };
        replace_blob_text(&mut blob, &ReplaceRules::default());
        assert_eq!(blob.data, b"unchanged");
    }
}
