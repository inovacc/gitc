//! Dictionary-substring matching over an embedded NLTK wordlist (faithful 1:1
//! port of Go `internal/words`).
//!
//! `has_match_in_list` walks a word and, at each start position, checks every
//! substring of length >= `min_len` against the dictionary. It aggregates all
//! matches (duplicates included in the count) plus the set of unique words.
//!
//! Reshape notes (vs Go):
//! - `Result` → [`MatchResult`] (Go's type name `Result` would shadow Rust's
//!   prelude `Result<T, E>`; renamed as a form-only adaptation).
//! - `HasMatchInList(...) []Result` (nil or a len-1 slice) → returns a
//!   `Vec<MatchResult>` where an **empty Vec == Go's nil**.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

use flate2::read::GzDecoder;

/// The embedded gzip-compressed NLTK wordlist (mirrors Go's `//go:embed`).
static COMPRESSED_WORDS: &[u8] = include_bytes!("../words.txt.gz");

/// Lazily-decompressed dictionary. Lines are stored as raw bytes so substring
/// lookup is exact-byte, matching Go's `map[string]struct{}` keyed on a byte
/// slice. Mirrors Go's `sync.Once`-guarded lazy load.
fn dictionary() -> &'static HashSet<Vec<u8>> {
    static DICT: OnceLock<HashSet<Vec<u8>>> = OnceLock::new();
    DICT.get_or_init(|| {
        let mut set = HashSet::new();
        // Safe to panic on a decode error: it implies a corrupted embedded asset.
        let reader = BufReader::new(GzDecoder::new(COMPRESSED_WORDS));
        for line in reader.split(b'\n') {
            let word = line.expect("corrupted embedded wordlist");
            if !word.is_empty() {
                set.insert(word);
            }
        }
        set
    })
}

/// A single dictionary hit: the matched substring and its byte length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub word: String,
    pub len: usize,
}

/// Aggregated matches for one input word (Go's `words.Result`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    /// Total match count, including duplicate substrings at different positions.
    pub word_count: usize,
    /// The set of distinct matched words (order unspecified, like Go's map).
    pub unique_words: Vec<String>,
    pub matches: Vec<Match>,
}

/// Find all dictionary words that appear as substrings of `word` (each at least
/// `min_len` bytes long). Returns a single-element `Vec` with the aggregated
/// [`MatchResult`], or an **empty `Vec`** when there are no matches (Go's `nil`).
pub fn has_match_in_list(word: &str, min_len: usize) -> Vec<MatchResult> {
    let dict = dictionary();

    let word = word.to_lowercase();
    let wb = word.as_bytes();
    if wb.len() < min_len {
        return Vec::new();
    }

    let mut matches: Vec<Match> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    // Walk the word: at each start position, try every substring length >= min_len.
    for start in 0..=(wb.len() - min_len) {
        let mut length = min_len;
        while start + length <= wb.len() {
            let sub = &wb[start..start + length];
            if dict.contains(sub) {
                seen.insert(sub.to_vec());
                matches.push(Match {
                    word: String::from_utf8_lossy(sub).into_owned(),
                    len: length,
                });
            }
            length += 1;
        }
    }

    if matches.is_empty() {
        return Vec::new();
    }

    let unique_words: Vec<String> = seen
        .iter()
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();

    vec![MatchResult {
        word_count: matches.len(),
        unique_words,
        matches,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_match_in_list_cases() {
        struct Case {
            name: &'static str,
            word: &'static str,
            min_len: usize,
            want_nil: bool,
            want_unique_words: &'static [&'static str],
            want_min_match_count: usize,
        }
        let cases = [
            Case { name: "empty string", word: "", min_len: 3, want_nil: true, want_unique_words: &[], want_min_match_count: 0 },
            Case { name: "shorter than minLen", word: "ab", min_len: 3, want_nil: true, want_unique_words: &[], want_min_match_count: 0 },
            Case { name: "no dictionary substring", word: "xyzabc", min_len: 3, want_nil: true, want_unique_words: &[], want_min_match_count: 0 },
            Case { name: "exact word", word: "pass", min_len: 3, want_nil: false, want_unique_words: &["pass"], want_min_match_count: 1 },
            Case { name: "prefix and middle matches", word: "password", min_len: 3, want_nil: false, want_unique_words: &["pass", "password", "sword", "word"], want_min_match_count: 4 },
            Case { name: "match in middle", word: "xxwordxx", min_len: 3, want_nil: false, want_unique_words: &["word"], want_min_match_count: 1 },
            Case { name: "minLen filters shorter", word: "word", min_len: 4, want_nil: false, want_unique_words: &["word"], want_min_match_count: 1 },
            Case { name: "minLen 4 excludes 3-char match", word: "aba", min_len: 4, want_nil: true, want_unique_words: &[], want_min_match_count: 0 },
        ];

        for c in cases {
            let got = has_match_in_list(c.word, c.min_len);
            if c.want_nil {
                assert!(got.is_empty(), "{}: HasMatchInList = {got:?}, want nil", c.name);
                continue;
            }
            assert!(!got.is_empty(), "{}: got nil, want result with {:?}", c.name, c.want_unique_words);
            let r = &got[0];
            assert!(
                r.word_count >= c.want_min_match_count,
                "{}: word_count = {}, want at least {}",
                c.name, r.word_count, c.want_min_match_count
            );
            let mut got_unique = r.unique_words.clone();
            got_unique.sort();
            let mut want_unique: Vec<String> = c.want_unique_words.iter().map(|s| s.to_string()).collect();
            want_unique.sort();
            assert_eq!(got_unique, want_unique, "{}: unique_words mismatch", c.name);
        }
    }

    // Differential parity: golden captured from the Go source on a novel input
    // ("handshake", min_len 3) NOT covered by the ported cases. Same embedded
    // wordlist + same walk ⇒ identical count, unique set, AND ordered match list
    // (the walk is deterministic: start ascending, then length ascending).
    #[test]
    fn diff_handshake_matches_go_golden() {
        let got = has_match_in_list("handshake", 3);
        assert_eq!(got.len(), 1);
        let r = &got[0];

        assert_eq!(r.word_count, 4);

        let mut unique = r.unique_words.clone();
        unique.sort();
        assert_eq!(unique, vec!["hand", "hands", "handshake", "shake"]);

        let ordered: Vec<(String, usize)> =
            r.matches.iter().map(|m| (m.word.clone(), m.len)).collect();
        assert_eq!(
            ordered,
            vec![
                ("hand".to_string(), 4),
                ("hands".to_string(), 5),
                ("handshake".to_string(), 9),
                ("shake".to_string(), 5),
            ]
        );
    }
}
