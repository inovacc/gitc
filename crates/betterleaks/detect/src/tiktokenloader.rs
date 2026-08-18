//! Port of Go `detect/tiktokenloader.go` — the BPE tokenizer behind
//! `filter.tokenRatio` and `failsTokenEfficiency`.
//!
//! ## What it decides
//!
//! 121 shipped filter expressions call `filter.tokenRatio`. The idea is that a
//! real secret is high-entropy and tokenizes BADLY — many tokens for few
//! characters — while an English-looking false positive tokenizes well. The
//! ratio of bytes to tokens separates them.
//!
//! Without a tokenizer the ratio is 0 and `failsTokenEfficiency` is false,
//! which is exactly how Go behaves when `tokenizerProvider` is nil. That is a
//! faithful degradation rather than a hole — but it also means 121 filters were
//! doing nothing, so this is not cosmetic.
//!
//! ## The vocabulary is Go's own file
//!
//! `assets/cl100k_base.tiktoken.gz` is copied BYTE FOR BYTE from the Go tree
//! and embedded the same way. The BPE algorithm is a published one and
//! `tiktoken-rs` implements it; what must not drift is the VOCABULARY, because
//! a different rank table gives different token counts and therefore different
//! findings. Taking the ranks from Go's own asset removes that risk entirely —
//! there is no second copy to fall out of date.

use base64::Engine;
// tiktoken-rs types its maps with FxBuildHasher, so the rank table must be
// built with the same hasher rather than converted at the boundary - a
// 100k-entry rehash on every construction for nothing.
use rustc_hash::FxHashMap;
use std::io::Read;
use std::sync::OnceLock;

/// Go's `//go:embed assets/cl100k_base.tiktoken.gz`.
const BPE_DATA: &[u8] = include_bytes!("../assets/cl100k_base.tiktoken.gz");

/// The cl100k_base splitting pattern, from the tiktoken specification.
///
/// It is part of the ENCODING, not an implementation detail: change it and the
/// same text tokenizes differently even with identical ranks.
const CL100K_PATTERN: &str = r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+";

/// Go `TiktokenLoader.LoadTiktokenBpe` — gunzip, then `base64 rank` per line.
///
/// A malformed line is SKIPPED rather than fatal, which is Go's behaviour
/// (`len(parts) != 2 { continue }`). A bad base64 or rank IS fatal, also as in
/// Go: those mean the asset is corrupt, and a partially-loaded vocabulary would
/// silently change every token count.
pub fn load_tiktoken_bpe() -> Result<FxHashMap<Vec<u8>, u32>, String> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(BPE_DATA)
        .read_to_string(&mut text)
        .map_err(|e| format!("cl100k_base: {e}"))?;

    let mut ranks = FxHashMap::default();
    ranks.reserve(100_256);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 2 {
            continue;
        }
        let token = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|e| format!("cl100k_base: bad token encoding: {e}"))?;
        let rank: u32 = parts[1]
            .parse()
            .map_err(|_| format!("cl100k_base: bad rank {:?}", parts[1]))?;
        ranks.insert(token, rank);
    }
    Ok(ranks)
}

/// The tokenizer, built once.
///
/// Go uses a `sync.Once` per detector and logs a warning if construction fails,
/// leaving the tokenizer nil. Same here: a failure degrades to "no tokenizer"
/// with a warning rather than aborting a scan, because a scan without token
/// ratios still finds secrets.
pub struct Cl100kTokenizer {
    bpe: tiktoken_rs::CoreBPE,
}

static SHARED: OnceLock<Option<Cl100kTokenizer>> = OnceLock::new();

impl Cl100kTokenizer {
    /// Go `(*Detector).Tokenizer` — the shared, lazily built instance.
    ///
    /// `None` when the asset could not be loaded, which callers treat exactly
    /// as Go treats a nil tokenizer.
    pub fn shared() -> Option<&'static Cl100kTokenizer> {
        SHARED
            .get_or_init(|| match Cl100kTokenizer::new() {
                Ok(t) => Some(t),
                Err(e) => {
                    logging::warn()
                        .msg(&format!("Could not initialize cl100k_base tiktokenizer: {e}"));
                    None
                }
            })
            .as_ref()
    }

    pub fn new() -> Result<Cl100kTokenizer, String> {
        let ranks = load_tiktoken_bpe()?;
        // No special tokens: `tokenRatio` measures a SECRET, and a secret that
        // happened to contain `<|endoftext|>` must be counted as the literal
        // bytes it is, not as one control token.
        let bpe = tiktoken_rs::CoreBPE::new(ranks, FxHashMap::default(), CL100K_PATTERN)
            .map_err(|e| format!("cl100k_base: {e}"))?;
        Ok(Cl100kTokenizer { bpe })
    }
}

impl exprruntime::Tokenizer for Cl100kTokenizer {
    /// Go `tiktoken.Encode(text, nil, nil)` — only the COUNT is used.
    fn encode_len(&self, text: &str) -> usize {
        self.bpe.encode_ordinary(text).len()
    }
}

#[cfg(test)]
mod tests;
