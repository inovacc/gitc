//! Port of Go `internal/ahocorasick` (`matcher.go`) — the detector's
//! allocation-free keyword matcher.
//!
//! The Go implementation is itself derived from `github.com/RRethy/ahocorasick`
//! (MIT). This is a faithful 1:1 port of the BESPOKE matcher, not a swap to the
//! `aho-corasick` crate: the API is `Compile(patterns, foldASCII)` + `Visit(text,
//! fn)` with an early-abort contract (`fn` returning false stops traversal) that
//! the crate does not reproduce, and the offset bookkeeping for Unicode runes
//! that fold to ASCII is specific to this design.
//!
//! **Allocation parity (flagged):** Go asserts zero allocations per scan with
//! `testing.AllocsPerRun` (`TestVisitASCIIAllocations`). Rust std has no
//! equivalent, so that assertion is NOT ported. The structural property is
//! preserved — `visit` scans with a 128-entry STACK array and only falls back to
//! the heap when a pattern exceeds it, exactly as Go's `localStarts [128]int`
//! does — but it is unasserted here.

/// Number of source-offset slots kept on the stack, matching Go's
/// `var localStarts [128]int`.
const STACK_STARTS: usize = 128;

/// Go `ahocorasick.Matcher` — a flat Aho-Corasick DFA. Pattern IDs are their
/// input indexes. A compiled Matcher is read-only and safe to share across
/// concurrent scans (Rust gives that statically via `&Matcher: Send + Sync`).
pub struct Matcher {
    /// Flattened `[state][byte]` table. Every entry is populated, including
    /// failure transitions, so `visit` needs one lookup per input byte.
    transitions: Vec<u32>,

    /// Pattern IDs completed at each state, INCLUDING those inherited through
    /// failure links — which is how overlapping matches are found. Order is
    /// load-bearing: a state's own outputs come before inherited ones.
    outputs: Vec<Vec<u32>>,

    /// Each pattern's matcher-byte length, indexed by pattern ID.
    lengths: Vec<usize>,

    /// Bounds the source-offset ring used by `visit`.
    max_length: usize,

    /// Makes ASCII matching case-insensitive. `visit` also recognizes Unicode
    /// runes whose simple-fold set contains an ASCII byte.
    fold_ascii: bool,
}

/// Go's build-time `node`. Uses a map for sparse edges, exactly as Go does,
/// before the dense table is materialized.
struct Node {
    next: std::collections::BTreeMap<u8, u32>,
    fail: u32,
    out: Vec<u32>,
}

impl Node {
    fn new() -> Node {
        Node {
            next: std::collections::BTreeMap::new(),
            fail: 0,
            out: Vec::new(),
        }
    }
}

impl Matcher {
    /// Go `Compile`. When `fold_ascii` is true, ASCII case is ignored.
    pub fn compile(patterns: &[&str], fold_ascii: bool) -> Matcher {
        let mut nodes: Vec<Node> = vec![Node::new()];
        let mut lengths = vec![0usize; patterns.len()];
        let mut max_length = 0usize;

        for (id, pattern) in patterns.iter().enumerate() {
            let mut state = 0u32;
            let bytes = pattern.as_bytes();
            // Go measures patterns in BYTES (`len(pattern)`), not chars.
            lengths[id] = bytes.len();
            max_length = max_length.max(bytes.len());
            for &raw in bytes {
                let b = fold(raw, fold_ascii);
                let next = match nodes[state as usize].next.get(&b) {
                    Some(&n) => n,
                    None => {
                        let n = nodes.len() as u32;
                        nodes[state as usize].next.insert(b, n);
                        nodes.push(Node::new());
                        n
                    }
                };
                state = next;
            }
            nodes[state as usize].out.push(id as u32);
        }

        // A dense table costs more memory than maps, but lets `visit` advance
        // with one indexed lookup per byte. Fill missing edges from each state's
        // failure state so the scan never walks the failure chain.
        let mut transitions = vec![0u32; nodes.len() * 256];
        let mut queue: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
        let root_edges: Vec<(u8, u32)> = nodes[0].next.iter().map(|(&b, &c)| (b, c)).collect();
        for (b, child) in root_edges {
            transitions[b as usize] = child;
            queue.push_back(child);
        }

        while let Some(state) = queue.pop_front() {
            let fail = nodes[state as usize].fail;
            // Inherit the failure state's outputs. BFS guarantees `fail` sits at
            // a shallower depth and was processed first, so this is deterministic
            // even though Go iterates a map (whose order is randomized) — the
            // randomness only permutes states WITHIN a level.
            let inherited = nodes[fail as usize].out.clone();
            if !inherited.is_empty() {
                nodes[state as usize].out.extend_from_slice(&inherited);
            }
            let base = state as usize * 256;
            let fail_base = fail as usize * 256;
            for b in 0..256usize {
                match nodes[state as usize].next.get(&(b as u8)).copied() {
                    Some(child) => {
                        nodes[child as usize].fail = transitions[fail_base + b];
                        transitions[base + b] = child;
                        queue.push_back(child);
                    }
                    None => {
                        transitions[base + b] = transitions[fail_base + b];
                    }
                }
            }
        }

        let outputs = nodes.into_iter().map(|n| n.out).collect();
        Matcher {
            transitions,
            outputs,
            lengths,
            max_length,
            fold_ascii,
        }
    }

    /// Go `Visit` — call `f` for every match. Returning false stops traversal.
    /// Offsets are SOURCE byte offsets, even where a multi-byte rune folded to a
    /// single matcher byte.
    pub fn visit<F>(&self, text: &str, mut f: F)
    where
        F: FnMut(usize, usize, usize) -> bool,
    {
        let mut state = 0u32;
        // Go: `var localStarts [128]int; starts := localStarts[:]` — and the ring
        // stays 128 wide even when maxLength is smaller, so the modulus below is
        // over 128, not over maxLength.
        let mut local_starts = [0usize; STACK_STARTS];
        let mut heap_starts: Vec<usize>;
        let starts: &mut [usize] = if self.max_length > STACK_STARTS {
            heap_starts = vec![0usize; self.max_length];
            &mut heap_starts
        } else {
            &mut local_starts
        };

        let bytes = text.as_bytes();
        let mut position = 0usize;
        let mut i = 0usize;

        while i < bytes.len() {
            let mut b = bytes[i];
            let mut size = 1usize;

            if self.fold_ascii && b >= 0x80 {
                // Go: utf8.DecodeRuneInString. A rune with no ASCII fold RESETS
                // the DFA to the root and is skipped whole.
                let (r, rune_size) = decode_rune(&bytes[i..]);
                match fold_rune_ascii(r) {
                    Some(folded) => {
                        b = folded;
                        size = rune_size;
                    }
                    None => {
                        state = 0;
                        i += rune_size;
                        continue;
                    }
                }
            } else {
                b = fold(b, self.fold_ascii);
            }

            // Patterns are measured in matcher bytes, while a Unicode rune that
            // folds to ASCII occupies multiple source bytes. Keep the source
            // start of the last `starts.len()` matcher bytes so callbacks still
            // receive byte offsets.
            let ring = starts.len();
            starts[position % ring] = i;
            state = self.transitions[state as usize * 256 + b as usize];
            for &id in &self.outputs[state as usize] {
                let end = i + size;
                let mut start = end;
                let length = self.lengths[id as usize];
                if length > 0 {
                    // position + 1 >= length holds because a match only
                    // completes after `length` matcher bytes were consumed.
                    start = starts[(position + 1 - length) % ring];
                }
                if !f(id as usize, start, end) {
                    return;
                }
            }
            position += 1;
            i += size;
        }
    }
}

/// Go `foldRuneASCII` — the ASCII member of a rune's Unicode simple-fold set.
///
/// Rust std has NO `unicode.SimpleFold`. Rather than approximate the fold orbit
/// with `to_lowercase`/`to_uppercase` (which gets `U+0130`/`U+0131` wrong), this
/// encodes the exhaustive answer captured from the Go source itself: sweeping
/// every valid rune through Go's own `foldRuneASCII` yields exactly TWO non-ASCII
/// runes with an ASCII fold. See `.scripts/05-B_gen_fold_golden.ps1` and the
/// `fold_rune_ascii_matches_go_golden` test.
fn fold_rune_ascii(r: char) -> Option<u8> {
    if (r as u32) < 0x80 {
        return Some(fold(r as u8, true));
    }
    match r {
        '\u{017F}' => Some(b's'), // LATIN SMALL LETTER LONG S
        '\u{212A}' => Some(b'k'), // KELVIN SIGN
        _ => None,
    }
}

/// Go `fold`.
fn fold(b: u8, enabled: bool) -> u8 {
    if enabled && b.is_ascii_uppercase() {
        b + (b'a' - b'A')
    } else {
        b
    }
}

/// Go `utf8.DecodeRuneInString`, over bytes. Returns `(rune, size)`; an invalid
/// sequence yields `(U+FFFD, 1)` exactly as Go does — which then takes the
/// no-ASCII-fold path and resets the DFA.
fn decode_rune(bytes: &[u8]) -> (char, usize) {
    match std::str::from_utf8(&bytes[..bytes.len().min(4)]) {
        Ok(s) => match s.chars().next() {
            Some(c) => (c, c.len_utf8()),
            None => (char::REPLACEMENT_CHARACTER, 1),
        },
        Err(e) => {
            // Decode just the first well-formed prefix, if any.
            let valid = e.valid_up_to();
            if valid > 0 {
                let s = std::str::from_utf8(&bytes[..valid]).expect("valid prefix");
                match s.chars().next() {
                    Some(c) => (c, c.len_utf8()),
                    None => (char::REPLACEMENT_CHARACTER, 1),
                }
            } else {
                (char::REPLACEMENT_CHARACTER, 1)
            }
        }
    }
}

#[cfg(test)]
mod tests;
