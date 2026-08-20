//! Tests for the file scanner. The chunking rules get the attention because
//! their failure mode is SILENT: a secret sliced across a chunk boundary simply
//! never matches, and nothing reports that it was missed.

use super::*;
use std::io::Cursor;

/// Collect every fragment a reader yields.
fn scan(content: &str, path: &str) -> Vec<Fragment> {
    let mut f = File::new(Cursor::new(content.as_bytes().to_vec()), path);
    let mut out = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut collect).expect("scan");
    out
}

#[test]
fn small_file_is_one_fragment() {
    let frags = scan("line one\nline two\n", "a.txt");
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].raw, "line one\nline two\n");
    assert_eq!(frags[0].start_line, 1, "line numbering is 1-based here");
    assert_eq!(frags[0].attr(ATTR_PATH), "a.txt");
    assert_eq!(frags[0].attr(ATTR_RESOURCE), RESOURCE_FILE_CONTENT);
}

#[test]
fn empty_file_yields_nothing() {
    assert!(scan("", "empty.txt").is_empty());
}

/// A NUL byte in the first chunk marks the content binary and the whole file is
/// skipped — Go reaches the same verdict via `filetype.Match`.
#[test]
fn binary_content_is_skipped() {
    let mut f = File::new(Cursor::new(b"\x00\x01\x02binary".to_vec()), "a.bin");
    let mut out: Vec<Fragment> = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut collect).expect("scan");
    assert!(out.is_empty(), "binary content must not be scanned");
}

/// A NUL AFTER the first chunk does not retro-actively skip — Go only checks at
/// the start of the file.
#[test]
fn binary_check_is_first_chunk_only() {
    let mut content = "a\n\n".repeat(DEFAULT_BUFFER_SIZE / 3 + 10);
    content.push('\0');
    let frags = scan(&content, "late.bin");
    assert!(!frags.is_empty(), "the leading text chunks are still scanned");
}

/// `start_line` accumulates across chunks, so a finding in a later chunk still
/// reports the right line.
#[test]
fn start_line_accumulates_across_chunks() {
    // Enough lines to exceed one 100 kB buffer.
    let line = "0123456789012345678901234567890123456789\n\n";
    let content = line.repeat(DEFAULT_BUFFER_SIZE / line.len() + 200);
    let frags = scan(&content, "big.txt");
    assert!(frags.len() > 1, "expected multiple chunks, got {}", frags.len());
    assert_eq!(frags[0].start_line, 1);
    for w in frags.windows(2) {
        assert!(
            w[1].start_line > w[0].start_line,
            "start_line must advance: {} then {}",
            w[0].start_line,
            w[1].start_line
        );
    }
    // The chunks must reconstruct the original exactly — no bytes lost or
    // duplicated at a boundary.
    let joined: String = frags.iter().map(|f| f.raw.as_str()).collect();
    assert_eq!(joined, content, "chunking must be lossless");
}

/// **The reason boundary-hunting exists.** A chunk boundary is pushed forward to
/// a blank line, so a long unbroken token is not sliced in half.
#[test]
fn chunk_boundary_prefers_a_blank_line() {
    // Fill just past the buffer with NO blank lines, then a blank line, then a
    // token that must survive intact.
    let filler = "x".repeat(DEFAULT_BUFFER_SIZE + 100);
    let token = testkeys::aws(1);
    let content = format!("{filler}\n\n{token}\n");
    let frags = scan(&content, "b.txt");

    let joined: String = frags.iter().map(|f| f.raw.as_str()).collect();
    assert_eq!(joined, content, "lossless");
    assert!(
        frags.iter().any(|f| f.raw.contains(&token)),
        "the token must live wholly inside one fragment"
    );
}

/// **The test the read-ahead exists for.** A token that STRADDLES the 100 kB
/// buffer boundary must end up whole inside one fragment — which is only
/// possible if the boundary hunt reads MORE from the reader rather than merely
/// inspecting what was already buffered.
///
/// An earlier version of this port only inspected the existing chunk, so the
/// hunt was inert and this token would have been sliced in half. Mutation
/// testing surfaced it: removing the carry-over changed nothing, because there
/// never was any.
#[test]
fn token_straddling_the_buffer_boundary_survives_intact() {
    let token = testkeys::aws(1);
    // The first read ends five characters into the token, with NO blank line
    // before it, so the hunt must read forward to the following blank line.
    let filler = "x".repeat(DEFAULT_BUFFER_SIZE - 5);
    let content = format!("{filler}{token}\n\ntrailing\n");
    assert!(
        filler.len() + 5 == DEFAULT_BUFFER_SIZE,
        "precondition: the boundary lands inside the token"
    );

    let frags = scan(&content, "straddle.txt");
    let joined: String = frags.iter().map(|f| f.raw.as_str()).collect();
    assert_eq!(joined, content, "lossless");
    assert!(
        frags.iter().any(|f| f.raw.contains(&token)),
        "the token was split across fragments — the boundary hunt did not read ahead"
    );
}

/// Boundary hunting gives up after MAX_PEEK_SIZE rather than reading forever.
#[test]
fn boundary_hunt_is_bounded() {
    // No blank line anywhere, well past buffer + peek.
    let content = "y".repeat(DEFAULT_BUFFER_SIZE + MAX_PEEK_SIZE + 5_000);
    let frags = scan(&content, "c.txt");
    let joined: String = frags.iter().map(|f| f.raw.as_str()).collect();
    assert_eq!(joined, content, "lossless even with no safe boundary");
    assert!(frags.len() >= 2, "it must still split rather than buffer everything");
}

/// Windows paths are normalised to forward slashes so path rules are portable.
#[test]
fn path_is_slash_normalised() {
    let frags = scan("x\n", r"src\pkg\file.go");
    let p = frags[0].attr(ATTR_PATH);
    if cfg!(windows) {
        assert_eq!(p, "src/pkg/file.go");
    } else {
        assert_eq!(p, r"src\pkg\file.go", "non-Windows leaves the path alone");
    }
}

#[test]
fn symlink_attribute_is_set_when_present() {
    let mut f = File::new(Cursor::new(b"x\n".to_vec()), "real.txt");
    f.symlink = "link.txt".to_string();
    let mut out = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut collect).expect("scan");
    assert_eq!(out[0].attr(ATTR_FS_SYMLINK), "link.txt");
}

/// `full_path` joins container paths with `!`, which is how an archive member
/// is addressed.
#[test]
fn full_path_joins_outer_paths() {
    let mut f = File::new(Cursor::new(Vec::new()), "inner/b.txt");
    assert_eq!(f.full_path(), "inner/b.txt");
    f.outer_paths = vec!["outer.zip".to_string()];
    assert_eq!(f.full_path(), "outer.zip!inner/b.txt");
    f.outer_paths = vec!["a.zip".to_string(), "b.tar".to_string()];
    assert_eq!(f.full_path(), "a.zip!b.tar!inner/b.txt");
}

/// A skip callback drops the fragment without aborting the scan.
#[test]
fn should_skip_filters_fragments() {
    let mut f = File::new(Cursor::new(b"secret\n".to_vec()), "vendor/x.go");
    let skip: SkipFunc = &|attrs: &std::collections::BTreeMap<String, String>| {
        attrs.get(ATTR_PATH).is_some_and(|p| p.starts_with("vendor/"))
    };
    f.should_skip = Some(skip);
    let mut out = Vec::new();
    let mut collect = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut collect).expect("scan");
    assert!(out.is_empty(), "a skipped path yields no fragment");
}
