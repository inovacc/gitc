//! Port of Go `sources/file.go` + the chunking helper from `common.go` — the
//! filesystem content scanner.
//!
//! ## Scope: the NON-ARCHIVE path
//!
//! Go's `File.Fragments` first asks `mholt/archives` whether the content is an
//! archive or a compressed stream and, if so, descends into it
//! (`extractorFragments` / `decompressorFragments`). That descent is DEFERRED:
//! PORT-PLAN records that no single Rust crate covers `archives`' format set,
//! which spans zip, tar, gzip, xz, zstd, bzip2, 7z, brotli, lz4, rar and more —
//! eight-plus crates assembled by hand.
//!
//! What is ported is the path every ordinary file takes: chunked reads, binary
//! detection, and safe-boundary splitting. [`File::max_archive_depth`] exists and
//! is honoured as a gate (0 = no descent, which is what this port always does),
//! so enabling archives later is additive rather than a reshape.
//!
//! ## Why chunking is not just "read the file"
//!
//! Content is read in 100 KB chunks, and a chunk boundary is pushed forward (up
//! to 25 KB) until it lands after two consecutive newlines. Without that a
//! secret straddling a boundary would be split in half and never match. The
//! fragment's `start_line` is tracked across chunks so locations stay correct.

use crate::{Fragment, SkipFunc, ATTR_FS_SYMLINK, ATTR_PATH, ATTR_RESOURCE, INNER_PATH_SEPARATOR,
            RESOURCE_FILE_CONTENT};
use std::io::Read;

/// Go `defaultBufferSize` — 100 kB.
pub const DEFAULT_BUFFER_SIZE: usize = 100 * 1_000;
/// Go `maxPeekSize` — 25 kB of look-ahead when hunting a safe boundary.
pub const MAX_PEEK_SIZE: usize = 25 * 1_000;

/// Go `isWhitespace` — the lookup table `readUntilSafeBoundary` consults.
fn is_whitespace(b: u8) -> bool {
    matches!(b, b'\n' | b'\r' | b' ' | b'\t' | 0x0b | 0x0c)
}

/// Go `sources.File`.
pub struct File<R: Read> {
    /// The file's content.
    pub content: R,
    /// The resolved real path.
    pub path: String,
    /// The symlink this file was discovered through, if any.
    pub symlink: String,
    /// Decides whether to skip based on attributes. `None` = never skip.
    pub should_skip: Option<SkipFunc<'static>>,
    /// How deep to descend into nested archives. 0 disables descent entirely.
    pub max_archive_depth: usize,
    /// Container paths (archives) leading to this file.
    pub(crate) outer_paths: Vec<String>,
    /// How many archives deep this file already is. Compared against
    /// `max_archive_depth` to bound the descent — a zip bomb is a nest of
    /// archives, and without a limit the scan never returns.
    pub(crate) archive_depth: usize,
}

impl<R: Read> File<R> {
    pub fn new(content: R, path: &str) -> File<R> {
        File {
            content,
            path: path.to_string(),
            symlink: String::new(),
            should_skip: None,
            max_archive_depth: 0,
            outer_paths: Vec::new(),
            archive_depth: 0,
        }
    }

    /// Go `File.FullPath` — the path with any container paths prefixed,
    /// joined by `!` (e.g. `outer.zip!inner/b.txt`).
    pub fn full_path(&self) -> String {
        if self.outer_paths.is_empty() {
            return self.path.clone();
        }
        let mut parts = self.outer_paths.clone();
        parts.push(self.path.clone());
        parts.join(INNER_PATH_SEPARATOR)
    }

    /// Go `File.Fragments` (non-archive path) — yield the file's content as
    /// chunked fragments.
    ///
    /// `yield_fn` returning `Err` aborts, mirroring Go's `FragmentsFunc`.
    pub fn fragments<E, F>(&mut self, mut yield_fn: F) -> Result<(), E>
    where
        F: FnMut(Result<Fragment, E>) -> Result<(), E>,
        E: From<String>,
    {
        self.fragments_dyn(&mut yield_fn)
    }

    /// The body of [`File::fragments`], over a TRAIT OBJECT callback.
    ///
    /// Archive descent recurses, and a generic `F` would monomorphize into
    /// `&mut &mut &mut …F` without bound — the compiler stops with a recursion
    /// overflow. One erased callback type makes the recursion finite.
    fn fragments_dyn<E>(
        &mut self,
        yield_fn: &mut dyn FnMut(Result<Fragment, E>) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<String>,
    {
        let full_path = self.full_path();
        // Go normalises to forward slashes on Windows so path rules are
        // portable; `isWindows` is a compile-time constant there.
        let frag_path = if cfg!(windows) {
            full_path.replace('\\', "/")
        } else {
            full_path.clone()
        };

        let mut total_lines: i64 = 0;
        let mut buf = vec![0u8; DEFAULT_BUFFER_SIZE];
        let mut first_chunk = true;
        // Look-ahead bytes carried over from the boundary hunt.
        let mut pending: Vec<u8> = Vec::new();

        loop {
            let n = match self.content.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    return yield_fn(Err(E::from(format!("could not read file: {e}"))));
                }
            };
            if n == 0 && pending.is_empty() {
                return Ok(());
            }

            let mut chunk = std::mem::take(&mut pending);
            chunk.extend_from_slice(&buf[..n]);

            // Binary check, only at the start of the file. Go asks
            // `filetype.Match` and skips when the MIME type is "application".
            if first_chunk {
                first_chunk = false;

                // ── archive descent ────────────────────────────────────────
                // Go identifies the format BEFORE the binary check, because an
                // archive IS binary — checking first would skip every one of
                // them, which is exactly what this port used to do.
                if self.archive_depth < self.max_archive_depth {
                    if let Some(format) = crate::archive::Format::identify(&self.path, &chunk) {
                        // Read the rest of the stream: an archive cannot be
                        // processed one 100 kB chunk at a time.
                        let mut all = std::mem::take(&mut chunk);
                        if let Err(e) = self.content.read_to_end(&mut all) {
                            return yield_fn(Err(E::from(format!("could not read archive: {e}"))));
                        }
                        return self.archive_fragments(format, &all, &frag_path, yield_fn);
                    }
                }

                if looks_binary(&chunk) {
                    return Ok(());
                }
            }

            // GROW the chunk to a blank line where possible. This reads MORE
            // from the reader — it does not merely inspect what was already
            // buffered — which is the whole point: otherwise a secret spanning
            // the 100 kB boundary is still sliced in half.
            read_until_safe_boundary(&mut self.content, n, &mut chunk);

            let raw = String::from_utf8_lossy(&chunk).into_owned();
            let mut fragment = Fragment {
                start_line: total_lines + 1,
                raw: raw.clone(),
                bytes: chunk.clone(),
                ..Default::default()
            };
            fragment.set_attr(ATTR_PATH, &frag_path);
            fragment.set_attr(ATTR_RESOURCE, RESOURCE_FILE_CONTENT);
            if !self.symlink.is_empty() {
                let symlink = if cfg!(windows) {
                    self.symlink.replace('\\', "/")
                } else {
                    self.symlink.clone()
                };
                fragment.set_attr(ATTR_FS_SYMLINK, &symlink);
            }

            total_lines += raw.matches('\n').count() as i64;

            if let Some(skip) = self.should_skip {
                if skip(&fragment.attributes) {
                    if n == 0 {
                        return Ok(());
                    }
                    continue;
                }
            }

            yield_fn(Ok(fragment))?;

            if n == 0 {
                return Ok(());
            }
        }
    }

    /// Go `extractorFragments` / `decompressorFragments` — scan an archive's
    /// contents as files in their own right.
    ///
    /// Each entry recurses through a fresh [`File`] at `archive_depth + 1`, with
    /// the container path pushed onto `outer_paths`, so a finding reports
    /// `outer.zip!inner/creds.txt` and a nested archive is descended into until
    /// the depth limit stops it.
    fn archive_fragments<E>(
        &self,
        format: crate::archive::Format,
        data: &[u8],
        frag_path: &str,
        yield_fn: &mut dyn FnMut(Result<Fragment, E>) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<String>,
    {
        // There is no "recognised but refused" branch any more: every format
        // `Format::identify` returns can be opened. See `archive::Format`.
        let entries = match crate::archive::extract(format, data) {
            Ok(e) => e,
            Err(e) => {
                // A malformed archive is skipped with a warning rather than
                // failing the scan — Go recovers from an outright panic here
                // for the same reason.
                logging::warn()
                    .str("path", frag_path)
                    .msg(&format!("error reading archive: {e}"));
                return Ok(());
            }
        };

        let mut outer = self.outer_paths.clone();
        outer.push(if cfg!(windows) {
            self.path.replace('\\', "/")
        } else {
            self.path.clone()
        });

        for entry in entries {
            // A decompressor yields one unnamed stream; it inherits the
            // container's name minus the compression suffix, so `x.tar.gz`
            // becomes `x.tar` and the next descent sees a tar.
            let inner_path = if entry.path.is_empty() {
                crate::archive::strip_compression_suffix(&self.path)
            } else {
                clean_inner_path(&entry.path)
            };

            let mut inner = File {
                content: std::io::Cursor::new(entry.content),
                path: inner_path,
                symlink: self.symlink.clone(),
                should_skip: self.should_skip,
                max_archive_depth: self.max_archive_depth,
                archive_depth: self.archive_depth + 1,
                outer_paths: outer.clone(),
            };
            inner.fragments_dyn(yield_fn)?;
        }
        Ok(())
    }
}

/// Go's `filepath.Clean(d.NameInArchive)` on an entry path, normalised to
/// forward slashes.
fn clean_inner_path(p: &str) -> String {
    let cleaned = p.replace('\\', "/");
    cleaned.trim_start_matches("./").to_string()
}

/// Go `readUntilSafeBoundary` — GROW `buf` from `r` until it ends in a blank
/// line, or `MAX_PEEK_SIZE` bytes past the original read, whichever comes first.
///
/// Two subtleties, both Go's and both load-bearing:
/// * a `\r`, space or tab does NOT reset the consecutive-newline count, but any
///   other character does — so `\n \n` still counts as a blank line;
/// * the cap is measured from `n`, the ORIGINAL read length, not from zero.
///
/// EOF simply stops the hunt; it is not an error.
pub fn read_until_safe_boundary<R: Read>(r: &mut R, n: usize, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }

    // Already ends in a blank line? Nothing to do.
    let mut newlines = 0;
    if is_whitespace(buf[buf.len() - 1]) {
        for &b in buf.iter().rev() {
            if b == b'\n' {
                newlines += 1;
                if newlines >= 2 {
                    return;
                }
            } else if is_whitespace(b) {
                // Intentionally does not reset — Go says so explicitly.
            } else {
                break;
            }
        }
    }

    // Otherwise read ahead one byte at a time, as Go does.
    newlines = 0;
    let mut one = [0u8; 1];
    loop {
        let last = buf[buf.len() - 1];
        if last == b'\n' {
            newlines += 1;
            if newlines >= 2 {
                return;
            }
        } else if is_whitespace(last) {
            // no reset
        } else {
            newlines = 0;
        }

        if buf.len().saturating_sub(n) >= MAX_PEEK_SIZE {
            return;
        }

        match r.read(&mut one) {
            Ok(0) => return, // EOF — stop, not an error
            Ok(_) => buf.push(one[0]),
            Err(_) => return,
        }
    }
}

/// Stand-in for Go's `filetype.Match(...).MIME.Type == "application"` binary
/// check.
///
/// **Deviation (flagged):** Go sniffs magic bytes through `h2non/filetype` and
/// skips anything whose MIME type is `application`. This uses git's own
/// heuristic — a NUL byte in the first 8 KB — rather than pulling a
/// magic-number crate for the one predicate the non-archive path needs. The two
/// agree on the cases that matter (executables, images, compiled objects all
/// contain NULs early) but differ on NUL-free binary formats. Revisit with
/// `infer` when archive support lands, since that path needs real type
/// detection anyway.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}
