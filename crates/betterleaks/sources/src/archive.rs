//! Archive descent — the port of Go's `extractorFragments` /
//! `decompressorFragments` (`sources/file.go:144-230`).
//!
//! **Why this matters.** Until this module existed, a secret inside a committed
//! `.zip` was missed by EVERY source — git, filesystem, S3, GitHub, GitLab.
//! Nothing reported it; the archive was simply classified as binary and
//! skipped. That is the quietest possible miss.
//!
//! ## Formats
//!
//! Go uses `mholt/archives`, which spans zip, tar, gzip, bzip2, xz, zstd, 7z,
//! brotli, lz4 and rar behind one interface. There is no single Rust
//! equivalent, so it is assembled from one crate per format — which PORT-PLAN
//! originally cited as the reason to defer the whole thing.
//!
//! Supported: **zip, tar, gzip, bzip2, xz, zstd, 7z, brotli and lz4** - every
//! format Go handles except **rar**. Each decoder is PURE RUST, chosen over the
//! C-linked bindings deliberately so the build needs no C toolchain.
//!
//! **rar is the one gap, and it is a deliberate one.** The available Rust
//! options are either FFI bindings to the C `libunrar` (which would put a C
//! toolchain in the build path for one archive format) or young pure-Rust
//! decoders that do not clear the maturity bar for something this port would
//! silently trust. So rar is NOT treated as an ordinary binary:
//! [`Format::identify`] recognises it by magic (`Rar!`) and by extension, and
//! the caller logs that a RAR went unscanned. An unscanned archive stays
//! visible rather than becoming invisible - which is the whole point.
//!
//! ## The two shapes
//!
//! * an **extractor** (zip, tar) contains many entries, each of which is
//!   scanned as a file in its own right, and may itself be an archive;
//! * a **decompressor** (gzip) wraps ONE stream, which is scanned as a single
//!   file — and is very often a tar.

use std::io::Read;

/// What a byte stream turned out to be.
///
/// Every variant here can be OPENED. There used to be an `Unsupported(name)`
/// variant for formats this port recognised but could not decode — 7z, xz,
/// bzip2, zstd, brotli, lz4 and finally rar each passed through it, and callers
/// had a branch that logged "this went unscanned". With rar decoding, nothing
/// constructs it and that branch became unreachable. An unreachable branch
/// promising to report skipped content is worse than none — it reads like a
/// guarantee nothing can trigger — so both were removed. If a format is ever
/// recognised-but-refused again, bring the variant back WITH the test that
/// proves the warning fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    SevenZip,
    Brotli,
    Lz4,
    Rar,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Tar => "tar",
            Format::Gzip => "gzip",
            Format::Bzip2 => "bzip2",
            Format::Xz => "xz",
            Format::Zstd => "zstd",
            Format::SevenZip => "7z",
            Format::Brotli => "brotli",
            Format::Lz4 => "lz4",
            Format::Rar => "rar",
        }
    }

    /// Go `archives.Identify` — by CONTENT first, then by extension.
    ///
    /// Content wins because an archive is frequently misnamed (a `.bin` that is
    /// really a zip, a release asset with no extension at all), and a scanner
    /// that trusts the name misses exactly those.
    pub fn identify(path: &str, head: &[u8]) -> Option<Format> {
        if let Some(f) = Self::from_magic(head) {
            return Some(f);
        }
        Self::from_extension(path)
    }

    /// Magic-number sniffing.
    fn from_magic(b: &[u8]) -> Option<Format> {
        if b.len() >= 4 {
            // "PK\x03\x04", plus the empty- and spanned-archive variants, which
            // are still zips.
            if &b[..2] == b"PK" && matches!(b[2], 0x03 | 0x05 | 0x07) {
                return Some(Format::Zip);
            }
            if b[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
                return Some(Format::Zstd);
            }
            if &b[..4] == b"Rar!" {
                return Some(Format::Rar);
            }
            // The LZ4 FRAME magic. Raw lz4 blocks have none, which is why the
            // extension fallback still matters for this format.
            if b[..4] == [0x04, 0x22, 0x4D, 0x18] {
                return Some(Format::Lz4);
            }
            if b[..4] == [0x37, 0x7A, 0xBC, 0xAF] {
                return Some(Format::SevenZip);
            }
        }
        if b.len() >= 3 {
            if b[..2] == [0x1F, 0x8B] {
                return Some(Format::Gzip);
            }
            if &b[..3] == b"BZh" {
                return Some(Format::Bzip2);
            }
        }
        if b.len() >= 6 && b[..6] == [0xFD, b'7', b'z', b'X', b'Z', 0x00] {
            return Some(Format::Xz);
        }
        // tar has no leading magic: the `ustar` marker sits at offset 257.
        if b.len() >= 265 && &b[257..262] == b"ustar" {
            return Some(Format::Tar);
        }
        None
    }

    /// Extension fallback, for a stream whose head was not conclusive.
    fn from_extension(path: &str) -> Option<Format> {
        let lower = path.to_lowercase();
        // Compound extensions first: `.tar.gz` is a gzip stream, and the tar
        // inside it is found on the next descent.
        for (suffix, format) in [
            (".tar.gz", Format::Gzip),
            (".tgz", Format::Gzip),
            (".tar.bz2", Format::Bzip2),
            (".tar.xz", Format::Xz),
            (".tar.zst", Format::Zstd),
            (".zip", Format::Zip),
            (".jar", Format::Zip),
            (".war", Format::Zip),
            (".ear", Format::Zip),
            (".whl", Format::Zip),
            (".nupkg", Format::Zip),
            (".tar", Format::Tar),
            (".gz", Format::Gzip),
            (".bz2", Format::Bzip2),
            (".xz", Format::Xz),
            (".zst", Format::Zstd),
            (".7z", Format::SevenZip),
            (".rar", Format::Rar),
            (".br", Format::Brotli),
            (".lz4", Format::Lz4),
        ] {
            if lower.ends_with(suffix) {
                return Some(format);
            }
        }
        None
    }
}

/// One entry pulled out of an archive.
#[derive(Debug)]
pub struct Entry {
    /// The path INSIDE the archive.
    pub path: String,
    pub content: Vec<u8>,
}

/// Extract every regular file from `data`.
///
/// Returns entries rather than streaming them because the whole archive is
/// already in memory by this point (it came from a git blob, an S3 object or a
/// file read), and streaming would buy nothing while complicating the
/// borrow structure of the recursive descent.
pub fn extract(format: Format, data: &[u8]) -> Result<Vec<Entry>, String> {
    match format {
        Format::Zip => extract_zip(data),
        Format::Tar => extract_tar(data),
        Format::SevenZip => extract_7z(data),
        Format::Rar => extract_rar(data),
        // ── decompressors ───────────────────────────────────────────────────
        // Each yields ONE stream, not a set of entries. Its name drops the
        // compression suffix, so `logs.tar.gz` becomes `logs.tar` — which the
        // next descent then recognises as a tar.
        Format::Gzip => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| format!("gzip: {e}"))?;
            Ok(vec![decompressed(out)])
        }
        Format::Bzip2 => {
            let mut out = Vec::new();
            bzip2_rs::DecoderReader::new(data)
                .read_to_end(&mut out)
                .map_err(|e| format!("bzip2: {e}"))?;
            Ok(vec![decompressed(out)])
        }
        Format::Xz => {
            let mut out = Vec::new();
            let mut input = std::io::BufReader::new(data);
            lzma_rs::xz_decompress(&mut input, &mut out).map_err(|e| format!("xz: {e}"))?;
            Ok(vec![decompressed(out)])
        }
        Format::Zstd => {
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(data)
                .map_err(|e| format!("zstd: {e}"))?;
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| format!("zstd: {e}"))?;
            Ok(vec![decompressed(out)])
        }
        Format::Brotli => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(data), &mut out)
                .map_err(|e| format!("brotli: {e}"))?;
            Ok(vec![decompressed(out)])
        }
        Format::Lz4 => {
            // The FRAME format, which is what a `.lz4` file on disk is and what
            // Gos archives package reads. The raw block format carries no
            // length header and cannot be decoded standalone.
            let mut out = Vec::new();
            lz4_flex::frame::FrameDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| format!("lz4: {e}"))?;
            Ok(vec![decompressed(out)])
        }
    }
}

/// The single unnamed stream a decompressor produces.
fn decompressed(content: Vec<u8>) -> Entry {
    Entry {
        path: String::new(),
        content,
    }
}

/// RAR, via the pure-Rust `rars` crate.
///
/// The alternative was FFI to the C `libunrar`, which would put a C toolchain
/// in the build path for one archive format. `rars` covers RAR 1.3 through
/// RAR 7 and describes its own status as "kinda works" - so the round trip is
/// TESTED against an archive it wrote itself rather than taken on trust, and a
/// member it cannot decode is skipped with a warning instead of failing the
/// whole archive.
fn extract_rar(data: &[u8]) -> Result<Vec<Entry>, String> {
    use std::sync::{Arc, Mutex};

    let archive = rars::ArchiveReader::read(data).map_err(|e| format!("rar: {e}"))?;

    // `extract_to` hands the caller a writer per entry, so each ones bytes are
    // collected into its own buffer and stitched to its name afterwards.
    type Collected = Arc<Mutex<Vec<(String, Arc<Mutex<Vec<u8>>>)>>>;
    let collected: Collected = Arc::new(Mutex::new(Vec::new()));

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let sink = collected.clone();
    let result = archive.extract_to(None, move |meta| {
        // The name is raw BYTES: a RAR entry name is not guaranteed UTF-8, and
        // refusing one would drop a file that may hold a secret.
        let name = String::from_utf8_lossy(&meta.name).replace('\\', "/");
        let buf = Arc::new(Mutex::new(Vec::new()));
        sink.lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name, buf.clone()));
        Ok(Box::new(SharedWriter(buf)) as Box<dyn std::io::Write>)
    });

    // A member using a feature this decoder lacks must not discard the members
    // that DID decode - the same rule the zip and tar readers follow.
    if let Err(e) = result {
        logging::warn().msg(&format!("rar: stopped early: {e}"));
    }

    let entries = collected.lock().unwrap_or_else(|p| p.into_inner());
    Ok(entries
        .iter()
        .filter(|(name, _)| !name.is_empty() && !name.ends_with('/'))
        .map(|(name, buf)| Entry {
            path: name.clone(),
            content: buf.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        })
        .collect())
}

fn extract_7z(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let cursor = std::io::Cursor::new(data);
    let mut archive = sevenz_rust2::ArchiveReader::new(cursor, sevenz_rust2::Password::empty())
        .map_err(|e| format!("7z: {e}"))?;
    archive
        .for_each_entries(|entry, reader| {
            if entry.is_directory() {
                return Ok(true);
            }
            let mut content = Vec::new();
            reader.read_to_end(&mut content)?;
            out.push(Entry {
                path: entry.name().replace('\\', "/"),
                content,
            });
            Ok(true)
        })
        .map_err(|e| format!("7z: {e}"))?;
    Ok(out)
}

fn extract_zip(data: &[u8]) -> Result<Vec<Entry>, String> {
    let cursor = std::io::Cursor::new(data);
    let mut zip = zip::ZipArchive::new(cursor).map_err(|e| format!("zip: {e}"))?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                // One unreadable entry (an unsupported compression method, a
                // corrupt member) must not abandon the rest of the archive.
                logging::warn().msg(&format!("skipping zip entry {i}: {e}"));
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        // `enclosed_name` rejects entries that would escape the archive root —
        // the zip-slip family. We never write these to disk, so the risk is
        // only a misleading path, but a `../../etc/passwd` in a finding is
        // misleading enough to refuse.
        let Some(name) = entry.enclosed_name() else {
            logging::warn().msg(&format!(
                "skipping zip entry with an unsafe path: {}",
                entry.name()
            ));
            continue;
        };
        let mut content = Vec::new();
        if let Err(e) = entry.read_to_end(&mut content) {
            logging::warn().msg(&format!("skipping unreadable zip entry: {e}"));
            continue;
        }
        out.push(Entry {
            path: name.to_string_lossy().replace('\\', "/"),
            content,
        });
    }
    Ok(out)
}

fn extract_tar(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(data));
    let mut out = Vec::new();
    let entries = archive.entries().map_err(|e| format!("tar: {e}"))?;
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                logging::warn().msg(&format!("skipping tar entry: {e}"));
                continue;
            }
        };
        // Go skips anything that is not a regular file — a symlink or device
        // node has no content to scan.
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().replace('\\', "/"),
            Err(e) => {
                logging::warn().msg(&format!("skipping tar entry with a bad path: {e}"));
                continue;
            }
        };
        let mut content = Vec::new();
        if let Err(e) = entry.read_to_end(&mut content) {
            logging::warn().msg(&format!("skipping unreadable tar entry: {e}"));
            continue;
        }
        out.push(Entry { path, content });
    }
    Ok(out)
}

/// Drop the compression suffix from a decompressed stream's name.
///
/// `logs.tar.gz` → `logs.tar`, so the next descent identifies the tar. Without
/// this the inner stream keeps a `.gz` name and would be re-identified as gzip
/// forever — bounded only by the depth limit, but wasted work and a confusing
/// path in the finding.
pub fn strip_compression_suffix(path: &str) -> String {
    let lower = path.to_lowercase();
    for suffix in [".gz", ".bz2", ".xz", ".zst", ".br", ".lz4"] {
        if lower.ends_with(suffix) {
            return path[..path.len() - suffix.len()].to_string();
        }
    }
    if lower.ends_with(".tgz") {
        return format!("{}.tar", &path[..path.len() - 4]);
    }
    path.to_string()
}

#[cfg(test)]
mod tests;
