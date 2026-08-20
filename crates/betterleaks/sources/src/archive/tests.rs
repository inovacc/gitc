//! Tests for archive descent.
//!
//! The headline case is the one that motivated the module: a secret inside a
//! `.zip` used to be missed by every source in the tool, silently, because the
//! archive was classified as binary and skipped.

use super::*;
use std::io::Write;

/// An AWS-shaped key, generated at runtime.
///
/// No literal provider token is committed anywhere in this repository — see the
/// `testkeys` crate for why. The specific characters are irrelevant to these
/// tests; what matters is that the same value is embedded and then asserted on.
fn aws_key() -> String {
    testkeys::aws(1)
}

/// `<prefix><key><suffix>` as owned bytes — the payload most tests here embed.
fn creds(prefix: &str, suffix: &str) -> Vec<u8> {
    format!("{prefix}{}{suffix}", aws_key()).into_bytes()
}

/// Build a real zip in memory.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(content).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, *name, *content).unwrap();
    }
    builder.into_inner().unwrap()
}

fn gzip_of(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

// ── identification ──────────────────────────────────────────────────────────

/// **Content wins over the name.** Archives arrive misnamed all the time — a
/// release asset with no extension, a `.bin` that is really a zip — and a
/// scanner that trusts the extension misses exactly those.
#[test]
fn a_format_is_identified_from_content_even_when_the_name_lies() {
    let z = zip_of(&[("a.txt", b"x")]);
    assert_eq!(Format::identify("mystery.bin", &z), Some(Format::Zip));
    assert_eq!(Format::identify("", &z), Some(Format::Zip));

    let g = gzip_of(b"hello");
    assert_eq!(Format::identify("noext", &g), Some(Format::Gzip));

    let t = tar_of(&[("a.txt", b"x")]);
    assert_eq!(Format::identify("noext", &t), Some(Format::Tar));
}

#[test]
fn the_extension_is_the_fallback_when_content_is_inconclusive() {
    assert_eq!(Format::identify("a.zip", b""), Some(Format::Zip));
    assert_eq!(Format::identify("a.jar", b""), Some(Format::Zip));
    assert_eq!(Format::identify("a.whl", b""), Some(Format::Zip));
    assert_eq!(Format::identify("a.tar", b""), Some(Format::Tar));
    assert_eq!(Format::identify("a.tar.gz", b""), Some(Format::Gzip));
    assert_eq!(Format::identify("a.tgz", b""), Some(Format::Gzip));
    assert_eq!(Format::identify("PLAIN.TXT", b"hello"), None);
    assert_eq!(Format::identify("noext", b"hello"), None);
}

/// Recognised AND openable, by magic and by extension alike. brotli, lz4 and
/// rar used to sit outside this loop as named refusals; they now have round-trip
/// tests of their own below rather than a mention here.
#[test]
fn the_supported_formats_are_recognised_both_ways() {
    for (name, magic, expect) in [
        ("a.7z", &[0x37u8, 0x7A, 0xBC, 0xAF][..], Format::SevenZip),
        ("a.zst", &[0x28u8, 0xB5, 0x2F, 0xFD][..], Format::Zstd),
        ("a.bz2", &b"BZh9"[..], Format::Bzip2),
        ("a.xz", &[0xFDu8, b'7', b'z', b'X', b'Z', 0x00][..], Format::Xz),
    ] {
        assert_eq!(Format::identify("noext", magic), Some(expect), "{name} by magic");
        assert_eq!(Format::identify(name, b""), Some(expect), "{name} by extension");
    }
}

/// rar is a real decoder now rather than a named refusal. Both the magic and
/// the extension route to it.
#[test]
fn rar_is_recognised_and_openable() {
    for id in [Format::identify("noext", b"Rar!"), Format::identify("a.rar", b"")] {
        assert_eq!(id, Some(Format::Rar));
    }
}

/// Build a real RAR archive to read back.
///
/// `rars`' RAR 1.5 store-only writer, which is the oldest format whose signature
/// is the `Rar!\x1a\x07\x00` the scanner detects on — the 1.3/1.4 writer emits a
/// different magic that would never reach this decoder, so a round trip through
/// it would prove nothing about what a scan actually does.
///
/// The round trip goes through the SAME `write` module that `Archive::read`
/// parses, so it cannot catch a bug both halves share. What it does catch is the
/// decoder silently returning nothing, or returning a member whose bytes differ
/// from what went in — which is the regression that would let a secret through.
fn build_test_rar(name: &str, data: &[u8]) -> Vec<u8> {
    use rars::rar15_40::{write_stored_archive, StoredEntry, WriterOptions};
    write_stored_archive(
        &[StoredEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .expect("writing the fixture archive")
}

/// The decisive one: a REAL rar archive, written and read back.
///
/// `rars` describes its own status as "kinda works", so this is evidence rather
/// than trust — if it regresses, a secret inside a committed `.rar` goes
/// unscanned and nothing else in the suite would notice.
#[test]
fn a_secret_inside_a_rar_is_found() {
    let plain: &[u8] = &creds("aws_key = ", "\n");
    let rar_bytes = build_test_rar("creds.txt", plain);

    assert_eq!(
        Format::identify("x.rar", &rar_bytes),
        Some(Format::Rar),
        "the archive must be recognised by magic"
    );

    let entries = extract(Format::Rar, &rar_bytes).expect("rar extract");
    assert_eq!(entries.len(), 1, "one member in, one member out");
    assert_eq!(entries[0].path, "creds.txt");
    assert_eq!(entries[0].content, plain, "rar must round trip exactly");

    // And end to end through the file source, which is what a scan does.
    let frags = scan(rar_bytes, "creds.rar", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
}

/// A corrupt archive is an ERROR, not an empty result. An empty result would
/// read as "this archive held nothing".
#[test]
fn a_corrupt_rar_is_an_error() {
    let mut junk = b"Rar!\x1a\x07\x01\x00".to_vec();
    junk.extend_from_slice(&[0xAB; 64]);
    assert!(extract(Format::Rar, &junk).is_err());
}

/// brotli and lz4 used to be in that same "recognised but refused" bucket and
/// are now real decoders. This asserts they moved, so the gap list cannot
/// silently grow back.
#[test]
fn brotli_and_lz4_are_now_openable() {
    assert_eq!(Format::identify("a.br", b""), Some(Format::Brotli));
    assert_eq!(Format::identify("a.lz4", b""), Some(Format::Lz4));
    // The LZ4 frame magic wins over a misleading name.
    assert_eq!(
        Format::identify("a.txt", &[0x04, 0x22, 0x4D, 0x18, 0x64, 0x40]),
        Some(Format::Lz4)
    );
}

// ── the decompressors added after zip/tar/gzip ──────────────────────────────

/// A decompressor yields ONE unnamed stream, and the round trip must return the
/// EXACT bytes — a decoder that silently truncates would drop the tail of a log
/// and any secrets in it.
///
/// xz is the one exercised end to end because `lzma-rs` ships an encoder.
/// `bzip2-rs`, `ruzstd` and `sevenz-rust2` are decode-only here, so those are
/// covered by identification plus the corrupt-input test below; producing real
/// fixtures for them would mean vendoring binary blobs.
#[test]
fn a_decompressor_round_trips_exactly() {
    let plain = &creds("aws_key = ", " and some trailing content to compress");

    let mut xz_bytes = Vec::new();
    lzma_rs::xz_compress(&mut &plain[..], &mut xz_bytes).expect("xz compress");

    let entries = extract(Format::Xz, &xz_bytes).expect("xz extract");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "", "a decompressor stream is unnamed");
    assert_eq!(entries[0].content, *plain, "xz must round trip exactly");

    // The identifier must agree with what the decoder accepts.
    assert_eq!(Format::identify("noext", &xz_bytes), Some(Format::Xz));
}

/// brotli and lz4 round trip exactly. Both crates ship an encoder, so unlike
/// bzip2/zstd/7z these are exercised end to end rather than by identification
/// alone.
#[test]
fn brotli_and_lz4_round_trip_exactly() {
    let plain: &[u8] =
        &creds("aws_key = ", " and some trailing content to compress");

    let mut br = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(plain),
        &mut br,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .expect("brotli compress");
    let entries = extract(Format::Brotli, &br).expect("brotli extract");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "", "a decompressor stream is unnamed");
    assert_eq!(entries[0].content, plain, "brotli must round trip exactly");

    let mut lz = Vec::new();
    {
        let mut enc = lz4_flex::frame::FrameEncoder::new(&mut lz);
        std::io::Write::write_all(&mut enc, plain).expect("lz4 write");
        enc.finish().expect("lz4 finish");
    }
    let entries = extract(Format::Lz4, &lz).expect("lz4 extract");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].content, plain, "lz4 must round trip exactly");
    // And the frame magic identifies it without help from the filename.
    assert_eq!(Format::identify("noext", &lz), Some(Format::Lz4));
}

/// A secret inside a `.br` and inside a `.lz4` is found end to end, which is
/// the point of adding the formats at all.
#[test]
fn a_secret_inside_brotli_and_lz4_is_found() {
    let plain: &[u8] = &creds("aws_key = ", "\n");

    let mut br = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(plain),
        &mut br,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    let frags = scan(br, "creds.txt.br", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
    assert_eq!(frags[0].attr(crate::ATTR_PATH), "creds.txt.br!creds.txt");

    let mut lz = Vec::new();
    {
        let mut enc = lz4_flex::frame::FrameEncoder::new(&mut lz);
        std::io::Write::write_all(&mut enc, plain).unwrap();
        enc.finish().unwrap();
    }
    let frags = scan(lz, "creds.txt.lz4", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
    assert_eq!(frags[0].attr(crate::ATTR_PATH), "creds.txt.lz4!creds.txt");
}

/// A secret inside an `.xz` is found end to end, which is the point of adding
/// the format at all.
#[test]
fn a_secret_inside_an_xz_stream_is_found() {
    let plain = &creds("aws_key = ", "\n");
    let mut xz_bytes = Vec::new();
    lzma_rs::xz_compress(&mut &plain[..], &mut xz_bytes).expect("compress");
    let frags = scan(xz_bytes, "creds.txt.xz", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
    assert_eq!(
        frags[0].attr(crate::ATTR_PATH),
        "creds.txt.xz!creds.txt",
        "the .xz suffix is dropped for the inner stream"
    );
}

/// A `.tar.xz` needs two descents, exactly as `.tar.gz` does.
#[test]
fn a_tar_xz_is_descended_through_both_layers() {
    let t = tar_of(&[("creds.txt", &creds("aws_key = ", ""))]);
    let mut xz_bytes = Vec::new();
    lzma_rs::xz_compress(&mut &t[..], &mut xz_bytes).expect("compress");
    let frags = scan(xz_bytes, "logs.tar.xz", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
}

#[test]
fn a_corrupt_stream_in_each_new_format_errors_rather_than_panicking() {
    assert!(extract(Format::Bzip2, b"BZh9 not really bzip2").is_err());
    assert!(extract(Format::Xz, &[0xFD, b'7', b'z', b'X', b'Z', 0x00, 0xFF]).is_err());
    assert!(extract(Format::Zstd, &[0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF]).is_err());
    assert!(extract(Format::SevenZip, b"7z\xBC\xAF garbage").is_err());
}

// ── extraction ──────────────────────────────────────────────────────────────

#[test]
fn zip_entries_are_extracted_with_their_paths() {
    let z = zip_of(&[
        ("creds.txt", &creds("aws_key = ", "")),
        ("nested/dir/other.txt", b"nothing here"),
    ]);
    let entries = extract(Format::Zip, &z).expect("extract");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "creds.txt");
    assert!(String::from_utf8_lossy(&entries[0].content).contains(&aws_key()));
    assert_eq!(entries[1].path, "nested/dir/other.txt");
}

#[test]
fn tar_entries_are_extracted_with_their_paths() {
    let t = tar_of(&[("creds.txt", &creds("secret ", ""))]);
    let entries = extract(Format::Tar, &t).expect("extract");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "creds.txt");
    assert!(String::from_utf8_lossy(&entries[0].content).contains("AKIA"));
}

/// A decompressor yields ONE unnamed stream, not a set of entries — the caller
/// renames it by dropping the compression suffix.
#[test]
fn gzip_yields_one_unnamed_stream() {
    let g = gzip_of(&creds("aws_key = ", ""));
    let entries = extract(Format::Gzip, &g).expect("extract");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "", "unnamed: it inherits the container's name");
    assert!(String::from_utf8_lossy(&entries[0].content).contains("AKIA"));
}

#[test]
fn a_corrupt_archive_is_an_error_rather_than_a_panic() {
    assert!(extract(Format::Zip, b"PK\x03\x04 not really a zip").is_err());
    assert!(extract(Format::Gzip, b"\x1f\x8b garbage").is_err());
    // A truncated tar yields no entries rather than exploding.
    let _ = extract(Format::Tar, b"\0".repeat(512).as_slice());
}

/// A zip entry whose path escapes the archive root is refused. We never write
/// these to disk, but `../../etc/passwd` in a finding is misleading enough on
/// its own.
#[test]
fn zip_slip_paths_are_refused() {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("../../escape.txt", opts).unwrap();
        w.write_all(&creds("", "")).unwrap();
        w.start_file("safe.txt", opts).unwrap();
        w.write_all(b"fine").unwrap();
        w.finish().unwrap();
    }
    let entries = extract(Format::Zip, &buf).expect("extract");
    assert_eq!(entries.len(), 1, "the escaping entry is dropped");
    assert_eq!(entries[0].path, "safe.txt");
}

// ── suffix stripping ────────────────────────────────────────────────────────

/// `logs.tar.gz` must become `logs.tar`, or the decompressed stream keeps a
/// `.gz` name, is re-identified as gzip, and the descent spins until the depth
/// limit stops it.
#[test]
fn the_compression_suffix_is_stripped_so_the_next_descent_sees_a_tar() {
    assert_eq!(strip_compression_suffix("logs.tar.gz"), "logs.tar");
    assert_eq!(strip_compression_suffix("logs.tgz"), "logs.tar");
    assert_eq!(strip_compression_suffix("data.gz"), "data");
    assert_eq!(strip_compression_suffix("a.tar.bz2"), "a.tar");
    assert_eq!(strip_compression_suffix("plain.txt"), "plain.txt");
    assert_eq!(strip_compression_suffix(""), "");
}

// ── end to end, through File ────────────────────────────────────────────────

use crate::{File, Fragment};

fn scan(data: Vec<u8>, path: &str, depth: usize) -> Vec<Fragment> {
    let mut f = File::new(std::io::Cursor::new(data), path);
    f.max_archive_depth = depth;
    let mut out = Vec::new();
    let mut sink = |r: Result<Fragment, String>| -> Result<(), String> {
        out.push(r?);
        Ok(())
    };
    f.fragments(&mut sink).expect("fragments");
    out
}

/// **THE case this module exists for.** Before it, this returned nothing.
#[test]
fn a_secret_inside_a_zip_is_found() {
    let z = zip_of(&[("creds.txt", &creds("aws_key = ", "\n"))]);
    let frags = scan(z, "bundle.zip", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
}

/// The finding's path names BOTH the container and the member, joined by `!`.
#[test]
fn the_fragment_path_names_the_container_and_the_member() {
    let z = zip_of(&[("inner/creds.txt", &creds("", ""))]);
    let frags = scan(z, "bundle.zip", 8);
    assert_eq!(frags[0].attr(crate::ATTR_PATH), "bundle.zip!inner/creds.txt");
}

/// `.tar.gz` needs TWO descents: gzip to a tar, then the tar to its entries.
#[test]
fn a_tar_gz_is_descended_through_both_layers() {
    let t = tar_of(&[("creds.txt", &creds("aws_key = ", ""))]);
    let g = gzip_of(&t);
    let frags = scan(g, "logs.tar.gz", 8);
    assert_eq!(frags.len(), 1);
    assert!(frags[0].raw.contains(&aws_key()));
    assert!(
        frags[0].attr(crate::ATTR_PATH).contains("creds.txt"),
        "path was {:?}",
        frags[0].attr(crate::ATTR_PATH)
    );
}

/// A zip inside a zip is descended into.
#[test]
fn nested_archives_are_descended() {
    let inner = zip_of(&[("creds.txt", &creds("", ""))]);
    let outer = zip_of(&[("inner.zip", &inner)]);
    let frags = scan(outer, "outer.zip", 8);
    assert_eq!(frags.len(), 1);
    assert_eq!(
        frags[0].attr(crate::ATTR_PATH),
        "outer.zip!inner.zip!creds.txt",
        "every container appears in the path"
    );
}

/// **The depth limit is a zip-bomb guard.** Without it a nest of archives never
/// terminates.
#[test]
fn the_depth_limit_stops_the_descent() {
    let inner = zip_of(&[("creds.txt", &creds("", ""))]);
    let outer = zip_of(&[("inner.zip", &inner)]);

    // Depth 1 opens the outer zip but not the inner one.
    assert!(
        scan(outer.clone(), "outer.zip", 1).is_empty(),
        "the inner zip must not be opened at depth 1"
    );
    assert_eq!(scan(outer, "outer.zip", 2).len(), 1, "depth 2 reaches it");
}

/// Depth 0 disables descent entirely, which is the default and the behaviour
/// every earlier wave of this port had.
#[test]
fn depth_zero_disables_descent() {
    let z = zip_of(&[("creds.txt", &creds("", ""))]);
    assert!(scan(z, "bundle.zip", 0).is_empty());
}

/// THE GAP LIST IS EMPTY, and this is what keeps it that way.
///
/// This replaces `an_unsupported_archive_yields_nothing_but_is_recognised`,
/// which used rar as its example of a format identified but not decodable. rar
/// decodes now, so `Format::Unsupported` had no constructor left and was removed
/// along with the caller branch that logged the skip — see `archive::Format`.
///
/// The invariant "every identifiable format can be opened" is now enforced by
/// the COMPILER: `extract` matches `Format` exhaustively and no arm returns a
/// refusal, so a new variant cannot be added without deciding how to open it.
/// The exhaustive match below is a second tripwire in the test file itself, so
/// the addition also lands in front of whoever maintains these fixtures.
///
/// bzip2, zstd and 7z are asserted by identification only: `bzip2-rs`, `ruzstd`
/// and `sevenz-rust2` are DECODE-ONLY, so a round trip would mean vendoring
/// binary blobs. Their decoders are exercised on corrupt input by
/// `a_corrupt_stream_in_each_new_format_errors_rather_than_panicking`.
#[test]
fn every_identifiable_format_is_accounted_for() {
    // Adding a variant to `Format` stops compiling HERE until it is placed in
    // one of the two buckets below deliberately.
    fn bucket(f: Format) -> &'static str {
        match f {
            Format::Zip
            | Format::Tar
            | Format::Gzip
            | Format::Xz
            | Format::Brotli
            | Format::Lz4
            | Format::Rar => "round-tripped",
            Format::Bzip2 | Format::Zstd | Format::SevenZip => "decode-only",
        }
    }

    // The name matters: brotli has NO magic number (the format simply has no
    // signature), so `.br` is the only way it can be identified — which is
    // exactly what `identify`'s content-then-extension order exists for.
    let round_tripped: Vec<(Format, &str, Vec<u8>)> = vec![
        (Format::Zip, "a.zip", zip_of(&[("a.txt", b"x")])),
        (Format::Tar, "a.tar", tar_of(&[("a.txt", b"x")])),
        (Format::Gzip, "a.gz", gzip_of(b"x")),
        (Format::Xz, "a.xz", {
            let mut v = Vec::new();
            lzma_rs::xz_compress(&mut &b"x"[..], &mut v).unwrap();
            v
        }),
        (Format::Brotli, "a.br", {
            let mut v = Vec::new();
            brotli::BrotliCompress(
                &mut std::io::Cursor::new(&b"x"[..]),
                &mut v,
                &brotli::enc::BrotliEncoderParams::default(),
            )
            .unwrap();
            v
        }),
        (Format::Lz4, "a.lz4", {
            let mut v = Vec::new();
            let mut enc = lz4_flex::frame::FrameEncoder::new(&mut v);
            std::io::Write::write_all(&mut enc, b"x").unwrap();
            enc.finish().unwrap();
            v
        }),
        (Format::Rar, "a.rar", build_test_rar("a.txt", b"x")),
    ];

    for (format, name, bytes) in &round_tripped {
        assert_eq!(bucket(*format), "round-tripped");
        assert_eq!(
            Format::identify(name, bytes),
            Some(*format),
            "{} must be identified from a real archive of it",
            format.name()
        );
        let entries = extract(*format, bytes)
            .unwrap_or_else(|e| panic!("{} must open, got {e}", format.name()));
        assert_eq!(entries.len(), 1, "{} yielded nothing", format.name());
        assert_eq!(entries[0].content, b"x", "{} content", format.name());
    }

    for (format, magic) in [
        (Format::Bzip2, &b"BZh9"[..]),
        (Format::Zstd, &[0x28u8, 0xB5, 0x2F, 0xFD][..]),
        (Format::SevenZip, &[0x37u8, 0x7A, 0xBC, 0xAF][..]),
    ] {
        assert_eq!(bucket(format), "decode-only");
        assert_eq!(Format::identify("noext", magic), Some(format));
    }

    assert_eq!(round_tripped.len() + 3, 10, "every Format variant is covered");
}

/// A CORRUPT archive in a supported format also yields nothing, and must not
/// take the scan down with it.
#[test]
fn a_corrupt_supported_archive_is_survived() {
    let fake_7z = [&[0x37u8, 0x7A, 0xBC, 0xAF][..], b"not a real 7z"].concat();
    assert_eq!(Format::identify("a.7z", &fake_7z), Some(Format::SevenZip));
    assert!(scan(fake_7z, "a.7z", 8).is_empty(), "skipped, not fatal");
}

/// A file that merely LOOKS like it might be an archive but is plain text is
/// scanned normally.
#[test]
fn ordinary_content_is_unaffected_by_the_archive_path() {
    let frags = scan(creds("aws_key = ", "\n"), "creds.txt", 8);
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].attr(crate::ATTR_PATH), "creds.txt");
}

/// Several members are each scanned, each with its own path.
#[test]
fn every_member_of_an_archive_is_scanned() {
    let z = zip_of(&[
        ("a.txt", &creds("first ", "")),
        ("b.txt", &creds("second ", "")),
        ("c.txt", b"third"),
    ]);
    let frags = scan(z, "bundle.zip", 8);
    assert_eq!(frags.len(), 3);
    let paths: Vec<&str> = frags.iter().map(|f| f.attr(crate::ATTR_PATH)).collect();
    assert_eq!(
        paths,
        vec!["bundle.zip!a.txt", "bundle.zip!b.txt", "bundle.zip!c.txt"]
    );
}

