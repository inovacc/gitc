//! The byte-exact value model of a fast-import stream (Rust port of git-filter-repo).
//!
//! The byte-exact value model of a fast-import stream (blobs, commits, resets,
//! tags, …) plus each record's `Dump` serializer, reproducing `fast-export`'s
//! cosmetic conventions so the re-serialized stream imports cleanly. Operates on
//! raw bytes — no newline translation.

use std::io::{self, Write};

use super::pathquoting::PathQuoting;

/// Stateless path quoter shared by the serializers.
const PATH_QUOTER: PathQuoting = PathQuoting;

/// A reference to a commit within a fast-import stream: a mark (`:N`, when
/// `mark > 0`) or a literal object id (when `oid` is set). Zero = "no reference".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ref {
    pub mark: i64,
    pub oid: Option<Vec<u8>>,
}

impl Ref {
    /// Whether the reference points at nothing.
    pub fn is_zero(&self) -> bool {
        self.mark == 0 && self.oid.is_none()
    }

    /// Emit the reference body (`:N` mark form or raw oid form).
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        if self.mark > 0 {
            w.write_all(format!(":{}", self.mark).as_bytes())
        } else {
            w.write_all(self.oid.as_deref().unwrap_or(&[]))
        }
    }
}

/// The three components of an author/committer/tagger identity line.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UserInfo {
    pub name: Vec<u8>,
    pub email: Vec<u8>,
    pub date: Vec<u8>,
}

/// Tracks whether a stream record has been dumped (1), skipped (2), or is still
/// pending (0). Embedded by every record (Go's `element`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Element {
    dumped: u8,
}

impl Element {
    /// Ensure the record will not be written to the output stream.
    pub fn skip(&mut self) {
        self.dumped = 2;
    }
    /// Whether the record was already dumped or skipped.
    pub fn was_handled(&self) -> bool {
        self.dumped != 0
    }
    /// Whether the record was explicitly skipped (dropped from output).
    pub fn is_skipped(&self) -> bool {
        self.dumped == 2
    }
    fn mark_dumped(&mut self) {
        self.dumped = 1;
    }
}

/// The file-change operations that can appear inside a commit. `DeleteAll` is the
/// `deleteall` pseudo-operation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileChangeType {
    Modify,
    Delete,
    Rename,
    Copy,
    DeleteAll,
}

impl Default for FileChangeType {
    fn default() -> Self {
        FileChangeType::Modify
    }
}

/// A single modification within a commit.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileChange {
    pub type_: FileChangeType,
    /// For `Modify`, e.g. `100644`.
    pub mode: Vec<u8>,
    /// For `Modify`: the affected blob (mark or oid).
    pub blob: Ref,
    /// Affected path (raw bytes, unquoted).
    pub path: Vec<u8>,
    /// For `Rename`/`Copy`: the source path.
    pub orig_path: Vec<u8>,
}

impl FileChange {
    /// Write the file-change in fast-import syntax. A `Modify` whose blob
    /// reference is empty represents a skipped blob and produces no output.
    pub fn dump<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self.type_ {
            FileChangeType::Modify => {
                if self.blob.is_zero() {
                    return Ok(()); // skipped blob
                }
                write_chunks(w, &[b"M ", &self.mode, b" "])?;
                self.blob.write(w)?;
                write_chunks(w, &[b" ", &PATH_QUOTER.enquote(&self.path), b"\n"])
            }
            FileChangeType::Delete => {
                write_chunks(w, &[b"D ", &PATH_QUOTER.enquote(&self.path), b"\n"])
            }
            FileChangeType::Rename | FileChangeType::Copy => {
                let verb: &[u8] = if self.type_ == FileChangeType::Copy {
                    b"C "
                } else {
                    b"R "
                };
                write_chunks(
                    w,
                    &[
                        verb,
                        &PATH_QUOTER.enquote(&self.orig_path),
                        b" ",
                        &PATH_QUOTER.enquote(&self.path),
                        b"\n",
                    ],
                )
            }
            FileChangeType::DeleteAll => w.write_all(b"deleteall\n"),
        }
    }
}

/// A blob record: file content plus its mark.
#[derive(Debug, Clone, Default)]
pub struct Blob {
    pub el: Element,
    pub mark: i64,
    pub original_oid: Vec<u8>,
    pub data: Vec<u8>,
}

impl Blob {
    /// Write the blob in fast-import syntax (the original-oid is intentionally not
    /// re-emitted — fast-import does not require it).
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        write_chunks(
            w,
            &[b"blob\nmark :", self.mark.to_string().as_bytes(), b"\n"],
        )?;
        write_chunks(
            w,
            &[b"data ", self.data.len().to_string().as_bytes(), b"\n"],
        )?;
        write_chunks(w, &[&self.data, b"\n"])
    }
}

/// A branch (re)creation record.
#[derive(Debug, Clone, Default)]
pub struct Reset {
    pub el: Element,
    pub ref_name: Vec<u8>,
    pub from: Ref,
}

impl Reset {
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        write_chunks(w, &[b"reset ", &self.ref_name, b"\n"])?;
        if !self.from.is_zero() {
            w.write_all(b"from ")?;
            self.from.write(w)?;
            return w.write_all(b"\n\n");
        }
        Ok(())
    }
}

/// A commit record with all associated metadata and file changes.
#[derive(Debug, Clone, Default)]
pub struct Commit {
    pub el: Element,
    pub branch: Vec<u8>,
    pub mark: i64,
    pub original_oid: Vec<u8>,
    pub author: UserInfo,
    pub committer: UserInfo,
    pub encoding: Vec<u8>,
    pub message: Vec<u8>,
    /// First parent; zero when the commit is a root.
    pub from: Ref,
    /// Additional parents.
    pub merges: Vec<Ref>,
    pub file_changes: Vec<FileChange>,
}

impl Commit {
    fn has_parents(&self) -> bool {
        !self.from.is_zero() || !self.merges.is_empty()
    }

    /// Write the commit in fast-import syntax, reproducing fast-export's cosmetic
    /// trailing-newline conventions so the resulting stream imports cleanly.
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        let has_parents = self.has_parents();

        // A root commit is preceded by a reset so fast-import starts a fresh branch.
        if !has_parents {
            write_chunks(w, &[b"reset ", &self.branch, b"\n"])?;
        }

        write_chunks(
            w,
            &[
                b"commit ",
                &self.branch,
                b"\nmark :",
                self.mark.to_string().as_bytes(),
                b"\n",
            ],
        )?;
        write_user(w, b"author ", &self.author)?;
        write_user(w, b"committer ", &self.committer)?;

        if !self.encoding.is_empty() {
            write_chunks(w, &[b"encoding ", &self.encoding, b"\n"])?;
        }

        // data <len>\n<message>[extra newline]
        let msg_ends_nl = self.message.last() == Some(&b'\n');
        let extra_newline = !msg_ends_nl && (has_parents || !self.file_changes.is_empty());
        write_chunks(
            w,
            &[
                b"data ",
                self.message.len().to_string().as_bytes(),
                b"\n",
                &self.message,
            ],
        )?;
        if extra_newline {
            w.write_all(b"\n")?;
        }

        // Parents: first as "from", the rest as "merge".
        if !self.from.is_zero() {
            w.write_all(b"from ")?;
            self.from.write(w)?;
            w.write_all(b"\n")?;
        }
        for m in &self.merges {
            w.write_all(b"merge ")?;
            m.write(w)?;
            w.write_all(b"\n")?;
        }

        for fc in &self.file_changes {
            fc.dump(w)?;
        }

        // Workaround for pre-2.22 fast-import get-mark handling.
        if !has_parents && self.file_changes.is_empty() {
            w.write_all(b"\n")?;
        }

        w.write_all(b"\n")
    }
}

/// An annotated tag record.
#[derive(Debug, Clone, Default)]
pub struct Tag {
    pub el: Element,
    pub mark: i64,
    /// Tag name without the `refs/tags/` prefix.
    pub ref_name: Vec<u8>,
    pub from: Ref,
    /// `tagger.name` empty means no tagger line.
    pub tagger: UserInfo,
    pub original_oid: Vec<u8>,
    pub message: Vec<u8>,
}

impl Tag {
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        write_chunks(w, &[b"tag ", &self.ref_name, b"\n"])?;
        if self.mark > 0 {
            write_chunks(w, &[b"mark :", self.mark.to_string().as_bytes(), b"\n"])?;
        }
        w.write_all(b"from ")?;
        self.from.write(w)?;
        w.write_all(b"\n")?;
        if !self.tagger.name.is_empty() {
            write_chunks(
                w,
                &[
                    b"tagger ",
                    &self.tagger.name,
                    b" <",
                    &self.tagger.email,
                    b"> ",
                    &self.tagger.date,
                    b"\n",
                ],
            )?;
        }
        write_chunks(
            w,
            &[
                b"data ",
                self.message.len().to_string().as_bytes(),
                b"\n",
                &self.message,
            ],
        )?;
        w.write_all(b"\n")
    }
}

/// A progress record echoed to fast-import.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub el: Element,
    pub message: Vec<u8>,
}

impl Progress {
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        write_chunks(w, &[b"progress ", &self.message, b"\n\n"])
    }
}

/// Forces fast-import to flush the current packfile.
#[derive(Debug, Clone, Default)]
pub struct Checkpoint {
    pub el: Element,
}

impl Checkpoint {
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        w.write_all(b"checkpoint\n\n")
    }
}

/// A single verbatim line (feature/option/done/comment) passed through unchanged.
#[derive(Debug, Clone, Default)]
pub struct LiteralCommand {
    pub el: Element,
    pub line: Vec<u8>,
}

impl LiteralCommand {
    pub fn dump<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.el.mark_dumped();
        w.write_all(&self.line)
    }
}

/// Write an identity line `<prefix><name> <<email>> <date>\n`.
fn write_user<W: Write>(w: &mut W, prefix: &[u8], u: &UserInfo) -> io::Result<()> {
    write_chunks(
        w,
        &[prefix, &u.name, b" <", &u.email, b"> ", &u.date, b"\n"],
    )
}

/// Write each chunk in order, skipping empty ones (mirrors Go's `writeAll`).
fn write_chunks<W: Write>(w: &mut W, chunks: &[&[u8]]) -> io::Result<()> {
    for c in chunks {
        if c.is_empty() {
            continue;
        }
        w.write_all(c)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dumped<F: FnOnce(&mut Vec<u8>) -> io::Result<()>>(f: F) -> Vec<u8> {
        let mut buf = Vec::new();
        f(&mut buf).expect("dump");
        buf
    }

    #[test]
    fn blob_dump_is_byte_exact() {
        let mut b = Blob {
            mark: 1,
            data: b"hello".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| b.dump(w)), b"blob\nmark :1\ndata 5\nhello\n");
        // A NUL-containing payload survives verbatim.
        let mut b2 = Blob {
            mark: 2,
            data: vec![b'a', 0, b'b', b'\n', b'c'],
            ..Default::default()
        };
        assert_eq!(
            dumped(|w| b2.dump(w)),
            b"blob\nmark :2\ndata 5\na\x00b\nc\n"
        );
    }

    #[test]
    fn ref_write_forms() {
        assert_eq!(dumped(|w| Ref { mark: 3, oid: None }.write(w)), b":3");
        assert_eq!(
            dumped(|w| Ref {
                mark: 0,
                oid: Some(b"abc123".to_vec())
            }
            .write(w)),
            b"abc123"
        );
        assert!(Ref::default().is_zero());
    }

    #[test]
    fn filechange_dump_variants() {
        let modify = FileChange {
            type_: FileChangeType::Modify,
            mode: b"100644".to_vec(),
            blob: Ref { mark: 1, oid: None },
            path: b"bin.dat".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| modify.dump(w)), b"M 100644 :1 bin.dat\n");

        let del = FileChange {
            type_: FileChangeType::Delete,
            path: b"gone".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| del.dump(w)), b"D gone\n");

        let ren = FileChange {
            type_: FileChangeType::Rename,
            orig_path: b"a".to_vec(),
            path: b"b".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| ren.dump(w)), b"R a b\n");

        let da = FileChange {
            type_: FileChangeType::DeleteAll,
            ..Default::default()
        };
        assert_eq!(dumped(|w| da.dump(w)), b"deleteall\n");

        // A Modify with a zero blob ref is skipped (no output).
        let skipped = FileChange {
            type_: FileChangeType::Modify,
            mode: b"100644".to_vec(),
            path: b"x".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| skipped.dump(w)), b"");

        // A path needing quoting is enquoted.
        let nl = FileChange {
            type_: FileChangeType::Delete,
            path: b"a\nb".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| nl.dump(w)), b"D \"a\\nb\"\n");
    }

    #[test]
    fn root_commit_dump_is_byte_exact() {
        // Mirrors the shape TestParserInMemory expects for a root commit.
        let mut c = Commit {
            branch: b"refs/heads/main".to_vec(),
            mark: 2,
            author: UserInfo {
                name: b"A U Thor".to_vec(),
                email: b"au@thor.test".to_vec(),
                date: b"1112911570 -0700".to_vec(),
            },
            committer: UserInfo {
                name: b"C Om".to_vec(),
                email: b"c@om.test".to_vec(),
                date: b"1112911570 -0700".to_vec(),
            },
            message: b"hello\n".to_vec(),
            file_changes: vec![FileChange {
                type_: FileChangeType::Modify,
                mode: b"100644".to_vec(),
                blob: Ref { mark: 1, oid: None },
                path: b"bin.dat".to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let want = b"reset refs/heads/main\ncommit refs/heads/main\nmark :2\nauthor A U Thor <au@thor.test> 1112911570 -0700\ncommitter C Om <c@om.test> 1112911570 -0700\ndata 6\nhello\nM 100644 :1 bin.dat\n\n";
        assert_eq!(dumped(|w| c.dump(w)), want.to_vec());
        assert!(c.el.was_handled(), "dump marks the element dumped");
    }

    #[test]
    fn reset_dump_with_and_without_from() {
        let mut r = Reset {
            ref_name: b"refs/heads/main".to_vec(),
            ..Default::default()
        };
        assert_eq!(dumped(|w| r.dump(w)), b"reset refs/heads/main\n");
        let mut r2 = Reset {
            ref_name: b"refs/heads/x".to_vec(),
            from: Ref { mark: 5, oid: None },
            ..Default::default()
        };
        assert_eq!(dumped(|w| r2.dump(w)), b"reset refs/heads/x\nfrom :5\n\n");
    }

    #[test]
    fn element_skip_and_handled() {
        let mut e = Element::default();
        assert!(!e.was_handled());
        e.skip();
        assert!(e.was_handled());
    }
}
