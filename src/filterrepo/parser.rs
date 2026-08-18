//! Streaming fast-export→fast-import parser (Rust port of git-filter-repo's codec).
//!
//! A single streaming pass over a `git fast-export` stream: each record is parsed,
//! dispatched to the matching callback (which may mutate or `skip` it), and
//! re-emitted in fast-import syntax. Byte-exact — uses `Vec<u8>`/`io::Read`, never
//! `String`/lines, so embedded newlines and NUL bytes in `data <n>` payloads are
//! preserved verbatim (essential for a real-git round-trip on any platform).

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::io::{BufRead, Write};

use super::bytesutil::decode;
use super::idmap::IdMap;
use super::pathquoting::PathQuoting;
use super::records::{
    Blob, Checkpoint, Commit, FileChange, FileChangeType, LiteralCommand, Progress, Ref, Reset,
    Tag, UserInfo,
};

/// An error parsing a fast-export stream (unsupported command, malformed line, or
/// an IO/serialization failure).
#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ParseError {}

/// Optional hooks invoked as each record is parsed, before it is re-serialized. A
/// callback may mutate the record or call its element's `skip` to drop it. Any
/// `None` callback is ignored.
pub struct Callbacks<'c> {
    pub blob: Option<Box<dyn FnMut(&mut Blob) + 'c>>,
    pub reset: Option<Box<dyn FnMut(&mut Reset) + 'c>>,
    pub commit: Option<Box<dyn FnMut(&mut Commit) + 'c>>,
    pub tag: Option<Box<dyn FnMut(&mut Tag) + 'c>>,
    pub progress: Option<Box<dyn FnMut(&mut Progress) + 'c>>,
    pub checkpoint: Option<Box<dyn FnMut(&mut Checkpoint) + 'c>>,
    pub done: Option<Box<dyn FnMut() + 'c>>,
}

impl<'c> Default for Callbacks<'c> {
    fn default() -> Self {
        Callbacks {
            blob: None,
            reset: None,
            commit: None,
            tag: None,
            progress: None,
            checkpoint: None,
            done: None,
        }
    }
}

/// Persistent parser state (survives a `run`, exposed via the accessors).
pub struct FastExportParser {
    ids: IdMap,
    /// Last mark seen on each branch, so commits relying on fast-import's
    /// implicit-parent-by-branch behaviour get an explicit parent.
    latest_commit: HashMap<Vec<u8>, Ref>,
    exported_refs: Vec<String>,
    imported_refs: Vec<String>,
    seen_exported: HashSet<String>,
    seen_imported: HashSet<String>,
}

impl FastExportParser {
    pub fn new() -> Self {
        FastExportParser {
            ids: IdMap::new(),
            latest_commit: HashMap::new(),
            exported_refs: Vec::new(),
            imported_refs: Vec::new(),
            seen_exported: HashSet::new(),
            seen_imported: HashSet::new(),
        }
    }

    /// Read a fast-export stream from `r`, invoke `cb` per record, and write the
    /// re-serialized fast-import stream to `w`. Returns the first error, or `Ok`.
    pub fn run<R: BufRead, W: Write>(
        &mut self,
        r: R,
        w: W,
        cb: Callbacks<'_>,
    ) -> Result<(), ParseError> {
        let mut runner = Runner {
            p: self,
            br: r,
            w,
            cb,
            line: Vec::new(),
            err: None,
            done: false,
        };
        runner.run_loop();
        match runner.err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Refs observed in the input stream, in first-seen order.
    pub fn exported_refs(&self) -> &[String] {
        &self.exported_refs
    }
    /// Refs written to the output stream, in first-seen order.
    pub fn imported_refs(&self) -> &[String] {
        &self.imported_refs
    }
    /// The mark registry used by the parser.
    pub fn ids(&self) -> &IdMap {
        &self.ids
    }
}

impl Default for FastExportParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-run driver: borrows the persistent state and owns the reader/writer + the
/// transient line/error/done cursor. All the parsing methods live here.
struct Runner<'p, 'c, R: BufRead, W: Write> {
    p: &'p mut FastExportParser,
    br: R,
    w: W,
    cb: Callbacks<'c>,
    line: Vec<u8>,
    err: Option<ParseError>,
    done: bool,
}

impl<R: BufRead, W: Write> Runner<'_, '_, R, W> {
    fn run_loop(&mut self) {
        self.advance();
        while self.err.is_none() && !self.done && !self.line.is_empty() {
            if self.starts_with(b"blob") {
                self.parse_blob();
            } else if self.starts_with(b"reset") {
                self.parse_reset();
            } else if self.starts_with(b"commit") {
                self.parse_commit();
            } else if self.starts_with(b"tag") {
                self.parse_tag();
            } else if self.starts_with(b"progress") {
                self.parse_progress();
            } else if self.starts_with(b"checkpoint") {
                self.parse_checkpoint();
            } else if self.starts_with(b"feature")
                || self.starts_with(b"option")
                || self.starts_with(b"#")
            {
                self.parse_literal();
            } else if self.starts_with(b"done") {
                if let Some(f) = self.cb.done.as_mut() {
                    f();
                }
                self.parse_literal();
                self.done = true;
            } else if self.starts_with(b"get-mark")
                || self.starts_with(b"cat-blob")
                || self.starts_with(b"ls")
            {
                let msg = decode(trim_nl(&self.line));
                self.fail(ParseError(format!(
                    "filterrepo: unsupported command: {msg:?}"
                )));
            } else {
                let msg = decode(trim_nl(&self.line));
                self.fail(ParseError(format!(
                    "filterrepo: could not parse line: {msg:?}"
                )));
            }
        }
    }

    // --- low-level line handling ---

    fn advance(&mut self) {
        if self.err.is_some() {
            return;
        }
        let mut line = Vec::new();
        match self.br.read_until(b'\n', &mut line) {
            Ok(0) => self.line = Vec::new(), // EOF, nothing read
            Ok(_) => self.line = line,       // a line (may lack a trailing \n at EOF)
            Err(e) => {
                self.fail(ParseError(e.to_string()));
                self.line = Vec::new();
            }
        }
    }

    fn fail(&mut self, err: ParseError) {
        if self.err.is_none() {
            self.err = Some(err);
        }
    }

    fn dump_result(&mut self, res: std::io::Result<()>) {
        if let Err(e) = res {
            self.fail(ParseError(e.to_string()));
        }
    }

    fn starts_with(&self, s: &[u8]) -> bool {
        self.line.starts_with(s)
    }

    fn line_is_blank(&self) -> bool {
        self.line.len() == 1 && self.line[0] == b'\n'
    }

    fn record_exported(&mut self, ref_: &[u8]) {
        let s = String::from_utf8_lossy(ref_).into_owned();
        if self.p.seen_exported.insert(s.clone()) {
            self.p.exported_refs.push(s);
        }
    }

    fn record_imported(&mut self, ref_: &[u8]) {
        let s = String::from_utf8_lossy(ref_).into_owned();
        if self.p.seen_imported.insert(s.clone()) {
            self.p.imported_refs.push(s);
        }
    }

    // --- token parsers ---

    fn parse_optional_mark(&mut self) -> i64 {
        if !self.starts_with(b"mark :") {
            return 0;
        }
        let num = trim_nl(&self.line["mark :".len()..]).to_vec();
        match parse_i64(&num) {
            Some(n) => {
                self.advance();
                n
            }
            None => 0,
        }
    }

    /// Parse a `from`/`merge` line if present. Returns whether a parent line was
    /// consumed and the (translated) reference; a skipped parent yields
    /// `(true, zero)`.
    fn parse_optional_parent_ref(&mut self, refname: &[u8]) -> (bool, Ref) {
        let mark_prefix = [refname, b" :"].concat();
        if self.line.starts_with(&mark_prefix) {
            let num = trim_nl(&self.line[mark_prefix.len()..]).to_vec();
            if let Some(n) = parse_i64(&num) {
                let (new_mark, ok) = self.p.ids.translate(n);
                self.advance();
                if !ok {
                    return (true, Ref::default());
                }
                return (
                    true,
                    Ref {
                        mark: new_mark,
                        oid: None,
                    },
                );
            }
        }

        let oid_prefix = [refname, b" "].concat();
        if self.line.starts_with(&oid_prefix) {
            let rest = trim_nl(&self.line[oid_prefix.len()..]).to_vec();
            if is_hex_oid(&rest) {
                self.advance();
                return (
                    true,
                    Ref {
                        mark: 0,
                        oid: Some(rest),
                    },
                );
            }
        }

        (false, Ref::default())
    }

    fn parse_original_id(&mut self) -> Vec<u8> {
        let id = trim_end_ws(&self.line["original-oid ".len()..]).to_vec();
        self.advance();
        id
    }

    fn parse_encoding(&mut self) -> Vec<u8> {
        let enc = trim_end_ws(&self.line["encoding ".len()..]).to_vec();
        self.advance();
        enc
    }

    /// The argument of a `<prefix> <arg>\n` line; advances.
    fn parse_ref_line(&mut self, prefix: &[u8]) -> Vec<u8> {
        let mut pfx = prefix.to_vec();
        pfx.push(b' ');
        if !self.line.starts_with(&pfx) {
            let msg = decode(trim_nl(&self.line));
            self.fail(ParseError(format!(
                "filterrepo: malformed {} line: {msg:?}",
                String::from_utf8_lossy(prefix)
            )));
            return Vec::new();
        }
        let arg = trim_nl(&self.line[prefix.len() + 1..]).to_vec();
        self.advance();
        arg
    }

    /// Parse an `author`/`committer`/`tagger` identity line (prefix includes the
    /// trailing space).
    fn parse_user(&mut self, prefix: &[u8]) -> UserInfo {
        let rest = trim_nl(&self.line[prefix.len()..]).to_vec();
        let mut u = UserInfo::default();
        match find_sub(&rest, b" <") {
            None => u.name = rest,
            Some(lt) => {
                u.name = rest[..lt].to_vec();
                let after = &rest[lt + 2..];
                match find_sub(after, b"> ") {
                    None => u.email = after.to_vec(),
                    Some(gt) => {
                        u.email = after[..gt].to_vec();
                        u.date = after[gt + 2..].to_vec();
                    }
                }
            }
        }
        self.advance();
        u
    }

    /// Read a length-prefixed (`data <n>`) or delimited (`data <<EOF`) payload,
    /// reading exactly the declared bytes for the counted form so embedded
    /// newlines/NULs survive.
    fn parse_data(&mut self) -> Vec<u8> {
        let fields: Vec<Vec<u8>> = self
            .line
            .split(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
            .filter(|f| !f.is_empty())
            .map(|f| f.to_vec())
            .collect();
        if fields.len() < 2 || fields[0] != b"data" {
            let msg = decode(trim_nl(&self.line));
            self.fail(ParseError(format!(
                "filterrepo: expected data line, got {msg:?}"
            )));
            return Vec::new();
        }
        let spec = fields[1].clone();

        if spec.starts_with(b"<<") {
            let delim = spec[2..].to_vec();
            let mut buf = Vec::new();
            loop {
                let mut l = Vec::new();
                let n = self.br.read_until(b'\n', &mut l).unwrap_or(0);
                if l.is_empty() && n == 0 {
                    break;
                }
                if trim_nl(&l) == delim.as_slice() {
                    break;
                }
                buf.extend_from_slice(&l);
            }
            self.advance();
            if self.line_is_blank() {
                self.advance();
            }
            return buf;
        }

        let size = match parse_usize(&spec) {
            Some(n) => n,
            None => {
                self.fail(ParseError(format!(
                    "filterrepo: bad data length {:?}",
                    decode(&spec)
                )));
                return Vec::new();
            }
        };
        let mut data = vec![0u8; size];
        if self.br.read_exact(&mut data).is_err() {
            self.fail(ParseError(
                "filterrepo: short read on data payload".to_string(),
            ));
            return Vec::new();
        }
        self.advance();
        if self.line_is_blank() {
            self.advance();
        }
        data
    }

    // --- record parsers ---

    fn parse_blob(&mut self) {
        self.advance(); // consume "blob"
        let old_mark = self.parse_optional_mark();

        let mut orig_id = Vec::new();
        if self.starts_with(b"original-oid") {
            orig_id = self.parse_original_id();
        }

        let data = self.parse_data();
        if self.line_is_blank() {
            self.advance();
        }
        if self.err.is_some() {
            return;
        }

        let mark = self.p.ids.new_mark();
        let mut blob = Blob {
            mark,
            original_oid: orig_id,
            data,
            ..Default::default()
        };
        if old_mark != 0 {
            self.p.ids.record_rename(old_mark, mark);
        }

        if let Some(f) = self.cb.blob.as_mut() {
            f(&mut blob);
        }
        if !blob.el.was_handled() {
            let res = blob.dump(&mut self.w);
            self.dump_result(res);
        }
    }

    fn parse_reset(&mut self) {
        let ref_ = self.parse_ref_line(b"reset");
        self.record_exported(&ref_);

        let (_, from) = self.parse_optional_parent_ref(b"from");
        if self.line_is_blank() {
            self.advance();
        }
        if self.err.is_some() {
            return;
        }

        // fast-export emits extraneous resets with no "from"; drop them and forget
        // any tracked commit so the ref is not spuriously recorded as imported.
        if from.is_zero() {
            self.p.latest_commit.remove(&ref_);
            return;
        }

        let mut reset = Reset {
            ref_name: ref_.clone(),
            from: from.clone(),
            ..Default::default()
        };
        if let Some(f) = self.cb.reset.as_mut() {
            f(&mut reset);
        }
        self.p.latest_commit.insert(ref_.clone(), from);
        if !reset.el.was_handled() {
            self.record_imported(&ref_);
            let res = reset.dump(&mut self.w);
            self.dump_result(res);
        }
    }

    fn parse_commit(&mut self) {
        let branch = self.parse_ref_line(b"commit");
        self.record_exported(&branch);
        let old_mark = self.parse_optional_mark();

        let mut orig_id = Vec::new();
        if self.starts_with(b"original-oid") {
            orig_id = self.parse_original_id();
        }

        let mut author = UserInfo::default();
        let mut has_author = false;
        if self.starts_with(b"author ") {
            author = self.parse_user(b"author ");
            has_author = true;
        }
        let committer = self.parse_user(b"committer ");
        if !has_author {
            author = committer.clone();
        }

        // Strip any commit signature.
        while self.starts_with(b"gpgsig ") {
            self.advance();
            self.parse_data();
        }

        let mut encoding = Vec::new();
        if self.starts_with(b"encoding ") {
            encoding = self.parse_encoding();
        }

        let message = self.parse_data();

        // Parents: one optional "from" plus zero or more "merge" lines.
        let mut parents: Vec<Ref> = Vec::new();
        let (mut orig_present, from) = self.parse_optional_parent_ref(b"from");
        if orig_present && !from.is_zero() {
            parents.push(from);
        }
        while self.starts_with(b"merge ") {
            let (mp, mref) = self.parse_optional_parent_ref(b"merge");
            orig_present = orig_present || mp;
            if mp && !mref.is_zero() {
                parents.push(mref);
            }
        }

        // Honour fast-import's implicit-parent-by-branch behaviour.
        if !orig_present {
            if let Some(lc) = self.p.latest_commit.get(&branch) {
                if !lc.is_zero() {
                    parents = vec![lc.clone()];
                }
            }
        }

        // File changes.
        let mut file_changes: Vec<FileChange> = Vec::new();
        loop {
            let (fc, existed, _) = self.parse_optional_file_change();
            if !existed {
                break;
            }
            if let Some(fc) = fc {
                file_changes.push(fc);
            }
        }

        if self.line_is_blank() {
            self.advance();
        }
        if self.err.is_some() {
            return;
        }

        let mark = self.p.ids.new_mark();
        let mut commit = Commit {
            branch: branch.clone(),
            mark,
            original_oid: orig_id,
            author,
            committer,
            encoding,
            message,
            file_changes,
            ..Default::default()
        };
        if !parents.is_empty() {
            commit.from = parents[0].clone();
            commit.merges = parents[1..].to_vec();
        }
        if old_mark != 0 {
            self.p.ids.record_rename(old_mark, mark);
        }

        // refs/notes/ store note data in blobs named after other commits; pass
        // these through unmodified to avoid corrupting them via ordinary callbacks.
        if branch.starts_with(b"refs/notes/") {
            self.record_imported(&branch);
            let res = commit.dump(&mut self.w);
            self.dump_result(res);
            return;
        }

        if let Some(f) = self.cb.commit.as_mut() {
            f(&mut commit);
        }
        if !commit.el.is_skipped() {
            self.p
                .latest_commit
                .insert(branch.clone(), Ref { mark, oid: None });
        }
        if !commit.el.was_handled() {
            self.record_imported(&branch);
            let res = commit.dump(&mut self.w);
            self.dump_result(res);
        }
    }

    fn parse_tag(&mut self) {
        let name = self.parse_ref_line(b"tag");
        let mut tag_ref = b"refs/tags/".to_vec();
        tag_ref.extend_from_slice(&name);
        self.record_exported(&tag_ref);
        let old_mark = self.parse_optional_mark();
        let (_, from) = self.parse_optional_parent_ref(b"from");

        let mut orig_id = Vec::new();
        if self.starts_with(b"original-oid") {
            orig_id = self.parse_original_id();
        }

        let mut tagger = UserInfo::default();
        if self.starts_with(b"tagger") {
            tagger = self.parse_user(b"tagger ");
        }

        let message = self.parse_data();
        if self.line_is_blank() {
            self.advance();
        }
        if self.err.is_some() {
            return;
        }

        let mark = self.p.ids.new_mark();
        let mut tag = Tag {
            mark,
            ref_name: name.clone(),
            from: from.clone(),
            tagger,
            original_oid: orig_id,
            message,
            ..Default::default()
        };
        if old_mark != 0 {
            self.p.ids.record_rename(old_mark, mark);
        }

        if let Some(f) = self.cb.tag.as_mut() {
            f(&mut tag);
        }

        if !tag.from.is_zero() {
            if !tag.el.was_handled() {
                self.record_imported(&tag_ref);
                let res = tag.dump(&mut self.w);
                self.dump_result(res);
            }
        } else {
            tag.el.skip();
        }
    }

    fn parse_progress(&mut self) {
        let message = self.parse_ref_line(b"progress");
        if self.line_is_blank() {
            self.advance();
        }
        if self.err.is_some() {
            return;
        }
        let mut progress = Progress {
            message,
            ..Default::default()
        };
        if let Some(f) = self.cb.progress.as_mut() {
            f(&mut progress);
        }
        // Progress is not re-emitted by default.
    }

    fn parse_checkpoint(&mut self) {
        self.advance(); // consume "checkpoint"
        if self.line_is_blank() {
            self.advance();
        }
        let mut checkpoint = Checkpoint::default();
        if let Some(f) = self.cb.checkpoint.as_mut() {
            f(&mut checkpoint);
        }
        // Checkpoints are not re-emitted by default.
    }

    fn parse_literal(&mut self) {
        let mut cmd = LiteralCommand {
            line: self.line.clone(),
            ..Default::default()
        };
        self.advance();
        if !cmd.el.was_handled() {
            let res = cmd.dump(&mut self.w);
            self.dump_result(res);
        }
    }

    /// Parse a single file-change line if present. The bool reports whether a line
    /// was consumed; the third reports whether a modify targeting a skipped blob
    /// was dropped.
    fn parse_optional_file_change(&mut self) -> (Option<FileChange>, bool, bool) {
        if self.line.is_empty() {
            return (None, false, false);
        }

        match self.line[0] {
            b'M' => {
                let parts = split_n(&self.line, b' ', 4);
                if parts.len() < 4 {
                    return (None, false, false);
                }
                let mode = parts[1].to_vec();
                let mut idnum = parts[2].to_vec();
                if !idnum.is_empty() && idnum[0] == b':' {
                    idnum = idnum[1..].to_vec();
                }
                let mut path = trim_nl(parts[3]).to_vec();
                if !path.is_empty() && path[0] == b'"' {
                    path = PathQuoting.dequote(&path);
                }

                let blob_ref = if is_hex_oid(&idnum) {
                    Ref {
                        mark: 0,
                        oid: Some(idnum),
                    }
                } else {
                    match parse_i64(&idnum) {
                        Some(n) => {
                            let (new_mark, ok) = self.p.ids.translate(n);
                            if !ok {
                                self.advance();
                                return (None, true, true);
                            }
                            Ref {
                                mark: new_mark,
                                oid: None,
                            }
                        }
                        None => {
                            self.fail(ParseError(format!(
                                "filterrepo: bad blob id {:?}",
                                decode(&idnum)
                            )));
                            return (None, false, false);
                        }
                    }
                };

                self.advance();
                (
                    Some(FileChange {
                        type_: FileChangeType::Modify,
                        mode,
                        blob: blob_ref,
                        path,
                        ..Default::default()
                    }),
                    true,
                    false,
                )
            }

            b'D' => {
                let mut path = trim_nl(&self.line[2..]).to_vec();
                if !path.is_empty() && path[0] == b'"' {
                    path = PathQuoting.dequote(&path);
                }
                self.advance();
                (
                    Some(FileChange {
                        type_: FileChangeType::Delete,
                        path,
                        ..Default::default()
                    }),
                    true,
                    false,
                )
            }

            b'R' | b'C' => {
                let typ = if self.line[0] == b'C' {
                    FileChangeType::Copy
                } else {
                    FileChangeType::Rename
                };
                let rest = self.line[2..].to_vec();
                let (orig, new_path) = parse_rename_args(&rest);
                self.advance();
                (
                    Some(FileChange {
                        type_: typ,
                        orig_path: orig,
                        path: new_path,
                        ..Default::default()
                    }),
                    true,
                    false,
                )
            }

            b'd' => {
                if self.starts_with(b"deleteall") {
                    self.advance();
                    return (
                        Some(FileChange {
                            type_: FileChangeType::DeleteAll,
                            ..Default::default()
                        }),
                        true,
                        false,
                    );
                }
                (None, false, false)
            }

            _ => (None, false, false),
        }
    }
}

/// Split the `<orig> <new>` argument of an R/C line, honouring C-style quoting.
fn parse_rename_args(rest: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let rest = trim_nl(rest);
    let (orig, mut new_path): (Vec<u8>, Vec<u8>);
    if !rest.is_empty() && rest[0] == b'"' {
        let end = quoted_string_end(rest);
        if end > 0 {
            orig = PathQuoting.dequote(&rest[..end]);
            let mut tail = &rest[end..];
            if !tail.is_empty() && tail[0] == b' ' {
                tail = &tail[1..];
            }
            new_path = tail.to_vec();
        } else {
            orig = rest.to_vec();
            new_path = Vec::new();
        }
    } else if let Some(idx) = rest.iter().position(|&b| b == b' ') {
        orig = rest[..idx].to_vec();
        new_path = rest[idx + 1..].to_vec();
    } else {
        orig = rest.to_vec();
        new_path = Vec::new();
    }

    if !new_path.is_empty() && new_path[0] == b'"' {
        new_path = PathQuoting.dequote(&new_path);
    }
    (orig, new_path)
}

// --- helpers ---

/// `b` without a single trailing newline.
fn trim_nl(b: &[u8]) -> &[u8] {
    match b {
        [rest @ .., b'\n'] => rest,
        _ => b,
    }
}

/// `b` without trailing ` \t\r\n`.
fn trim_end_ws(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && matches!(b[end - 1], b' ' | b'\t' | b'\r' | b'\n') {
        end -= 1;
    }
    &b[..end]
}

/// Whether `b` is a 40- or 64-character lowercase hex object id.
fn is_hex_oid(b: &[u8]) -> bool {
    if b.len() != 40 && b.len() != 64 {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Index just past the closing quote of a C-style quoted string starting at
/// `b[0]`, or 0 if unterminated.
fn quoted_string_end(b: &[u8]) -> usize {
    if b.is_empty() || b[0] != b'"' {
        return 0;
    }
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1, // skip escaped byte
            b'"' => return i + 1,
            _ => {}
        }
        i += 1;
    }
    0
}

fn parse_i64(b: &[u8]) -> Option<i64> {
    std::str::from_utf8(b).ok()?.parse::<i64>().ok()
}

fn parse_usize(b: &[u8]) -> Option<usize> {
    std::str::from_utf8(b).ok()?.parse::<usize>().ok()
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Like Go `bytes.SplitN(b, [sep], n)`: at most `n` parts, splitting on the first
/// `n-1` separators; the last part is the remainder.
fn split_n(b: &[u8], sep: u8, n: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    if n == 0 {
        return out;
    }
    let mut start = 0;
    let mut i = 0;
    while i < b.len() && out.len() < n - 1 {
        if b[i] == sep {
            out.push(&b[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&b[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn parser_in_memory_roundtrip() {
        // A blob with an embedded NUL and newline, a root commit referencing it,
        // and a done marker (the shape produced by t9391's fixture).
        let bin_data = [b'a', 0u8, b'b', b'\n', b'c'];
        let mut input = Vec::new();
        input.extend_from_slice(b"blob\nmark :1\ndata 5\n");
        input.extend_from_slice(&bin_data);
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"reset refs/heads/main\n");
        input.extend_from_slice(b"commit refs/heads/main\nmark :2\n");
        input.extend_from_slice(b"author A U Thor <au@thor.test> 1112911570 -0700\n");
        input.extend_from_slice(b"committer C Om <c@om.test> 1112911570 -0700\n");
        input.extend_from_slice(b"data 6\nhello\n");
        input.extend_from_slice(b"M 100644 :1 bin.dat\n");
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"done\n");

        let mut p = FastExportParser::new();
        let mut out = Vec::new();
        p.run(&input[..], &mut out, Callbacks::default())
            .expect("run");

        assert!(
            contains(&out, &bin_data),
            "NUL blob payload preserved verbatim: {out:?}"
        );
        assert!(
            contains(&out, b"M 100644 :1 bin.dat\n"),
            "filechange preserved"
        );
        assert!(
            contains(&out, b"data 6\nhello\n"),
            "commit message preserved"
        );
        assert!(contains(&out, b"done\n"), "done marker preserved");
        assert_eq!(p.exported_refs(), &["refs/heads/main".to_string()]);
    }

    #[test]
    fn callback_can_skip_a_blob() {
        let mut input = Vec::new();
        input.extend_from_slice(b"blob\nmark :1\ndata 3\nabc\n");
        input.extend_from_slice(b"done\n");

        let mut p = FastExportParser::new();
        let mut out = Vec::new();
        let cb = Callbacks {
            blob: Some(Box::new(|b: &mut Blob| b.el.skip())),
            ..Default::default()
        };
        p.run(&input[..], &mut out, cb).expect("run");
        assert!(
            !contains(&out, b"abc"),
            "skipped blob must not be emitted: {out:?}"
        );
        assert!(contains(&out, b"done\n"));
    }
}
