//! CSV report emitter (faithful port of Go `report/csv.go`).
//!
//! Go uses `encoding/csv`. Rust std has no CSV, so the quoting is hand-rolled to
//! reproduce Go's `csv.Writer` rules EXACTLY (`fieldNeedsQuotes`): a field is
//! quoted iff it is non-empty AND (it is `\.`, OR contains `,`/`"`/CR/LF, OR its
//! first rune is Unicode whitespace); quotes inside are doubled. Records are
//! joined with `,` and terminated with `\n` (Go's default). No `csv` crate.

use std::io::{self, Write};

use crate::Finding;

/// Emits findings as CSV (Go `CsvReporter`).
pub struct CsvReporter;

impl CsvReporter {
    /// Write `findings` as CSV to `w` (Go `(*CsvReporter).Write`). Writes nothing
    /// for an empty slice.
    pub fn write(&self, w: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        let mut columns: Vec<&str> = vec![
            "RuleID",
            "Commit",
            "File",
            "SymlinkFile",
            "Secret",
            "Match",
            "StartLine",
            "EndLine",
            "StartColumn",
            "EndColumn",
            "Author",
            "Message",
            "Date",
            "Email",
            "Fingerprint",
            "Tags",
        ];
        // A miserable attempt at "omitempty" (mirrors the Go source exactly).
        let has_link = !findings[0].link.is_empty();
        if has_link {
            columns.push("Link");
        }
        let has_match_context = findings.iter().any(|f| !f.match_context.is_empty());
        if has_match_context {
            columns.push("MatchContext");
        }

        write_record(w, &columns)?;

        for f in findings {
            let mut row: Vec<String> = vec![
                f.rule_id.clone(),
                f.commit.clone(),
                f.file.clone(),
                f.symlink_file.clone(),
                f.secret.clone(),
                f.r#match.clone(),
                f.start_line.to_string(),
                f.end_line.to_string(),
                f.start_column.to_string(),
                f.end_column.to_string(),
                f.author.clone(),
                f.message.clone(),
                f.date.clone(),
                f.email.clone(),
                f.fingerprint.clone(),
                f.tags.join(" "),
            ];
            if has_link {
                row.push(f.link.clone());
            }
            if has_match_context {
                row.push(f.match_context.clone());
            }
            write_record(w, &row)?;
        }

        Ok(())
    }
}

/// Write one CSV record: comma-joined quoted fields + `\n`.
fn write_record<S: AsRef<str>>(w: &mut dyn Write, fields: &[S]) -> io::Result<()> {
    let line: Vec<String> = fields.iter().map(|f| csv_field(f.as_ref())).collect();
    w.write_all(line.join(",").as_bytes())?;
    w.write_all(b"\n")
}

/// Quote a field per Go `encoding/csv` if needed; otherwise return it as-is.
fn csv_field(field: &str) -> String {
    if !needs_quotes(field) {
        return field.to_string();
    }
    let mut s = String::with_capacity(field.len() + 2);
    s.push('"');
    for c in field.chars() {
        if c == '"' {
            s.push('"'); // double an embedded quote
        }
        s.push(c);
    }
    s.push('"');
    s
}

/// Go `csv.Writer.fieldNeedsQuotes` (with the default comma `,`).
fn needs_quotes(field: &str) -> bool {
    if field.is_empty() {
        return false;
    }
    if field == "\\." {
        return true;
    }
    if field
        .bytes()
        .any(|c| c == b'\n' || c == b'\r' || c == b'"' || c == b',')
    {
        return true;
    }
    // First rune is whitespace (Go: `unicode.IsSpace(r1)`).
    field.chars().next().is_some_and(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;

    /// Golden captured verbatim from the Go fixture
    /// `testdata/expected/report/csv_simple.csv` (line endings normalized to `\n`).
    const GOLDEN_CSV: &str = "RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags\ntest-rule,0000000000000000,auth.py,,a secret,line containing secret,1,2,1,2,John Doe,opps,10-19-2003,johndoe@gmail.com,fingerprint,tag1 tag2 tag3\n";

    /// Normalize line endings, like the Go test's `lineEndingReplacer`.
    fn norm(s: &str) -> String {
        s.replace("\r\n", "\n").replace('\r', "\n")
    }

    fn simple_finding() -> Finding {
        Finding {
            rule_id: "test-rule".to_string(),
            r#match: "line containing secret".to_string(),
            secret: "a secret".to_string(),
            start_line: 1,
            end_line: 2,
            start_column: 1,
            end_column: 2,
            message: "opps".to_string(),
            file: "auth.py".to_string(),
            commit: "0000000000000000".to_string(),
            author: "John Doe".to_string(),
            email: "johndoe@gmail.com".to_string(),
            date: "10-19-2003".to_string(),
            fingerprint: "fingerprint".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn write_csv_simple() {
        let mut buf = Vec::new();
        CsvReporter
            .write(&mut buf, std::slice::from_ref(&simple_finding()))
            .unwrap();
        let got = norm(&String::from_utf8(buf).unwrap());
        assert_eq!(got, norm(GOLDEN_CSV));
    }

    #[test]
    fn write_csv_empty() {
        let mut buf = Vec::new();
        CsvReporter.write(&mut buf, &[]).unwrap();
        assert!(buf.is_empty(), "empty findings must write nothing");
    }

    // Differential golden captured from the Go source (`encoding/csv`) for a
    // finding that hits EVERY quoting trigger the simple test misses: a comma
    // (`sec,ret`), an embedded quote (`say "hi"` → doubled), a leading space
    // (`" spaced"`), and an embedded newline (`line1\nline2` → quoted) — plus the
    // conditional `Link` + `MatchContext` columns. Pins the hand-rolled quoting
    // against Go byte-for-byte.
    const GOLDEN_CSV_QUOTED: &str = concat!(
    "RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,",
    "EndColumn,Author,Message,Date,Email,Fingerprint,Tags,Link,MatchContext\n",
    "r1,c1,\"a\"\"b,c\",,\"sec,ret\",\"say \"\"hi\"\"\",1,1,1,1,\" spaced\",",
    "\"line1\nline2\",d,e,fp,t1 t2,http://x,ctx here\n"
    );

    #[test]
    fn diff_csv_quoting_matches_go() {
        let f = Finding {
            rule_id: "r1".to_string(),
            commit: "c1".to_string(),
            file: "a\"b,c".to_string(),
            secret: "sec,ret".to_string(),
            r#match: "say \"hi\"".to_string(),
            start_line: 1,
            end_line: 1,
            start_column: 1,
            end_column: 1,
            author: " spaced".to_string(),
            message: "line1\nline2".to_string(),
            date: "d".to_string(),
            email: "e".to_string(),
            fingerprint: "fp".to_string(),
            tags: vec!["t1".to_string(), "t2".to_string()],
            link: "http://x".to_string(),
            match_context: "ctx here".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        CsvReporter.write(&mut buf, std::slice::from_ref(&f)).unwrap();
        let got = norm(&String::from_utf8(buf).unwrap());
        assert_eq!(got, norm(GOLDEN_CSV_QUOTED));
    }
}
