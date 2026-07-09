package filterrepo

import (
	"bytes"
	"io"
	"strconv"
)

// pathQuoter is stateless; a single shared value is sufficient.
var pathQuoter PathQuoting

// Ref is a reference to a commit within a fast-import stream. It is either a
// mark (":N", when Mark > 0) or a literal object id such as a 40-hex SHA-1
// (when OID is non-nil). The zero value means "no reference".
type Ref struct {
	Mark int
	OID  []byte
}

// IsZero reports whether the reference points at nothing.
func (r Ref) IsZero() bool { return r.Mark == 0 && r.OID == nil }

// write emits the reference body ("%d" mark form or raw oid form) to w.
func (r Ref) write(w io.Writer) error {
	if r.Mark > 0 {
		_, err := io.WriteString(w, ":"+strconv.Itoa(r.Mark))
		return err
	}

	_, err := w.Write(r.OID)

	return err
}

// UserInfo holds the three components of an author/committer/tagger identity
// line: the name, the email (without angle brackets), and the raw date field.
type UserInfo struct {
	Name  []byte
	Email []byte
	Date  []byte
}

// element is embedded by every stream record and tracks whether the record has
// been dumped (1), skipped (2), or is still pending (0).
type element struct {
	dumped int
}

// Skip ensures the record will not be written to the output stream.
func (e *element) Skip() { e.dumped = 2 }

func (e *element) wasHandled() bool { return e.dumped != 0 }
func (e *element) markDumped()      { e.dumped = 1 }

// FileChangeType enumerates the file-change operations that can appear inside a
// commit. The deleteall pseudo-operation is represented distinctly.
type FileChangeType byte

const (
	FileModify    FileChangeType = 'M'
	FileDelete    FileChangeType = 'D'
	FileRename    FileChangeType = 'R'
	FileCopy      FileChangeType = 'C'
	FileDeleteAll FileChangeType = 0
)

// FileChange is a single modification within a commit.
type FileChange struct {
	Type     FileChangeType
	Mode     []byte // for FileModify, e.g. "100644"
	Blob     Ref    // for FileModify: the affected blob (mark or oid)
	Path     []byte // affected path (raw bytes, unquoted)
	OrigPath []byte // for FileRename/FileCopy: the source path
}

// Dump writes the file-change in fast-import syntax. A FileModify whose blob
// reference is empty represents a skipped blob and produces no output.
func (fc *FileChange) Dump(w io.Writer) error {
	switch fc.Type {
	case FileModify:
		if fc.Blob.IsZero() {
			return nil // skipped blob
		}

		if err := writeAll(w, []byte("M "), fc.Mode, []byte(" ")); err != nil {
			return err
		}

		if err := fc.Blob.write(w); err != nil {
			return err
		}

		return writeAll(w, []byte(" "), pathQuoter.Enquote(fc.Path), []byte("\n"))
	case FileDelete:
		return writeAll(w, []byte("D "), pathQuoter.Enquote(fc.Path), []byte("\n"))
	case FileRename, FileCopy:
		verb := []byte("R ")
		if fc.Type == FileCopy {
			verb = []byte("C ")
		}

		return writeAll(w, verb,
			pathQuoter.Enquote(fc.OrigPath), []byte(" "),
			pathQuoter.Enquote(fc.Path), []byte("\n"))
	case FileDeleteAll:
		_, err := io.WriteString(w, "deleteall\n")
		return err
	default:
		return io.ErrShortWrite
	}
}

// Blob is a blob record: file content plus its mark.
type Blob struct {
	element
	Mark        int
	OriginalOID []byte
	Data        []byte
}

// Dump writes the blob in fast-import syntax. The original-oid is intentionally
// not re-emitted (fast-import does not require it and dropping it does not
// change resulting object content).
func (b *Blob) Dump(w io.Writer) error {
	b.markDumped()

	if err := writeAll(w, []byte("blob\nmark :"), []byte(strconv.Itoa(b.Mark)), []byte("\n")); err != nil {
		return err
	}

	if err := writeAll(w, []byte("data "), []byte(strconv.Itoa(len(b.Data))), []byte("\n")); err != nil {
		return err
	}

	return writeAll(w, b.Data, []byte("\n"))
}

// Reset is a branch (re)creation record.
type Reset struct {
	element
	Ref  []byte
	From Ref
}

// Dump writes the reset in fast-import syntax.
func (r *Reset) Dump(w io.Writer) error {
	r.markDumped()

	if err := writeAll(w, []byte("reset "), r.Ref, []byte("\n")); err != nil {
		return err
	}

	if !r.From.IsZero() {
		if err := writeAll(w, []byte("from ")); err != nil {
			return err
		}

		if err := r.From.write(w); err != nil {
			return err
		}

		return writeAll(w, []byte("\n\n"))
	}

	return nil
}

// Commit is a commit record with all associated metadata and file changes.
type Commit struct {
	element
	Branch      []byte
	Mark        int
	OriginalOID []byte
	Author      UserInfo
	Committer   UserInfo
	Encoding    []byte
	Message     []byte
	From        Ref   // first parent; zero when the commit is a root
	Merges      []Ref // additional parents
	FileChanges []*FileChange
}

//nolint:funcorder // small predicate kept beside its use
func (c *Commit) hasParents() bool { return !c.From.IsZero() || len(c.Merges) > 0 }

// Dump writes the commit in fast-import syntax, reproducing fast-export's
// cosmetic trailing-newline conventions so that the resulting stream imports
// cleanly.
func (c *Commit) Dump(w io.Writer) error { //nolint:funlen // cohesive commit serializer
	c.markDumped()

	hasParents := c.hasParents()

	// A root commit is preceded by a reset so fast-import starts a fresh branch.
	if !hasParents {
		if err := writeAll(w, []byte("reset "), c.Branch, []byte("\n")); err != nil {
			return err
		}
	}

	if err := writeAll(w, []byte("commit "), c.Branch, []byte("\nmark :"),
		[]byte(strconv.Itoa(c.Mark)), []byte("\n")); err != nil {
		return err
	}

	if err := writeUser(w, "author ", c.Author); err != nil {
		return err
	}

	if err := writeUser(w, "committer ", c.Committer); err != nil {
		return err
	}

	if len(c.Encoding) > 0 {
		if err := writeAll(w, []byte("encoding "), c.Encoding, []byte("\n")); err != nil {
			return err
		}
	}

	// data <len>\n<message>[extra newline]
	extraNewline := !bytes.HasSuffix(c.Message, []byte("\n")) && (hasParents || len(c.FileChanges) > 0)

	if err := writeAll(w, []byte("data "), []byte(strconv.Itoa(len(c.Message))), []byte("\n"), c.Message); err != nil {
		return err
	}

	if extraNewline {
		if err := writeAll(w, []byte("\n")); err != nil {
			return err
		}
	}

	// Parents: first as "from", the rest as "merge".
	if !c.From.IsZero() {
		if err := writeAll(w, []byte("from ")); err != nil {
			return err
		}

		if err := c.From.write(w); err != nil {
			return err
		}

		if err := writeAll(w, []byte("\n")); err != nil {
			return err
		}
	}

	for _, m := range c.Merges {
		if err := writeAll(w, []byte("merge ")); err != nil {
			return err
		}

		if err := m.write(w); err != nil {
			return err
		}

		if err := writeAll(w, []byte("\n")); err != nil {
			return err
		}
	}

	for _, fc := range c.FileChanges {
		if err := fc.Dump(w); err != nil {
			return err
		}
	}

	// Workaround for pre-2.22 fast-import get-mark handling.
	if !hasParents && len(c.FileChanges) == 0 {
		if err := writeAll(w, []byte("\n")); err != nil {
			return err
		}
	}

	return writeAll(w, []byte("\n"))
}

// Tag is an annotated tag record.
type Tag struct {
	element
	Mark        int
	Ref         []byte // tag name without the refs/tags/ prefix
	From        Ref
	Tagger      UserInfo // Tagger.Name empty means no tagger line
	OriginalOID []byte
	Message     []byte
}

// Dump writes the tag in fast-import syntax.
func (t *Tag) Dump(w io.Writer) error {
	t.markDumped()

	if err := writeAll(w, []byte("tag "), t.Ref, []byte("\n")); err != nil {
		return err
	}

	if t.Mark > 0 {
		if err := writeAll(w, []byte("mark :"), []byte(strconv.Itoa(t.Mark)), []byte("\n")); err != nil {
			return err
		}
	}

	if err := writeAll(w, []byte("from ")); err != nil {
		return err
	}

	if err := t.From.write(w); err != nil {
		return err
	}

	if err := writeAll(w, []byte("\n")); err != nil {
		return err
	}

	if len(t.Tagger.Name) > 0 {
		if err := writeAll(w, []byte("tagger "), t.Tagger.Name, []byte(" <"),
			t.Tagger.Email, []byte("> "), t.Tagger.Date, []byte("\n")); err != nil {
			return err
		}
	}

	if err := writeAll(w, []byte("data "), []byte(strconv.Itoa(len(t.Message))), []byte("\n"), t.Message); err != nil {
		return err
	}

	return writeAll(w, []byte("\n"))
}

// Progress is a progress record echoed to fast-import.
type Progress struct {
	element
	Message []byte
}

// Dump writes the progress record.
func (p *Progress) Dump(w io.Writer) error {
	p.markDumped()
	return writeAll(w, []byte("progress "), p.Message, []byte("\n\n"))
}

// Checkpoint forces fast-import to flush the current packfile.
type Checkpoint struct {
	element
}

// Dump writes the checkpoint record.
func (c *Checkpoint) Dump(w io.Writer) error {
	c.markDumped()
	return writeAll(w, []byte("checkpoint\n\n"))
}

// LiteralCommand is a single verbatim line (feature/option/done/comment) passed
// through unchanged.
type LiteralCommand struct {
	element
	Line []byte
}

// Dump writes the literal line exactly as received.
func (l *LiteralCommand) Dump(w io.Writer) error {
	l.markDumped()
	return writeAll(w, l.Line)
}

// writeUser writes an identity line of the form "<prefix><name> <<email>> <date>\n".
func writeUser(w io.Writer, prefix string, u UserInfo) error {
	return writeAll(w, []byte(prefix), u.Name, []byte(" <"), u.Email, []byte("> "), u.Date, []byte("\n"))
}

// writeAll writes each chunk in order, stopping at the first error.
func writeAll(w io.Writer, chunks ...[]byte) error {
	for _, c := range chunks {
		if len(c) == 0 {
			continue
		}

		if _, err := w.Write(c); err != nil {
			return err
		}
	}

	return nil
}
