package filterrepo

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
)

// Callbacks holds optional hooks invoked as each record is parsed, before it is
// re-serialized. A callback may mutate the record or call its Skip method to
// drop it from the output. Any nil callback is ignored.
type Callbacks struct {
	Blob       func(*Blob)
	Reset      func(*Reset)
	Commit     func(*Commit)
	Tag        func(*Tag)
	Progress   func(*Progress)
	Checkpoint func(*Checkpoint)
	Done       func()
}

// FastExportParser performs a single streaming pass over a `git fast-export`
// stream, dispatching each record to the matching callback and re-emitting it in
// fast-import syntax. It is stateful and single-use per Run.
type FastExportParser struct {
	ids *IDMap

	// latestCommit tracks the last mark seen on each branch, so that commits
	// relying on fast-import's implicit-parent-by-branch-name behaviour can be
	// given an explicit parent.
	latestCommit map[string]Ref

	exportedRefs []string
	importedRefs []string
	seenExported map[string]bool
	seenImported map[string]bool

	cb   Callbacks
	br   *bufio.Reader
	w    io.Writer
	pq   PathQuoting
	line []byte
	err  error
	done bool
}

// NewFastExportParser returns a ready-to-run parser.
func NewFastExportParser() *FastExportParser {
	return &FastExportParser{
		ids:          NewIDMap(),
		latestCommit: make(map[string]Ref),
		seenExported: make(map[string]bool),
		seenImported: make(map[string]bool),
	}
}

// Run reads a fast-export stream from r, invokes cb for each record, and writes
// the re-serialized fast-import stream to w. It returns the first error
// encountered, or nil on a clean parse.
func (p *FastExportParser) Run(r io.Reader, w io.Writer, cb Callbacks) error {
	p.br = bufio.NewReaderSize(r, 1<<16)
	p.w = w
	p.cb = cb

	p.advance()
	for p.err == nil && !p.done && len(p.line) > 0 {
		switch {
		case p.startsWith("blob"):
			p.parseBlob()
		case p.startsWith("reset"):
			p.parseReset()
		case p.startsWith("commit"):
			p.parseCommit()
		case p.startsWith("tag"):
			p.parseTag()
		case p.startsWith("progress"):
			p.parseProgress()
		case p.startsWith("checkpoint"):
			p.parseCheckpoint()
		case p.startsWith("feature"), p.startsWith("option"), p.startsWith("#"):
			p.parseLiteral()
		case p.startsWith("done"):
			if p.cb.Done != nil {
				p.cb.Done()
			}
			p.parseLiteral()
			p.done = true
		case p.startsWith("get-mark"), p.startsWith("cat-blob"), p.startsWith("ls"):
			p.fail(fmt.Errorf("filterrepo: unsupported command: %q", trimNL(p.line)))
		default:
			p.fail(fmt.Errorf("filterrepo: could not parse line: %q", trimNL(p.line)))
		}
	}
	return p.err
}

// ExportedRefs returns the refs observed in the input stream, in first-seen order.
func (p *FastExportParser) ExportedRefs() []string { return p.exportedRefs }

// ImportedRefs returns the refs written to the output stream, in first-seen order.
func (p *FastExportParser) ImportedRefs() []string { return p.importedRefs }

// IDs exposes the mark registry used by the parser.
func (p *FastExportParser) IDs() *IDMap { return p.ids }

// --- low-level line handling ---

func (p *FastExportParser) advance() {
	if p.err != nil {
		return
	}
	line, err := p.br.ReadBytes('\n')
	if err != nil {
		if err == io.EOF {
			if len(line) == 0 {
				p.line = nil
			} else {
				p.line = line
			}
			return
		}
		p.fail(err)
		p.line = nil
		return
	}
	p.line = line
}

func (p *FastExportParser) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

func (p *FastExportParser) startsWith(s string) bool {
	return bytes.HasPrefix(p.line, []byte(s))
}

func (p *FastExportParser) lineIsBlank() bool {
	return len(p.line) == 1 && p.line[0] == '\n'
}

func (p *FastExportParser) recordExported(ref []byte) {
	s := string(ref)
	if !p.seenExported[s] {
		p.seenExported[s] = true
		p.exportedRefs = append(p.exportedRefs, s)
	}
}

func (p *FastExportParser) recordImported(ref []byte) {
	s := string(ref)
	if !p.seenImported[s] {
		p.seenImported[s] = true
		p.importedRefs = append(p.importedRefs, s)
	}
}

// --- token parsers ---

func (p *FastExportParser) parseOptionalMark() int {
	if !p.startsWith("mark :") {
		return 0
	}
	num := trimNL(p.line[len("mark :"):])
	n, err := strconv.Atoi(string(num))
	if err != nil {
		return 0
	}
	p.advance()
	return n
}

// parseOptionalParentRef parses a "from"/"merge" line if present. It returns
// whether a parent line was consumed and the (translated) reference; a skipped
// parent yields present==true with a zero Ref.
func (p *FastExportParser) parseOptionalParentRef(refname string) (present bool, ref Ref) {
	markPrefix := refname + " :"
	if p.startsWith(markPrefix) {
		num := trimNL(p.line[len(markPrefix):])
		if n, err := strconv.Atoi(string(num)); err == nil {
			newMark, ok := p.ids.Translate(n)
			p.advance()
			if !ok {
				return true, Ref{}
			}
			return true, Ref{Mark: newMark}
		}
	}
	oidPrefix := refname + " "
	if p.startsWith(oidPrefix) {
		rest := trimNL(p.line[len(oidPrefix):])
		if isHexOID(rest) {
			oid := append([]byte(nil), rest...)
			p.advance()
			return true, Ref{OID: oid}
		}
	}
	return false, Ref{}
}

func (p *FastExportParser) parseOriginalID() []byte {
	id := bytes.TrimRight(p.line[len("original-oid "):], " \t\r\n")
	out := append([]byte(nil), id...)
	p.advance()
	return out
}

func (p *FastExportParser) parseEncoding() []byte {
	enc := bytes.TrimRight(p.line[len("encoding "):], " \t\r\n")
	out := append([]byte(nil), enc...)
	p.advance()
	return out
}

// parseRefLine returns the argument of a "<prefix> <arg>\n" line and advances.
func (p *FastExportParser) parseRefLine(prefix string) []byte {
	if !p.startsWith(prefix + " ") {
		p.fail(fmt.Errorf("filterrepo: malformed %s line: %q", prefix, trimNL(p.line)))
		return nil
	}
	arg := trimNL(p.line[len(prefix)+1:])
	out := append([]byte(nil), arg...)
	p.advance()
	return out
}

// parseUser parses an "author"/"committer"/"tagger" identity line.
func (p *FastExportParser) parseUser(prefix string) UserInfo {
	rest := trimNL(p.line[len(prefix):])
	var u UserInfo
	lt := bytes.Index(rest, []byte(" <"))
	if lt < 0 {
		u.Name = append([]byte(nil), rest...)
		p.advance()
		return u
	}
	u.Name = append([]byte(nil), rest[:lt]...)
	after := rest[lt+2:]
	gt := bytes.Index(after, []byte("> "))
	if gt < 0 {
		u.Email = append([]byte(nil), after...)
	} else {
		u.Email = append([]byte(nil), after[:gt]...)
		u.Date = append([]byte(nil), after[gt+2:]...)
	}
	p.advance()
	return u
}

// parseData reads a length-prefixed ("data <n>") or delimited ("data <<EOF")
// payload, reading exactly the declared number of raw bytes for the counted
// form so embedded newlines and NUL bytes are preserved.
func (p *FastExportParser) parseData() []byte {
	fields := bytes.Fields(p.line)
	if len(fields) < 2 || !bytes.Equal(fields[0], []byte("data")) {
		p.fail(fmt.Errorf("filterrepo: expected data line, got %q", trimNL(p.line)))
		return nil
	}
	spec := fields[1]

	if bytes.HasPrefix(spec, []byte("<<")) {
		delim := append([]byte(nil), spec[2:]...)
		var buf bytes.Buffer
		for {
			l, err := p.br.ReadBytes('\n')
			if len(l) == 0 && err != nil {
				break
			}
			if bytes.Equal(trimNL(l), delim) {
				break
			}
			buf.Write(l)
		}
		p.advance()
		if p.lineIsBlank() {
			p.advance()
		}
		return buf.Bytes()
	}

	size, err := strconv.Atoi(string(spec))
	if err != nil {
		p.fail(fmt.Errorf("filterrepo: bad data length %q: %w", spec, err))
		return nil
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(p.br, data); err != nil {
		p.fail(fmt.Errorf("filterrepo: short read on data payload: %w", err))
		return nil
	}
	p.advance()
	if p.lineIsBlank() {
		p.advance()
	}
	return data
}

// --- record parsers ---

func (p *FastExportParser) parseBlob() {
	p.advance() // consume "blob"
	oldMark := p.parseOptionalMark()

	var origID []byte
	if p.startsWith("original-oid") {
		origID = p.parseOriginalID()
	}

	data := p.parseData()
	if p.lineIsBlank() {
		p.advance()
	}
	if p.err != nil {
		return
	}

	mark := p.ids.New()
	blob := &Blob{Mark: mark, OriginalOID: origID, Data: data}
	if oldMark != 0 {
		p.ids.RecordRename(oldMark, mark)
	}

	if p.cb.Blob != nil {
		p.cb.Blob(blob)
	}
	if !blob.wasHandled() {
		p.fail(blob.Dump(p.w))
	}
}

func (p *FastExportParser) parseReset() {
	ref := p.parseRefLine("reset")
	p.recordExported(ref)
	_, from := p.parseOptionalParentRef("from")
	if p.lineIsBlank() {
		p.advance()
	}
	if p.err != nil {
		return
	}

	// fast-export emits extraneous resets with no "from"; drop them and forget
	// any tracked commit so the ref is not spuriously recorded as imported.
	if from.IsZero() {
		delete(p.latestCommit, string(ref))
		return
	}

	reset := &Reset{Ref: ref, From: from}
	if p.cb.Reset != nil {
		p.cb.Reset(reset)
	}
	p.latestCommit[string(ref)] = from
	if !reset.wasHandled() {
		p.recordImported(ref)
		p.fail(reset.Dump(p.w))
	}
}

func (p *FastExportParser) parseCommit() {
	branch := p.parseRefLine("commit")
	p.recordExported(branch)
	oldMark := p.parseOptionalMark()

	var origID []byte
	if p.startsWith("original-oid") {
		origID = p.parseOriginalID()
	}

	var author UserInfo
	hasAuthor := false
	if p.startsWith("author ") {
		author = p.parseUser("author ")
		hasAuthor = true
	}
	committer := p.parseUser("committer ")
	if !hasAuthor {
		author = committer
	}

	// Strip any commit signature.
	for p.startsWith("gpgsig ") {
		p.advance()
		p.parseData()
	}

	var encoding []byte
	if p.startsWith("encoding ") {
		encoding = p.parseEncoding()
	}

	message := p.parseData()

	// Parents: one optional "from" plus zero or more "merge" lines.
	var parents []Ref
	origPresent, from := p.parseOptionalParentRef("from")
	if origPresent && !from.IsZero() {
		parents = append(parents, from)
	}
	for p.startsWith("merge ") {
		mp, mref := p.parseOptionalParentRef("merge")
		origPresent = origPresent || mp
		if mp && !mref.IsZero() {
			parents = append(parents, mref)
		}
	}

	// Honour fast-import's implicit-parent-by-branch behaviour: with no explicit
	// parent, the previous commit on this branch is the parent.
	if !origPresent {
		if lc, ok := p.latestCommit[string(branch)]; ok && !lc.IsZero() {
			parents = []Ref{lc}
		}
	}

	// File changes.
	var fileChanges []*FileChange
	for {
		fc, existed, _ := p.parseOptionalFileChange()
		if !existed {
			break
		}
		if fc != nil {
			fileChanges = append(fileChanges, fc)
		}
	}
	if p.lineIsBlank() {
		p.advance()
	}
	if p.err != nil {
		return
	}

	mark := p.ids.New()
	commit := &Commit{
		Branch:      branch,
		Mark:        mark,
		OriginalOID: origID,
		Author:      author,
		Committer:   committer,
		Encoding:    encoding,
		Message:     message,
		FileChanges: fileChanges,
	}
	if len(parents) > 0 {
		commit.From = parents[0]
		commit.Merges = parents[1:]
	}
	if oldMark != 0 {
		p.ids.RecordRename(oldMark, mark)
	}

	// refs/notes/ store note data in blobs named after other commits; passing
	// these through unmodified avoids corrupting them via ordinary callbacks.
	if bytes.HasPrefix(branch, []byte("refs/notes/")) {
		p.recordImported(branch)
		p.fail(commit.Dump(p.w))
		return
	}

	if p.cb.Commit != nil {
		p.cb.Commit(commit)
	}

	if commit.dumped != 2 { // not skipped
		p.latestCommit[string(branch)] = Ref{Mark: mark}
	}
	if !commit.wasHandled() {
		p.recordImported(branch)
		p.fail(commit.Dump(p.w))
	}
}

func (p *FastExportParser) parseTag() {
	name := p.parseRefLine("tag")
	tagRef := append([]byte("refs/tags/"), name...)
	p.recordExported(tagRef)
	oldMark := p.parseOptionalMark()
	_, from := p.parseOptionalParentRef("from")

	var origID []byte
	if p.startsWith("original-oid") {
		origID = p.parseOriginalID()
	}

	var tagger UserInfo
	if p.startsWith("tagger") {
		tagger = p.parseUser("tagger ")
	}
	message := p.parseData()
	if p.lineIsBlank() {
		p.advance()
	}
	if p.err != nil {
		return
	}

	mark := p.ids.New()
	tag := &Tag{Mark: mark, Ref: name, From: from, Tagger: tagger, OriginalOID: origID, Message: message}
	if oldMark != 0 {
		p.ids.RecordRename(oldMark, mark)
	}

	if p.cb.Tag != nil {
		p.cb.Tag(tag)
	}

	if !tag.From.IsZero() {
		if !tag.wasHandled() {
			p.recordImported(tagRef)
			p.fail(tag.Dump(p.w))
		}
	} else {
		tag.Skip()
	}
}

func (p *FastExportParser) parseProgress() {
	message := p.parseRefLine("progress")
	if p.lineIsBlank() {
		p.advance()
	}
	if p.err != nil {
		return
	}
	progress := &Progress{Message: message}
	if p.cb.Progress != nil {
		p.cb.Progress(progress)
	}
	// Progress is not re-emitted by default; a callback that wants it must do so.
}

func (p *FastExportParser) parseCheckpoint() {
	p.advance() // consume "checkpoint"
	if p.lineIsBlank() {
		p.advance()
	}
	checkpoint := &Checkpoint{}
	if p.cb.Checkpoint != nil {
		p.cb.Checkpoint(checkpoint)
	}
	// Checkpoints are not re-emitted by default.
}

func (p *FastExportParser) parseLiteral() {
	line := append([]byte(nil), p.line...)
	cmd := &LiteralCommand{Line: line}
	p.advance()
	if !cmd.wasHandled() {
		p.fail(cmd.Dump(p.w))
	}
}

// parseOptionalFileChange parses a single file-change line if present. The
// second result reports whether a line was consumed; the third reports whether
// a modify targeting a skipped blob was dropped.
func (p *FastExportParser) parseOptionalFileChange() (fc *FileChange, existed, skipped bool) {
	if len(p.line) == 0 {
		return nil, false, false
	}
	switch p.line[0] {
	case 'M':
		parts := bytes.SplitN(p.line, []byte(" "), 4)
		if len(parts) < 4 {
			return nil, false, false
		}
		mode := append([]byte(nil), parts[1]...)
		idnum := parts[2]
		if len(idnum) > 0 && idnum[0] == ':' {
			idnum = idnum[1:]
		}
		path := trimNL(parts[3])
		if len(path) > 0 && path[0] == '"' {
			path = p.pq.Dequote(path)
		}
		path = append([]byte(nil), path...)

		var blobRef Ref
		if isHexOID(idnum) {
			blobRef = Ref{OID: append([]byte(nil), idnum...)}
		} else {
			n, err := strconv.Atoi(string(idnum))
			if err != nil {
				p.fail(fmt.Errorf("filterrepo: bad blob id %q", idnum))
				return nil, false, false
			}
			newMark, ok := p.ids.Translate(n)
			if !ok {
				p.advance()
				return nil, true, true
			}
			blobRef = Ref{Mark: newMark}
		}
		p.advance()
		return &FileChange{Type: FileModify, Mode: mode, Blob: blobRef, Path: path}, true, false

	case 'D':
		path := trimNL(p.line[2:])
		if len(path) > 0 && path[0] == '"' {
			path = p.pq.Dequote(path)
		}
		path = append([]byte(nil), path...)
		p.advance()
		return &FileChange{Type: FileDelete, Path: path}, true, false

	case 'R', 'C':
		typ := FileRename
		if p.line[0] == 'C' {
			typ = FileCopy
		}
		orig, newPath := p.parseRenameArgs(p.line[2:])
		p.advance()
		return &FileChange{Type: typ, OrigPath: orig, Path: newPath}, true, false

	case 'd':
		if p.startsWith("deleteall") {
			p.advance()
			return &FileChange{Type: FileDeleteAll}, true, false
		}
	}
	return nil, false, false
}

// parseRenameArgs splits the "<orig> <new>" argument of an R/C line, honouring
// C-style quoting on either side.
func (p *FastExportParser) parseRenameArgs(rest []byte) (orig, newPath []byte) {
	rest = trimNL(rest)
	if len(rest) > 0 && rest[0] == '"' {
		end := quotedStringEnd(rest)
		if end > 0 {
			orig = p.pq.Dequote(rest[:end])
			tail := rest[end:]
			if len(tail) > 0 && tail[0] == ' ' {
				tail = tail[1:]
			}
			newPath = tail
		} else {
			orig = rest
		}
	} else if idx := bytes.IndexByte(rest, ' '); idx >= 0 {
		orig = rest[:idx]
		newPath = rest[idx+1:]
	} else {
		orig = rest
	}
	if len(newPath) > 0 && newPath[0] == '"' {
		newPath = p.pq.Dequote(newPath)
	}
	orig = append([]byte(nil), orig...)
	newPath = append([]byte(nil), newPath...)
	return orig, newPath
}

// --- helpers ---

// trimNL returns b without a single trailing newline.
func trimNL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		return b[:n-1]
	}
	return b
}

// isHexOID reports whether b is a 40- or 64-character lowercase hex object id.
func isHexOID(b []byte) bool {
	if len(b) != 40 && len(b) != 64 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// quotedStringEnd returns the index just past the closing quote of a C-style
// quoted string that begins at b[0], or 0 if unterminated.
func quotedStringEnd(b []byte) int {
	if len(b) == 0 || b[0] != '"' {
		return 0
	}
	for i := 1; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++ // skip escaped byte
		case '"':
			return i + 1
		}
	}
	return 0
}
