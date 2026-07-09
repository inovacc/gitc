package filterrepo

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// --- pathspec.NewName -------------------------------------------------------

func TestPathSpecNewNameMatch(t *testing.T) {
	tests := []struct {
		name     string
		build    func() *PathSpec
		path     string
		wantKeep bool
		wantName string
	}{
		{
			name:     "exact file kept",
			build:    func() *PathSpec { s := NewPathSpec(); _ = s.AddMatch([]byte("filename")); return s },
			path:     "filename",
			wantKeep: true, wantName: "filename",
		},
		{
			name:     "unmatched file dropped",
			build:    func() *PathSpec { s := NewPathSpec(); _ = s.AddMatch([]byte("filename")); return s },
			path:     "other",
			wantKeep: false,
		},
		{
			name:     "directory-boundary match",
			build:    func() *PathSpec { s := NewPathSpec(); _ = s.AddMatch([]byte("moduleA")); return s },
			path:     "moduleA/keepme",
			wantKeep: true, wantName: "moduleA/keepme",
		},
		{
			name:     "directory prefix without boundary not matched",
			build:    func() *PathSpec { s := NewPathSpec(); _ = s.AddMatch([]byte("mod")); return s },
			path:     "moduleA",
			wantKeep: false,
		},
		{
			name: "union of two paths",
			build: func() *PathSpec {
				s := NewPathSpec()
				_ = s.AddMatch([]byte("ten"))
				_ = s.AddMatch([]byte("twenty"))
				return s
			},
			path:     "twenty",
			wantKeep: true, wantName: "twenty",
		},
		{
			name:     "empty spec keeps everything",
			build:    func() *PathSpec { return NewPathSpec() },
			path:     "anything/here",
			wantKeep: true, wantName: "anything/here",
		},
		{
			name:     "empty match path keeps all (unusual)",
			build:    func() *PathSpec { s := NewPathSpec(); _ = s.AddMatch([]byte("")); return s },
			path:     "whatever",
			wantKeep: true, wantName: "whatever",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, keep := tt.build().NewName([]byte(tt.path))
			if keep != tt.wantKeep {
				t.Fatalf("keep = %v, want %v", keep, tt.wantKeep)
			}
			if keep && string(got) != tt.wantName {
				t.Fatalf("name = %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestPathSpecGlobAndInvert(t *testing.T) {
	// --invert-paths --path-glob 't*en*' : drop paths matching the glob.
	s := NewPathSpec()
	if err := s.AddGlob([]byte("t*en*")); err != nil {
		t.Fatal(err)
	}
	s.Invert = true

	if _, keep := s.NewName([]byte("twenty")); keep {
		t.Errorf("twenty should be dropped under inverted glob")
	}
	if got, keep := s.NewName([]byte("filename")); !keep || string(got) != "filename" {
		t.Errorf("filename should be kept, got keep=%v name=%q", keep, got)
	}
}

func TestPathSpecGlobDirectoryExtension(t *testing.T) {
	// A glob '*me' auto-selects a directory named to match plus its contents.
	s := NewPathSpec()
	if err := s.AddGlob([]byte("moduleA")); err != nil {
		t.Fatal(err)
	}
	if _, keep := s.NewName([]byte("moduleA/keepme")); !keep {
		t.Errorf("moduleA/keepme should be kept via auto directory extension")
	}
}

func TestPathSpecRegexInvert(t *testing.T) {
	// --invert-paths --path-regex 'f.*e.*e'
	s := NewPathSpec()
	if err := s.AddRegex([]byte("f.*e.*e")); err != nil {
		t.Fatal(err)
	}
	s.Invert = true
	if _, keep := s.NewName([]byte("filename")); keep {
		t.Errorf("filename matches regex and should be dropped when inverted")
	}
	if _, keep := s.NewName([]byte("ten")); !keep {
		t.Errorf("ten does not match and should be kept when inverted")
	}
}

func TestPathSpecRegexRejectsBackref(t *testing.T) {
	s := NewPathSpec()
	if err := s.AddRegex([]byte(`(a)\1`)); err == nil {
		t.Errorf("expected RE2 rejection of backreference")
	}
}

func TestPathSpecRename(t *testing.T) {
	s := NewPathSpec()
	if err := s.AddRename([]byte("sequences/tiny"), []byte("sequences/small")); err != nil {
		t.Fatal(err)
	}
	got, keep := s.NewName([]byte("sequences/tiny/one"))
	if !keep {
		t.Fatal("rename-only spec should keep all paths")
	}
	if string(got) != "sequences/small/one" {
		t.Errorf("rename = %q, want sequences/small/one", got)
	}
	// Non-matching path unchanged but still kept.
	if got, keep := s.NewName([]byte("values/big")); !keep || string(got) != "values/big" {
		t.Errorf("unrelated path should pass through, got keep=%v name=%q", keep, got)
	}
}

func TestPathSpecRenameRegexBackref(t *testing.T) {
	s := NewPathSpec()
	if err := s.AddRenameRegex([]byte(`^([^/]*)/(.*)ge$`), []byte(`\2/\1/ge`)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.NewName([]byte("values/huge"))
	if string(got) != "hu/values/ge" {
		t.Errorf("regex rename = %q, want hu/values/ge", got)
	}
}

func TestPathSpecFromFile(t *testing.T) {
	// Selection directives (literal + glob), comments and blank lines ignored.
	spec := NewPathSpec()
	in := "# comment\n\nliteral:keepme\nglob:*.txt\n"
	if err := spec.addFromReaderLines(bufio.NewReader(strings.NewReader(in))); err != nil {
		t.Fatal(err)
	}
	if _, keep := spec.NewName([]byte("keepme")); !keep {
		t.Errorf("keepme should be selected")
	}
	if _, keep := spec.NewName([]byte("a/b.txt")); !keep {
		t.Errorf("*.txt glob should select a/b.txt")
	}
	if _, keep := spec.NewName([]byte("other")); keep {
		t.Errorf("unrelated path should be dropped when filters are present")
	}

	// A rename-only file keeps everything and rewrites matches.
	renameSpec := NewPathSpec()
	if err := renameSpec.addFromReaderLines(bufio.NewReader(strings.NewReader("values/huge==>values/gargantuan\n"))); err != nil {
		t.Fatal(err)
	}
	got, keep := renameSpec.NewName([]byte("values/huge"))
	if !keep || string(got) != "values/gargantuan" {
		t.Errorf("rename via file = %q keep=%v, want values/gargantuan", got, keep)
	}
}

// --- pathfilter.FilterFiles -------------------------------------------------

func TestFilterFilesDropRenameDeleteAll(t *testing.T) {
	spec := NewPathSpec()
	if err := spec.AddMatch([]byte("keep")); err != nil {
		t.Fatal(err)
	}
	if err := spec.AddRename([]byte("keep"), []byte("kept")); err != nil {
		t.Fatal(err)
	}

	commit := &Commit{FileChanges: []*FileChange{
		{Type: FileDeleteAll},
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 1}, Path: []byte("drop")},
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 2}, Path: []byte("keep")},
	}}
	if err := FilterFiles(commit, spec); err != nil {
		t.Fatal(err)
	}
	if len(commit.FileChanges) != 2 {
		t.Fatalf("expected 2 changes (deleteall + renamed keep), got %d", len(commit.FileChanges))
	}
	// deleteall sorts first (empty path).
	if commit.FileChanges[0].Type != FileDeleteAll {
		t.Errorf("deleteall not preserved/first: %+v", commit.FileChanges[0])
	}
	if string(commit.FileChanges[1].Path) != "kept" {
		t.Errorf("renamed path = %q, want kept", commit.FileChanges[1].Path)
	}
}

func TestFilterFilesRenameCollisionWithDeletion(t *testing.T) {
	// old -> new, where new is separately deleted: the deletion yields.
	spec := NewPathSpec()
	if err := spec.AddRename([]byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	commit := &Commit{FileChanges: []*FileChange{
		{Type: FileDelete, Path: []byte("new")},
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 5}, Path: []byte("old")},
	}}
	if err := FilterFiles(commit, spec); err != nil {
		t.Fatalf("collision with a deletion should be resolved, got %v", err)
	}
	if len(commit.FileChanges) != 1 || commit.FileChanges[0].Type != FileModify {
		t.Fatalf("expected the modify to win, got %+v", commit.FileChanges)
	}
}

func TestFilterFilesRenameHardCollisionErrors(t *testing.T) {
	spec := NewPathSpec()
	if err := spec.AddRename([]byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	commit := &Commit{FileChanges: []*FileChange{
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 7}, Path: []byte("new")},
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 8}, Path: []byte("old")},
	}}
	if err := FilterFiles(commit, spec); err == nil {
		t.Errorf("expected colliding-pathnames error")
	}
}

func TestFilterFilesSorted(t *testing.T) {
	spec := NewPathSpec()
	commit := &Commit{FileChanges: []*FileChange{
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 1}, Path: []byte("zeta")},
		{Type: FileModify, Mode: []byte("100644"), Blob: Ref{Mark: 2}, Path: []byte("alpha")},
	}}
	if err := FilterFiles(commit, spec); err != nil {
		t.Fatal(err)
	}
	if string(commit.FileChanges[0].Path) != "alpha" || string(commit.FileChanges[1].Path) != "zeta" {
		t.Errorf("changes not sorted: %q, %q", commit.FileChanges[0].Path, commit.FileChanges[1].Path)
	}
}

// --- replacetext.ParseReplaceRules ------------------------------------------

func parseRules(t *testing.T, in string) *ReplaceRules {
	t.Helper()
	r, err := ParseReplaceRules(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseReplaceTextSampleFixture(t *testing.T) {
	// t9390/sample-replace
	rules := parseRules(t, "mod==>modified-by-gremlins\n")
	if len(rules.Literals) != 1 || len(rules.Regexes) != 0 {
		t.Fatalf("expected one literal rule, got %+v", rules)
	}
	if string(rules.Literals[0].From) != "mod" || string(rules.Literals[0].To) != "modified-by-gremlins" {
		t.Errorf("bad literal rule: %+v", rules.Literals[0])
	}
}

func TestParseReplaceTextDefaultReplacement(t *testing.T) {
	rules := parseRules(t, "secret\n")
	if len(rules.Literals) != 1 {
		t.Fatalf("expected one literal, got %+v", rules)
	}
	if !bytes.Equal(rules.Literals[0].To, DefaultReplacement) {
		t.Errorf("default replacement = %q, want %q", rules.Literals[0].To, DefaultReplacement)
	}
}

func TestParseReplaceTextPrefixes(t *testing.T) {
	rules := parseRules(t, "literal:foo==>bar\nregex:a.c\nglob:*.log\n\n")
	if len(rules.Literals) != 1 {
		t.Fatalf("literals = %d, want 1", len(rules.Literals))
	}
	if string(rules.Literals[0].From) != "foo" || string(rules.Literals[0].To) != "bar" {
		t.Errorf("literal rule wrong: %+v", rules.Literals[0])
	}
	if len(rules.Regexes) != 2 {
		t.Fatalf("regexes = %d, want 2 (regex: + glob:)", len(rules.Regexes))
	}
	// glob rule compiled to anchored form should match a whole filename.
	if !rules.Regexes[1].Re.Match([]byte("error.log")) {
		t.Errorf("glob *.log should match error.log")
	}
	if rules.Regexes[1].Re.Match([]byte("error.log.1")) {
		t.Errorf("glob *.log is anchored and should not match error.log.1")
	}
}

func TestParseReplaceTextRegexBackrefError(t *testing.T) {
	if _, err := ParseReplaceRules(bufio.NewReader(strings.NewReader(`regex:(a)\1` + "\n"))); err == nil {
		t.Errorf("expected RE2 rejection for backreference")
	}
}

// --- blobfilter.ReplaceBlobText ---------------------------------------------

func TestReplaceBlobTextLiteralAndRegex(t *testing.T) {
	rules := parseRules(t, "mod==>modified-by-gremlins\nregex:se+cret\n")
	blob := &Blob{Data: []byte("this mod has a seecret value")}
	ReplaceBlobText(blob, rules)
	got := string(blob.Data)
	want := "this modified-by-gremlins has a ***REMOVED*** value"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReplaceBlobTextBinaryUntouched(t *testing.T) {
	rules := parseRules(t, "mod==>X\n")
	original := []byte("mod\x00mod")
	blob := &Blob{Data: append([]byte(nil), original...)}
	ReplaceBlobText(blob, rules)
	if !bytes.Equal(blob.Data, original) {
		t.Errorf("binary blob was modified: %q", blob.Data)
	}
}

func TestReplaceBlobTextEmptyRulesNoop(t *testing.T) {
	blob := &Blob{Data: []byte("unchanged")}
	ReplaceBlobText(blob, &ReplaceRules{})
	if string(blob.Data) != "unchanged" {
		t.Errorf("empty rules mutated data: %q", blob.Data)
	}
}
