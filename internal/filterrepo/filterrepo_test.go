package filterrepo

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPathQuotingDequote(t *testing.T) {
	var pq PathQuoting
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"unquoted", []byte("simple.txt"), []byte("simple.txt")},
		{"quoted plain", []byte(`"simple.txt"`), []byte("simple.txt")},
		{"newline escape", []byte(`"a\nb"`), []byte("a\nb")},
		{"tab escape", []byte(`"a\tb"`), []byte("a\tb")},
		{"quote escape", []byte(`"a\"b"`), []byte(`a"b`)},
		{"backslash escape", []byte(`"a\\b"`), []byte(`a\b`)},
		{"octal high byte", []byte(`"caf\303\251.txt"`), []byte("caf\xc3\xa9.txt")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pq.Dequote(tc.in); !bytes.Equal(got, tc.want) {
				t.Fatalf("Dequote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPathQuotingEnquote(t *testing.T) {
	var pq PathQuoting
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"plain unquoted", []byte("simple.txt"), []byte("simple.txt")},
		{"space not quoted", []byte("my file.txt"), []byte("my file.txt")},
		{"utf8 not quoted", []byte("caf\xc3\xa9.txt"), []byte("caf\xc3\xa9.txt")},
		{"newline quoted", []byte("a\nb"), []byte(`"a\nb"`)},
		{"leading quote quoted", []byte(`"x`), []byte(`"\"x"`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pq.Enquote(tc.in); !bytes.Equal(got, tc.want) {
				t.Fatalf("Enquote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPathQuotingRoundTrip(t *testing.T) {
	var pq PathQuoting
	for _, raw := range [][]byte{
		[]byte("plain"),
		[]byte("a\nb"),
		[]byte("caf\xc3\xa9"),
		{0x00, 0x01, 0xff, '"', '\\', '\n'},
	} {
		got := pq.Dequote(pq.Enquote(raw))
		if !bytes.Equal(got, raw) {
			t.Fatalf("round trip mismatch: raw=%q enquote=%q dequote=%q", raw, pq.Enquote(raw), got)
		}
	}
}

func TestIDMapTranslate(t *testing.T) {
	m := NewIDMap()
	if m.HasRenames() {
		t.Fatal("new map should have no renames")
	}
	a, b := m.New(), m.New()
	if a != 1 || b != 2 {
		t.Fatalf("New() sequence = %d,%d want 1,2", a, b)
	}
	m.RecordRename(5, b)
	if got, ok := m.Translate(5); !ok || got != 2 {
		t.Fatalf("Translate(5) = %d,%v want 2,true", got, ok)
	}
	if got, ok := m.Translate(9); !ok || got != 9 {
		t.Fatalf("Translate(9) = %d,%v want 9,true (identity)", got, ok)
	}
	m.RecordRename(7, MarkNone)
	if got, ok := m.Translate(7); ok || got != MarkNone {
		t.Fatalf("Translate(7) = %d,%v want none,false", got, ok)
	}
	if !m.HasRenames() {
		t.Fatal("map should report renames")
	}
}

func TestGlobToRegexAnchored(t *testing.T) {
	src := string(GlobToRegex([]byte("*.txt")))
	if !strings.HasPrefix(src, `(?s)\A`) || !strings.HasSuffix(src, `\z`) {
		t.Fatalf("glob regex not anchored: %q", src)
	}
	if !strings.Contains(src, ".*") {
		t.Fatalf("glob '*' not translated to '.*': %q", src)
	}
}

// TestParserInMemory feeds a hand-authored fast-export fixture (in the shape
// produced by t9391's create_fast_export_output.py) through the parser and
// checks that re-serialization preserves record structure and payload bytes,
// including a NUL-containing blob.
func TestParserInMemory(t *testing.T) {
	// A blob with an embedded NUL and newline, a root commit referencing it,
	// and a done marker.
	binData := []byte{'a', 0x00, 'b', '\n', 'c'}
	var in bytes.Buffer
	in.WriteString("blob\n")
	in.WriteString("mark :1\n")
	in.WriteString("data 5\n")
	in.Write(binData)
	in.WriteString("\n")
	in.WriteString("reset refs/heads/main\n")
	in.WriteString("commit refs/heads/main\n")
	in.WriteString("mark :2\n")
	in.WriteString("author A U Thor <au@thor.test> 1112911570 -0700\n")
	in.WriteString("committer C Om <c@om.test> 1112911570 -0700\n")
	in.WriteString("data 6\n")
	in.WriteString("hello\n")
	in.WriteString("M 100644 :1 bin.dat\n")
	in.WriteString("\n")
	in.WriteString("done\n")

	p := NewFastExportParser()
	var out bytes.Buffer
	if err := p.Run(bytes.NewReader(in.Bytes()), &out, Callbacks{}); err != nil {
		t.Fatalf("parser Run: %v", err)
	}

	got := out.Bytes()
	// The NUL-containing blob payload must survive verbatim.
	if !bytes.Contains(got, binData) {
		t.Fatalf("blob payload not preserved verbatim in output:\n%q", got)
	}
	if !bytes.Contains(got, []byte("M 100644 :1 bin.dat\n")) {
		t.Fatalf("filechange not preserved:\n%q", got)
	}
	if !bytes.Contains(got, []byte("data 6\nhello\n")) {
		t.Fatalf("commit message not preserved:\n%q", got)
	}
	if !bytes.Contains(got, []byte("done\n")) {
		t.Fatalf("done marker not preserved:\n%q", got)
	}
	if want := []string{"refs/heads/main"}; !equalStrings(p.ExportedRefs(), want) {
		t.Fatalf("ExportedRefs = %v want %v", p.ExportedRefs(), want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFastExportRoundTrip is the parity test: export a real repo, pipe it
// through the parser, re-import into a fresh repo, and assert identical
// commit count and tree hashes.
func TestFastExportRoundTrip(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}

	src := t.TempDir()
	runGit(t, git, src, "-c", "init.defaultBranch=main", "init", "-q")
	runGit(t, git, src, "config", "user.name", "Test")
	runGit(t, git, src, "config", "user.email", "test@example.com")
	runGit(t, git, src, "config", "commit.gpgsign", "false")

	// Commit 1: a normal file, a binary file with NUL bytes, a spaced path,
	// and a non-ASCII (quoting-requiring) path.
	writeFile(t, src, "normal.txt", []byte("hello world\n"))
	writeFile(t, src, "binary.dat", []byte{0x00, 0x01, 0x02, '\n', 0xff, 0x00, 'x'})
	writeFile(t, src, "my file.txt", []byte("spaced\n"))
	writeFile(t, src, "caf\xc3\xa9.txt", []byte("unicode name\n"))
	runGit(t, git, src, "add", "-A")
	runGit(t, git, src, "commit", "-q", "-m", "initial commit\n\nwith body")

	// Commit 2: modify + add a subdir file.
	writeFile(t, src, "normal.txt", []byte("hello again\n"))
	writeFile(t, src, filepath.Join("sub", "nested.txt"), []byte("nested\n"))
	runGit(t, git, src, "add", "-A")
	runGit(t, git, src, "commit", "-q", "-m", "second commit")

	// An annotated tag.
	runGit(t, git, src, "tag", "-a", "v1.0", "-m", "release one")

	exportArgs := []string{
		"fast-export", "--show-original-ids", "--signed-tags=strip",
		"--tag-of-filtered-object=rewrite", "--fake-missing-tagger",
		"--use-done-feature", "--all",
	}
	stream := runGit(t, git, src, exportArgs...)
	if len(stream) == 0 {
		t.Fatal("empty fast-export stream")
	}

	// Pipe through the codec with no filtering.
	p := NewFastExportParser()
	var rewritten bytes.Buffer
	if err := p.Run(bytes.NewReader(stream), &rewritten, Callbacks{}); err != nil {
		t.Fatalf("parser Run: %v", err)
	}

	// Re-import into a fresh repo.
	dst := t.TempDir()
	runGit(t, git, dst, "-c", "init.defaultBranch=main", "init", "-q")
	importCmd := exec.Command(git, "fast-import", "--force", "--quiet")
	importCmd.Dir = dst
	importCmd.Stdin = bytes.NewReader(rewritten.Bytes())
	if out, err := importCmd.CombinedOutput(); err != nil {
		t.Fatalf("fast-import failed: %v\n%s", err, out)
	}

	// Compare commit counts.
	srcCount := strings.TrimSpace(string(runGit(t, git, src, "rev-list", "--count", "--all")))
	dstCount := strings.TrimSpace(string(runGit(t, git, dst, "rev-list", "--count", "--all")))
	if srcCount != dstCount {
		t.Fatalf("commit count mismatch: src=%s dst=%s", srcCount, dstCount)
	}

	// Compare the multiset of tree hashes (content-addressed; identical content
	// yields identical tree SHAs regardless of commit metadata differences).
	srcTrees := treeHashes(t, git, src)
	dstTrees := treeHashes(t, git, dst)
	if !equalStrings(srcTrees, dstTrees) {
		t.Fatalf("tree hash mismatch:\n src=%v\n dst=%v", srcTrees, dstTrees)
	}

	// The main branch head tree must match exactly.
	srcHead := strings.TrimSpace(string(runGit(t, git, src, "rev-parse", "HEAD^{tree}")))
	dstHead := strings.TrimSpace(string(runGit(t, git, dst, "rev-parse", "main^{tree}")))
	if srcHead != dstHead {
		t.Fatalf("HEAD tree mismatch: src=%s dst=%s", srcHead, dstHead)
	}
}

func treeHashes(t *testing.T, git, dir string) []string {
	t.Helper()
	out := runGit(t, git, dir, "log", "--all", "--format=%T")
	lines := strings.Fields(strings.TrimSpace(string(out)))
	sort.Strings(lines)
	return lines
}

func runGit(t *testing.T, git, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("git %v failed: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatalf("git %v failed: %v", args, err)
	}
	return out
}

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
