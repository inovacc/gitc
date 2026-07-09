package filterrepo

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitAvailable reports whether a real `git` is on PATH, skipping the test when
// it is not (e.g. CI images without git).
func gitAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
}

// runGitT runs git in dir, failing the test on error.
func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimRight(out.String(), "\r\n")
}

// initRepo creates a fresh repo with a deterministic identity so commits are
// reproducible, then repacks it so SanityCheck sees a fresh-clone-like store.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitT(t, dir, "init", "-q", "-b", "main")
	runGitT(t, dir, "config", "user.name", "Test")
	runGitT(t, dir, "config", "user.email", "test@example.com")
	runGitT(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func writeRepoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	runGitT(t, dir, "add", "-A")
	runGitT(t, dir, "commit", "-q", "-m", msg)
}

func TestRunRemovesPathFromAllHistory(t *testing.T) {
	gitAvailable(t)
	dir := initRepo(t)

	// Early commit introduces secret.txt and keep.txt.
	writeRepoFile(t, dir, "secret.txt", "top secret\n")
	writeRepoFile(t, dir, "keep.txt", "keep me\n")
	commitAll(t, dir, "add secret and keep")

	// Secret persists across later commits.
	writeRepoFile(t, dir, "keep.txt", "keep me v2\n")
	commitAll(t, dir, "update keep")

	writeRepoFile(t, dir, "other.txt", "unrelated\n")
	commitAll(t, dir, "add other")

	// Pack the repo so it looks fresh (though we pass Force anyway).
	runGitT(t, dir, "gc", "--quiet")

	spec := NewPathSpec()
	if err := spec.AddMatch([]byte("secret.txt")); err != nil {
		t.Fatalf("AddMatch: %v", err)
	}
	spec.Invert = true // remove matching path

	err := Run(context.Background(), Options{
		RepoDir: dir,
		Paths:   spec,
		Prune:   PruneAuto,
		Force:   true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// secret.txt must be gone from every ref's history.
	if out := runGitT(t, dir, "log", "--all", "--oneline", "--", "secret.txt"); out != "" {
		t.Fatalf("secret.txt still present in history:\n%s", out)
	}

	// keep.txt history is intact (two touching commits).
	keepLog := runGitT(t, dir, "log", "--all", "--oneline", "--", "keep.txt")
	if lines := nonEmptyLines(keepLog); len(lines) != 2 {
		t.Fatalf("keep.txt history changed, want 2 commits, got %d:\n%s", len(lines), keepLog)
	}

	// HEAD tree no longer contains secret.txt.
	tree := runGitT(t, dir, "ls-tree", "-r", "--name-only", "HEAD")
	for _, name := range nonEmptyLines(tree) {
		if name == "secret.txt" {
			t.Fatalf("secret.txt still in HEAD tree")
		}
	}

	// Repo is still valid.
	runGitT(t, dir, "fsck", "--full")
}

func TestRunReplaceTextRedactsSecret(t *testing.T) {
	gitAvailable(t)
	dir := initRepo(t)

	const secret = "hunter2password"
	writeRepoFile(t, dir, "config.txt", "api_key = "+secret+"\n")
	commitAll(t, dir, "add config with secret")

	// Secret survives into a later commit's blob too.
	writeRepoFile(t, dir, "config.txt", "api_key = "+secret+"\nextra = 1\n")
	commitAll(t, dir, "extend config")

	runGitT(t, dir, "gc", "--quiet")

	rules := &ReplaceRules{
		Literals: []LiteralReplace{{From: []byte(secret), To: []byte("REDACTED")}},
	}

	err := Run(context.Background(), Options{
		RepoDir:     dir,
		ReplaceText: rules,
		Prune:       PruneAuto,
		Force:       true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The secret must not appear in any historical blob.
	revs := nonEmptyLines(runGitT(t, dir, "rev-list", "--all"))
	grepArgs := append([]string{"grep", "-I", secret}, revs...)
	cmd := exec.Command("git", append([]string{"-C", dir}, grepArgs...)...)
	out, _ := cmd.CombinedOutput()
	if len(bytes.TrimSpace(out)) != 0 {
		t.Fatalf("secret still found in history:\n%s", out)
	}

	// The replacement is present in the current file.
	head := runGitT(t, dir, "show", "HEAD:config.txt")
	if !strings.Contains(head, "REDACTED") {
		t.Fatalf("replacement not found in HEAD config.txt:\n%s", head)
	}
	if strings.Contains(head, secret) {
		t.Fatalf("secret still present in HEAD config.txt")
	}

	runGitT(t, dir, "fsck", "--full")
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
