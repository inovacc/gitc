// Package enrich augments audit records with a structured snapshot of the
// repository state at the moment a git command ran.
//
// The default implementation is cgo-free: it shells out to the resolved git
// backend for `status --porcelain=v2 --branch` and parses the result. This is
// deliberately dependency-light and always available. The Enricher interface
// is the extension seam — a future libgit2/git2go implementation can satisfy
// it for programmatic access without changing callers.
//
// Enrichment must never fail an invocation: every implementation degrades to
// (nil, nil) on any error.
package enrich

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
)

// Enricher produces an optional structured JSON blob describing repo state at
// cwd. A nil result (with nil error) means "no enrichment available".
type Enricher interface {
	Enrich(ctx context.Context, cwd string) (json.RawMessage, error)
}

// Noop returns an enricher that always yields nil enrichment.
func Noop() Enricher { return noop{} }

type noop struct{}

func (noop) Enrich(context.Context, string) (json.RawMessage, error) { return nil, nil }

// NewExec returns an enricher that captures repo state by running git at
// gitPath. If gitPath is empty it falls back to a no-op.
func NewExec(gitPath string) Enricher {
	if gitPath == "" {
		return noop{}
	}
	return &execEnricher{gitPath: gitPath}
}

type execEnricher struct{ gitPath string }

// Status is the structured snapshot recorded per invocation.
type Status struct {
	Branch    string `json:"branch,omitempty"`
	OID       string `json:"oid,omitempty"`
	Ahead     int    `json:"ahead"`
	Behind    int    `json:"behind"`
	Staged    int    `json:"staged"`
	Unstaged  int    `json:"unstaged"`
	Untracked int    `json:"untracked"`
	Conflicts int    `json:"conflicts"`
}

func (e *execEnricher) Enrich(ctx context.Context, cwd string) (json.RawMessage, error) {
	args := []string{"status", "--porcelain=v2", "--branch"}
	cmd := exec.CommandContext(ctx, e.gitPath, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.Output()
	if err != nil {
		// Not a git repo, git unavailable, etc. — degrade silently.
		return nil, nil //nolint:nilerr // enrichment must never surface errors
	}
	st := parseStatus(string(out))
	blob, err := json.Marshal(st)
	if err != nil {
		return nil, nil //nolint:nilerr
	}
	return blob, nil
}

// parseStatus parses `git status --porcelain=v2 --branch` output.
func parseStatus(out string) Status {
	var st Status
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# branch.head "):
			st.Branch = strings.TrimPrefix(line, "# branch.head ")
		case strings.HasPrefix(line, "# branch.oid "):
			st.OID = strings.TrimPrefix(line, "# branch.oid ")
		case strings.HasPrefix(line, "# branch.ab "):
			st.Ahead, st.Behind = parseAheadBehind(strings.TrimPrefix(line, "# branch.ab "))
		case strings.HasPrefix(line, "1 "), strings.HasPrefix(line, "2 "):
			// Ordinary/renamed change: "1 <XY> ..." — X=staged, Y=unstaged.
			fields := strings.Fields(line)
			if len(fields) >= 2 && len(fields[1]) == 2 {
				if fields[1][0] != '.' {
					st.Staged++
				}
				if fields[1][1] != '.' {
					st.Unstaged++
				}
			}
		case strings.HasPrefix(line, "u "):
			st.Conflicts++
		case strings.HasPrefix(line, "? "):
			st.Untracked++
		}
	}
	return st
}

// parseAheadBehind parses "+A -B" into (A, B).
func parseAheadBehind(s string) (ahead, behind int) {
	for _, tok := range strings.Fields(s) {
		if len(tok) < 2 {
			continue
		}
		n, err := strconv.Atoi(tok[1:])
		if err != nil {
			continue
		}
		switch tok[0] {
		case '+':
			ahead = n
		case '-':
			behind = n
		}
	}
	return ahead, behind
}
