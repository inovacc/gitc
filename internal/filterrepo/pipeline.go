package filterrepo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Options configures a single history-rewriting run.
type Options struct {
	// RepoDir is the path to the repository to rewrite. Commands are executed
	// with `git -C RepoDir`.
	RepoDir string

	// GitBin is the git executable to invoke. Empty means DefaultGitBinary
	// ("git" from PATH). A host that ships its own `git` shim should set this to
	// the resolved real-git path to avoid re-entering the shim.
	GitBin string

	// Refs limits the rewrite to the given refs/rev-list arguments. Empty means
	// the whole history ("--all").
	Refs []string

	// Paths, when non-nil, filters/renames file paths in every commit. A nil
	// PathSpec leaves paths untouched.
	Paths *PathSpec

	// ReplaceText, when non-empty, applies textual substitutions to blob
	// contents. A nil or empty rule set leaves blobs untouched.
	ReplaceText *ReplaceRules

	// Prune selects how commits that become empty are handled.
	Prune PruneMode

	// Force bypasses the fresh-clone SanityCheck. It is required to rewrite any
	// repository that is not a pristine clone.
	Force bool

	// DryRun runs the export and all transforms but discards the import stream,
	// leaving the repository unchanged. Cleanup is skipped.
	DryRun bool
}

// fastExportFlags are the fixed flags git-filter-repo passes to fast-export so
// the stream carries enough information to be losslessly re-imported.
var fastExportFlags = []string{
	"fast-export",
	"--show-original-ids",
	"--reference-excluded-parents",
	"--signed-tags=strip",
	"--tag-of-filtered-object=rewrite",
	"--fake-missing-tagger",
	"--use-done-feature",
}

// Run rewrites the repository described by opts. It runs the safety check, then
// streams `git fast-export` through the codec+transform callbacks into `git
// fast-import`, and finally runs Cleanup on success. On DryRun the import stream
// is discarded and the repository is left untouched.
func Run(ctx context.Context, opts Options) error {
	gitBin := opts.GitBin
	if gitBin == "" {
		gitBin = DefaultGitBinary
	}

	layout, err := RepoLayout(gitBin, opts.RepoDir)
	if err != nil {
		return fmt.Errorf("filterrepo: resolving repository layout: %w", err)
	}

	if err := sanityCheck(gitBin, opts.RepoDir, opts.Force); err != nil {
		return err
	}

	refs := opts.Refs
	if len(refs) == 0 {
		refs = []string{"--all"}
	}

	exportArgs := append([]string{"-C", opts.RepoDir}, fastExportFlags...)
	exportArgs = append(exportArgs, refs...)
	exportCmd := exec.CommandContext(ctx, gitBin, exportArgs...)
	var exportErr bytes.Buffer
	exportCmd.Stderr = &exportErr
	exportOut, err := exportCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("filterrepo: fast-export stdout pipe: %w", err)
	}

	// Assemble the sink for the filtered stream.
	var (
		importCmd *exec.Cmd
		importIn  io.WriteCloser
		importErr bytes.Buffer
		output    io.Writer = io.Discard
	)
	if !opts.DryRun {
		importCmd = exec.CommandContext(ctx, gitBin,
			"-C", opts.RepoDir, "-c", "core.ignorecase=false",
			"fast-import", "--force", "--quiet")
		importCmd.Stderr = &importErr
		importCmd.Stdout = io.Discard
		importIn, err = importCmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("filterrepo: fast-import stdin pipe: %w", err)
		}
		output = importIn
	}

	if err := exportCmd.Start(); err != nil {
		return fmt.Errorf("filterrepo: starting fast-export: %w", err)
	}
	if importCmd != nil {
		if err := importCmd.Start(); err != nil {
			_ = exportCmd.Wait()
			return fmt.Errorf("filterrepo: starting fast-import: %w", err)
		}
	}

	parser := NewFastExportParser()
	cb, cbErrp := buildCallbacks(parser, opts)

	runErr := parser.Run(exportOut, output, cb)

	// Signal end-of-input to fast-import before waiting on it.
	if importIn != nil {
		if cerr := importIn.Close(); cerr != nil && runErr == nil {
			runErr = fmt.Errorf("filterrepo: closing fast-import stdin: %w", cerr)
		}
	}

	waitExport := exportCmd.Wait()
	var waitImport error
	if importCmd != nil {
		waitImport = importCmd.Wait()
	}

	if err := aggregateErrors(*cbErrp, runErr, waitExport, exportErr.String(),
		waitImport, importErr.String()); err != nil {
		return err
	}

	if opts.DryRun {
		return nil
	}
	if err := cleanup(gitBin, opts.RepoDir, layout.Bare); err != nil {
		return err
	}
	return nil
}

// buildCallbacks wires the ported transforms onto the parser's shared IDMap and
// a single CommitFilter. The returned pointer holds the first error raised
// inside a callback (callbacks cannot return errors directly).
func buildCallbacks(parser *FastExportParser, opts Options) (Callbacks, *error) {
	ids := parser.IDs()
	cf := NewCommitFilter(opts.Prune, ids)
	rules := opts.ReplaceText
	var cbErr error

	cb := Callbacks{}
	if !rules.Empty() {
		cb.Blob = func(b *Blob) {
			ReplaceBlobText(b, rules)
		}
	}
	cb.Commit = func(c *Commit) {
		if cbErr != nil {
			c.Skip()
			return
		}
		// Capture original emptiness BEFORE filtering: PruneAuto must not prune a
		// commit the author intentionally made empty.
		hadFileChanges := len(c.FileChanges) > 0
		if opts.Paths != nil {
			if err := FilterFiles(c, opts.Paths); err != nil {
				cbErr = fmt.Errorf("filterrepo: filtering files: %w", err)
				c.Skip()
				return
			}
		}
		cf.Tweak(c, hadFileChanges)
	}
	return cb, &cbErr
}

// aggregateErrors combines every failure surface into a single error, favouring
// the earliest/most-specific cause and attaching captured stderr for context.
func aggregateErrors(cbErr, runErr, waitExport error, exportStderr string,
	waitImport error, importStderr string) error {
	if cbErr != nil {
		return cbErr
	}
	if waitExport != nil {
		return fmt.Errorf("filterrepo: fast-export failed: %w%s", waitExport, stderrSuffix(exportStderr))
	}
	if waitImport != nil {
		return fmt.Errorf("filterrepo: fast-import failed: %w%s", waitImport, stderrSuffix(importStderr))
	}
	if runErr != nil {
		// A parser/stream error is often a downstream symptom of fast-import
		// dying; surface its stderr too when present.
		if importStderr != "" {
			return fmt.Errorf("filterrepo: stream error: %w%s", runErr, stderrSuffix(importStderr))
		}
		return fmt.Errorf("filterrepo: stream error: %w", runErr)
	}
	return nil
}

func stderrSuffix(s string) string {
	s = trimSpaceASCII(s)
	if s == "" {
		return ""
	}
	return ": " + s
}

// trimSpaceASCII trims surrounding ASCII whitespace without pulling in strings
// for a single call site.
func trimSpaceASCII(s string) string {
	start, end := 0, len(s)
	for start < end && isASCIISpace(s[start]) {
		start++
	}
	for end > start && isASCIISpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
