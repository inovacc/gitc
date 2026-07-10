// Package scan wraps the gitleaks detection engine to provide detection-only
// secret scanning for gitc. It never mutates anything it scans.
//
// The detector is built from gitleaks' embedded default ruleset, so the secret
// patterns stay current with the gitleaks dependency (see ADR 0002).
package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// maxFileSize bounds how large a file we will read into memory to scan. Files
// larger than this are skipped (secrets in huge binaries are out of scope and
// scanning them wastes memory).
const maxFileSize = 10 << 20 // 10 MiB

// skipDirs are directory names skipped by default: VCS metadata and large
// vendored/dependency trees, where findings are third-party noise rather than
// the repository's own leaked secrets.
var skipDirs = map[string]bool{
	".git":         true,
	".svn":         true,
	".hg":          true,
	"node_modules": true,
	"vendor":       true,
	"third_party":  true,
}

// Scanner runs gitleaks secret detection over strings and directory trees. It
// is safe to reuse across many scans; construct it once with New.
type Scanner struct {
	detector *detect.Detector
}

// Skip records a path that could not be scanned because of a permission or I/O
// error (not an intentional policy skip like empty/oversized/binary), so a
// "clean" result is never silently incomplete.
type Skip struct {
	Path   string
	Reason string
}

// Result is the outcome of ScanDir: the findings plus any paths that could not
// be read. A caller that treats a clean scan as a gate should also inspect
// Skipped (see the --strict handling in `git scan`).
type Result struct {
	Findings []report.Finding
	Skipped  []Skip
}

// New builds a Scanner from the gitleaks embedded default configuration.
func New() (*Scanner, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("scan: building detector: %w", err)
	}

	return &Scanner{detector: d}, nil
}

// Mask returns a display-safe rendering of a detected secret: the first few
// characters followed by a fixed run of asterisks, so a finding can be reported
// (in `git scan`, the secret gate, or the audit view) without printing the full
// secret.
func Mask(secret string) string {
	if secret == "" {
		return "<redacted>"
	}

	const keep = 4
	if len(secret) <= keep {
		return strings.Repeat("*", len(secret))
	}

	return secret[:keep] + strings.Repeat("*", 6)
}

// ScanString scans a single string and returns any secret findings.
func (s *Scanner) ScanString(content string) []report.Finding {
	return s.detector.DetectString(content)
}

// ScanBytes scans raw bytes attributed to filePath and returns any findings.
// filePath is recorded on each finding so callers can report a location.
func (s *Scanner) ScanBytes(filePath string, content []byte) []report.Finding {
	frag := detect.Fragment{
		Raw:      string(content),
		FilePath: filepath.ToSlash(filePath),
	}

	findings := s.detector.Detect(frag)
	for i := range findings {
		if findings[i].File == "" {
			findings[i].File = filepath.ToSlash(filePath)
		}
	}

	return findings
}

// ScanDir walks root (skipping the .git directory) and scans each regular,
// reasonably sized, non-binary file, aggregating findings with their paths.
// Files that cannot be read (permission/I/O errors) are recorded in
// Result.Skipped rather than silently dropped, so the caller can tell a clean
// scan from an incomplete one. It is detection-only and never modifies the tree.
func (s *Scanner) ScanDir(root string) (Result, error) {
	var res Result

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d == nil {
				return err // root itself is unreadable: surface as a hard error
			}

			res.Skipped = append(res.Skipped, Skip{Path: path, Reason: err.Error()})

			if d.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}

			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			res.Skipped = append(res.Skipped, Skip{Path: path, Reason: ierr.Error()})
			return nil
		}

		if info.Size() == 0 || info.Size() > maxFileSize {
			return nil // intentional policy skip, not an error
		}

		content, rerr := os.ReadFile(path)
		if rerr != nil {
			res.Skipped = append(res.Skipped, Skip{Path: path, Reason: rerr.Error()})
			return nil
		}

		if isBinary(content) {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}

		res.Findings = append(res.Findings, s.ScanBytes(rel, content)...)

		return nil
	})
	if walkErr != nil {
		return res, fmt.Errorf("scan: walking %s: %w", root, walkErr)
	}

	return res, nil
}

// isBinary reports whether content looks like a binary blob (contains a NUL in
// the first chunk), in which case textual secret detection is not meaningful.
func isBinary(content []byte) bool {
	n := min(len(content), 8000)
	return strings.IndexByte(string(content[:n]), 0) >= 0
}
