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

// Scanner runs gitleaks secret detection over strings and directory trees. It
// is safe to reuse across many scans; construct it once with New.
type Scanner struct {
	detector *detect.Detector
}

// New builds a Scanner from the gitleaks embedded default configuration.
func New() (*Scanner, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("scan: building detector: %w", err)
	}

	return &Scanner{detector: d}, nil
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
// It is detection-only and never modifies the tree.
func (s *Scanner) ScanDir(root string) ([]report.Finding, error) {
	var findings []report.Finding

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}

			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return nil // skip unreadable entry, keep going
		}

		if info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}

		content, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // unreadable file: skip, don't abort the whole scan
		}

		if isBinary(content) {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}

		findings = append(findings, s.ScanBytes(rel, content)...)

		return nil
	})
	if walkErr != nil {
		return findings, fmt.Errorf("scan: walking %s: %w", root, walkErr)
	}

	return findings, nil
}

// isBinary reports whether content looks like a binary blob (contains a NUL in
// the first chunk), in which case textual secret detection is not meaningful.
func isBinary(content []byte) bool {
	n := min(len(content), 8000)
	return strings.IndexByte(string(content[:n]), 0) >= 0
}
