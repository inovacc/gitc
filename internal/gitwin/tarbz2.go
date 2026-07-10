package gitwin

import (
	"archive/tar"
	"compress/bzip2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarBz2 extracts a .tar.bz2 archive into destDir using only the standard
// library (bzip2 + tar) — no external tool and no executing a downloaded
// installer. Entries are guarded against path traversal, and hard/symlinks are
// dereferenced to real file copies (Windows can't reliably create links, and
// git-for-windows tarballs link e.g. sh.exe to bash.exe).
func ExtractTarBz2(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	tr := tar.NewReader(bzip2.NewReader(f))
	cleanDest := filepath.Clean(destDir)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		target, err := safeJoin(cleanDest, hdr.Name)
		if err != nil {
			return err
		}

		if err := extractEntry(tr, hdr, cleanDest, target); err != nil {
			return err
		}
	}

	return nil
}

// safeJoin joins name onto dest, rejecting a path that would escape dest.
func safeJoin(dest, name string) (string, error) {
	target := filepath.Join(dest, name)
	if target != dest && !strings.HasPrefix(target, dest+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe path in archive: %q", name)
	}

	return target, nil
}

// extractEntry writes one tar entry, dereferencing links to real copies.
func extractEntry(tr *tar.Reader, hdr *tar.Header, dest, target string) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, 0o755)
	case tar.TypeReg:
		return writeRegular(tr, target, hdr.FileInfo().Mode())
	case tar.TypeLink, tar.TypeSymlink:
		// Dereference to a copy of the already-extracted referenced file.
		linkSrc, err := safeJoin(dest, hdr.Linkname)
		if err != nil {
			return err
		}

		if err := copyFile(linkSrc, target); err != nil {
			return nil //nolint:nilerr // best-effort; a missing link target is non-fatal
		}

		return nil
	default:
		return nil // devices/fifos etc. — not present in the git tarball
	}
}

// writeRegular streams a regular file entry to target.
func writeRegular(tr *tar.Reader, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode|0o200)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // release asset, bounded by disk
		_ = out.Close()
		return err
	}

	return out.Close()
}

// copyFile copies src to dst (used to materialize links as real files).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}

	return out.Close()
}
