package filterrepo

import "bytes"

// binaryScanLimit bounds how much of a blob is inspected for a NUL byte when
// deciding whether the blob is binary, matching git-filter-repo's 8 KiB check.
const binaryScanLimit = 8192

// ReplaceBlobText applies a ReplaceRules set to a blob's data in place,
// reproducing the substitution core of git-filter-repo's _tweak_blob. Binary
// blobs (those containing a NUL byte within the first 8 KiB) are left
// untouched. For text blobs the literal substitutions are applied in order,
// then the regex substitutions in order. It is deterministic and does no I/O.
func ReplaceBlobText(blob *Blob, rules *ReplaceRules) {
	if blob == nil || rules.Empty() {
		return
	}

	if isBinary(blob.Data) {
		return
	}

	for _, lit := range rules.Literals {
		blob.Data = bytes.ReplaceAll(blob.Data, lit.From, lit.To)
	}

	for _, rr := range rules.Regexes {
		// The replacement is treated literally; unlike Python's re.sub we do
		// not expand backreferences in replace-text replacements.
		blob.Data = rr.Re.ReplaceAllLiteral(blob.Data, rr.To)
	}
}

// isBinary reports whether data looks like binary content: a NUL byte within
// the first binaryScanLimit bytes.
func isBinary(data []byte) bool {
	limit := len(data)
	if limit > binaryScanLimit {
		limit = binaryScanLimit
	}

	return bytes.IndexByte(data[:limit], 0) >= 0
}
