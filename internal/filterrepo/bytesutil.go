// Package filterrepo implements a clean-room Go port of the git-filter-repo
// fast-export/fast-import stream codec: the byte-exact model of a fast-import
// stream (blobs, commits, resets, tags, ...) plus a single-pass streaming
// parser that round-trips a `git fast-export` stream back into a stream that
// `git fast-import` accepts.
//
// The codec operates purely on raw bytes. No text/newline translation is
// performed, which is essential for byte-exact round-tripping on platforms
// (such as Windows) whose text mode would otherwise rewrite line endings.
package filterrepo

import (
	"strings"
	"unicode/utf8"
)

// Decode renders a raw byte string as a Go string for human-readable error
// messages. Invalid UTF-8 bytes are preserved via a backslash-hex escape so
// the operation is lossless and never panics.
func Decode(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			// Emit the raw byte as \xNN, matching a backslashreplace policy.
			const hex = "0123456789abcdef"
			sb.WriteString("\\x")
			sb.WriteByte(hex[b[i]>>4])
			sb.WriteByte(hex[b[i]&0xf])
			i++
			continue
		}
		sb.WriteRune(r)
		i += size
	}
	return sb.String()
}

// GlobToRegex translates a shell glob pattern (operating on raw bytes) into an
// anchored RE2 source. The translation follows fnmatch semantics: '*' matches
// any run of characters (including path separators and newlines), '?' matches a
// single character, and '[...]' / '[!...]' introduce a character class. All
// other bytes are matched literally. The returned pattern is fully anchored and
// uses the dot-all flag so '*'/'?' can span newlines.
func GlobToRegex(glob []byte) []byte {
	var sb strings.Builder
	sb.WriteString(`(?s)\A`)
	i, n := 0, len(glob)
	for i < n {
		c := glob[i]
		i++
		switch c {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteByte('.')
		case '[':
			j := i
			if j < n && (glob[j] == '!' || glob[j] == '^') {
				j++
			}
			if j < n && glob[j] == ']' {
				j++
			}
			for j < n && glob[j] != ']' {
				j++
			}
			if j >= n {
				// No closing bracket: treat '[' as a literal.
				sb.WriteString(`\[`)
				continue
			}
			stuff := glob[i:j]
			i = j + 1
			sb.WriteByte('[')
			switch {
			case len(stuff) > 0 && stuff[0] == '!':
				sb.WriteByte('^')
				stuff = stuff[1:]
			case len(stuff) > 0 && stuff[0] == '^':
				sb.WriteByte('\\')
			}
			for _, b := range stuff {
				if b == '\\' {
					sb.WriteString(`\\`)
				} else {
					sb.WriteByte(b)
				}
			}
			sb.WriteByte(']')
		default:
			sb.WriteString(escapeRegexByte(c))
		}
	}
	sb.WriteString(`\z`)
	return []byte(sb.String())
}

// escapeRegexByte returns a regex source fragment matching exactly one literal
// byte c, escaping any RE2 metacharacter.
func escapeRegexByte(c byte) string {
	switch c {
	case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
		return "\\" + string(c)
	}
	return string(c)
}
