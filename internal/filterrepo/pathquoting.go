package filterrepo

import "bytes"

// escapeTable maps every byte value to the byte sequence fast-import uses to
// represent it inside a C-style quoted path. Bytes 0x00-0x7e map to themselves,
// bytes 0x7f-0xff map to a three-digit octal escape (\NNN), and the handful of
// bytes with a named C escape (\a \b \f \n \r \t \v \" \\) are overridden below.
var escapeTable [256][]byte

// namedEscape maps the escape letter used after a backslash to the byte it
// represents, for the recognised C-style single-character escapes.
var namedEscape = map[byte]byte{
	'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n',
	'r': '\r', 't': '\t', 'v': '\v', '"': '"', '\\': '\\',
}

func init() {
	for i := 0; i < 256; i++ {
		if i < 0x7f {
			escapeTable[i] = []byte{byte(i)}
		} else {
			escapeTable[i] = []byte{'\\',
				'0' + byte((i>>6)&7),
				'0' + byte((i>>3)&7),
				'0' + byte(i&7),
			}
		}
	}

	for letter, val := range namedEscape {
		escapeTable[val] = []byte{'\\', letter}
	}
}

func isOctal(b byte) bool { return b >= '0' && b <= '7' }

// PathQuoting reproduces the C-style path quoting that git fast-export uses when
// a path contains bytes that require escaping. A quoted path is emitted starting
// with a double quote; all other paths are emitted verbatim.
type PathQuoting struct{}

// Dequote converts a possibly quoted path back to its raw byte form. If the
// input does not start with a double quote it is returned unchanged.
func (PathQuoting) Dequote(quoted []byte) []byte {
	if len(quoted) == 0 || quoted[0] != '"' {
		return quoted
	}
	// Strip the surrounding quotes.
	inner := quoted
	if len(inner) >= 2 && inner[len(inner)-1] == '"' {
		inner = inner[1 : len(inner)-1]
	} else {
		inner = inner[1:]
	}

	out := make([]byte, 0, len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\\' || i+1 >= len(inner) {
			out = append(out, inner[i])
			continue
		}

		next := inner[i+1]
		if isOctal(next) && i+3 < len(inner) && isOctal(inner[i+2]) && isOctal(inner[i+3]) {
			// Three-digit octal escape \NNN.
			v := (inner[i+1]-'0')*64 + (inner[i+2]-'0')*8 + (inner[i+3] - '0')
			out = append(out, v)
			i += 3

			continue
		}

		if b, ok := namedEscape[next]; ok {
			out = append(out, b)
			i++

			continue
		}
		// Unknown escape: keep the escaped byte literally.
		out = append(out, next)
		i++
	}

	return out
}

// Enquote returns the path quoted only when quoting is actually required by
// fast-import: when the path begins with a double quote or contains a newline.
// When quoting is required every byte is escaped via the escape table.
func (PathQuoting) Enquote(path []byte) []byte {
	if len(path) == 0 {
		return path
	}

	if path[0] != '"' && bytes.IndexByte(path, '\n') < 0 {
		return path
	}

	var buf bytes.Buffer
	buf.Grow(len(path) + 2)
	buf.WriteByte('"')

	for _, b := range path {
		buf.Write(escapeTable[b])
	}

	buf.WriteByte('"')

	return buf.Bytes()
}
