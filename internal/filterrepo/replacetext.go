package filterrepo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
)

// DefaultReplacement is the replacement used for a --replace-text rule that
// omits an explicit "==>REPLACEMENT".
var DefaultReplacement = []byte("***REMOVED***")

// LiteralReplace is a literal from->to substitution.
type LiteralReplace struct {
	From []byte
	To   []byte
}

// RegexReplace is a regular-expression substitution.
type RegexReplace struct {
	Re *regexp.Regexp
	To []byte
}

// ReplaceRules is the parsed content of a --replace-text file: an ordered list
// of literal substitutions followed by an ordered list of regex substitutions.
type ReplaceRules struct {
	Literals []LiteralReplace
	Regexes  []RegexReplace
}

// Empty reports whether the rule set contains no substitutions.
func (r *ReplaceRules) Empty() bool {
	return r == nil || (len(r.Literals) == 0 && len(r.Regexes) == 0)
}

// ParseReplaceText reads a --replace-text file and returns the parsed rules.
func ParseReplaceText(filename string) (*ReplaceRules, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseReplaceRules(bufio.NewReader(f))
}

// ParseReplaceRules parses --replace-text directives from r, one per line.
//
// Each line is stripped of a trailing CR/LF. An optional "==>REPLACEMENT"
// suffix (split at the last "==>") sets the replacement, defaulting to
// DefaultReplacement. A "regex:" prefix compiles the remainder as an RE2
// pattern; "glob:" translates the remainder through GlobToRegex; "literal:"
// (or no prefix) is a literal byte match. Empty literal lines are skipped.
func ParseReplaceRules(r *bufio.Reader) (*ReplaceRules, error) {
	rules := &ReplaceRules{}
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			if perr := rules.addLine(line); perr != nil {
				return nil, perr
			}
		}
		if readErr != nil {
			return rules, nil
		}
	}
}

func (rules *ReplaceRules) addLine(line []byte) error {
	line = bytes.TrimRight(line, "\r\n")

	replacement := DefaultReplacement
	if idx := bytes.LastIndex(line, []byte("==>")); idx >= 0 {
		replacement = cloneBytes(line[idx+3:])
		line = line[:idx]
	}

	var pattern []byte
	switch {
	case bytes.HasPrefix(line, []byte("regex:")):
		pattern = line[6:]
	case bytes.HasPrefix(line, []byte("glob:")):
		pattern = GlobToRegex(line[5:])
	}
	if pattern != nil {
		re, err := regexp.Compile(string(pattern))
		if err != nil {
			return fmt.Errorf("invalid replace-text regex %q (RE2 does not support backreferences or lookaround): %w", Decode(pattern), err)
		}
		rules.Regexes = append(rules.Regexes, RegexReplace{Re: re, To: cloneBytes(replacement)})
		return nil
	}

	if bytes.HasPrefix(line, []byte("literal:")) {
		line = line[8:]
	}
	if len(line) == 0 {
		return nil
	}
	rules.Literals = append(rules.Literals, LiteralReplace{From: cloneBytes(line), To: cloneBytes(replacement)})
	return nil
}
