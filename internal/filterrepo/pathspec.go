package filterrepo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
)

// pathMod distinguishes selection rules ("filter") from renaming rules
// ("rename").
type pathMod uint8

const (
	modFilter pathMod = iota
	modRename
)

// pathKind is the matching style of a rule.
type pathKind uint8

const (
	kindMatch pathKind = iota // exact path / leading-directory match
	kindGlob                  // shell glob (fnmatch), compiled to an anchored regex
	kindRegex                 // arbitrary regular expression (unanchored search)
)

// PathRule is a single path selection or renaming directive. Rules are opaque;
// build them through the PathSpec Add* methods.
type PathRule struct {
	mod   pathMod
	kind  pathKind
	match []byte         // raw expression for kindMatch (filter or rename source)
	repl  []byte         // rename replacement (kindMatch/kindRegex renames)
	re    *regexp.Regexp // compiled matcher for kindGlob / kindRegex
}

// PathSpec is an ordered set of path filtering and renaming rules. It models
// the union of git-filter-repo's --path/--path-glob/--path-regex/--path-rename
// options plus --invert-paths. A PathSpec is pure: NewName performs no I/O.
type PathSpec struct {
	rules     []PathRule
	hasFilter bool // whether any filter (selection) rule was added

	// Invert corresponds to --invert-paths: when true the selection is
	// inverted so that files matching a filter rule are dropped instead of
	// kept. It only has an effect when at least one filter rule exists.
	Invert bool
}

// NewPathSpec returns an empty PathSpec that keeps every path.
func NewPathSpec() *PathSpec { return &PathSpec{} }

// AddMatch adds an exact path (file or leading directory) selection rule,
// corresponding to --path / --path-match.
func (s *PathSpec) AddMatch(path []byte) error {
	if err := validatePath(path); err != nil {
		return err
	}
	s.rules = append(s.rules, PathRule{mod: modFilter, kind: kindMatch, match: cloneBytes(path)})
	s.hasFilter = true
	return nil
}

// AddGlob adds a glob selection rule, corresponding to --path-glob. As in the
// original, a glob that does not already end in '*' also matches everything
// beneath it: an extra rule glob+"/*" (or glob+"*" when it ends in '/') is
// appended so that a directory glob selects its contents too.
func (s *PathSpec) AddGlob(glob []byte) error {
	if err := validatePath(glob); err != nil {
		return err
	}
	re, err := compileGlobRule(glob)
	if err != nil {
		return err
	}
	s.rules = append(s.rules, PathRule{mod: modFilter, kind: kindGlob, match: cloneBytes(glob), re: re})
	s.hasFilter = true
	if !bytes.HasSuffix(glob, []byte("*")) {
		ext := []byte("/*")
		if bytes.HasSuffix(glob, []byte("/")) {
			ext = []byte("*")
		}
		extended := append(cloneBytes(glob), ext...)
		re2, err := compileGlobRule(extended)
		if err != nil {
			return err
		}
		s.rules = append(s.rules, PathRule{mod: modFilter, kind: kindGlob, match: extended, re: re2})
	}
	return nil
}

// AddRegex adds a regular-expression selection rule, corresponding to
// --path-regex. The expression is searched (unanchored) against each path.
func (s *PathSpec) AddRegex(pattern []byte) error {
	if err := validatePath(pattern); err != nil {
		return err
	}
	re, err := compilePathRegex(pattern)
	if err != nil {
		return err
	}
	s.rules = append(s.rules, PathRule{mod: modFilter, kind: kindRegex, re: re})
	s.hasFilter = true
	return nil
}

// AddRename adds an exact-match renaming rule, corresponding to --path-rename.
// A path whose name matches old (as a file or leading directory) has its first
// occurrence of old rewritten to new.
func (s *PathSpec) AddRename(old, new []byte) error {
	if err := validateRename(old, new); err != nil {
		return err
	}
	s.rules = append(s.rules, PathRule{mod: modRename, kind: kindMatch, match: cloneBytes(old), repl: cloneBytes(new)})
	return nil
}

// AddRenameRegex adds a regular-expression renaming rule. Every match of
// pattern in a path is replaced by repl. Python-style numeric backreferences
// (\1) in repl are accepted and translated to Go's ${1} form.
func (s *PathSpec) AddRenameRegex(pattern, repl []byte) error {
	re, err := compilePathRegex(pattern)
	if err != nil {
		return err
	}
	s.rules = append(s.rules, PathRule{mod: modRename, kind: kindRegex, re: re, repl: translateBackrefs(repl)})
	return nil
}

// AddFromFile parses a paths file (one directive per line, as accepted by
// --paths-from-file) and appends the resulting rules. Blank lines and lines
// beginning with '#' are ignored. A line may be prefixed with "regex:",
// "glob:", or "literal:" (the default) and may contain "==>" to specify a
// rename.
func (s *PathSpec) AddFromFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.addFromReaderLines(bufio.NewReader(f))
}

// addFromReaderLines is the byte-oriented core of AddFromFile, split out so it
// can be exercised directly from tests without a temporary file.
func (s *PathSpec) addFromReaderLines(r *bufio.Reader) error {
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			if perr := s.addLine(line); perr != nil {
				return perr
			}
		}
		if readErr != nil {
			return nil
		}
	}
}

func (s *PathSpec) addLine(line []byte) error {
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 || line[0] == '#' {
		return nil
	}

	var repl []byte
	hasRepl := false
	if idx := bytes.LastIndex(line, []byte("==>")); idx >= 0 {
		repl = line[idx+3:]
		line = line[:idx]
		hasRepl = true
	}

	switch {
	case bytes.HasPrefix(line, []byte("regex:")):
		pat := line[6:]
		if hasRepl {
			return s.AddRenameRegex(pat, repl)
		}
		return s.AddRegex(pat)
	case bytes.HasPrefix(line, []byte("glob:")):
		if hasRepl {
			return fmt.Errorf("'glob:' and '==>' are incompatible (renaming globs makes no sense)")
		}
		return s.AddGlob(line[5:])
	default:
		match := line
		if bytes.HasPrefix(line, []byte("literal:")) {
			match = line[8:]
		}
		if hasRepl {
			return s.AddRename(match, repl)
		}
		if len(match) == 0 {
			return nil
		}
		return s.AddMatch(match)
	}
}

// NewName applies every rule to path in order and reports the resulting name
// together with whether the path should be kept. It reproduces
// git-filter-repo's newname(): filter rules set a "wanted" flag, rename rules
// rewrite the running name, and the path is kept when wanted equals the
// effective inclusive flag. When kept is false the returned slice is nil.
func (s *PathSpec) NewName(path []byte) (newPath []byte, keep bool) {
	wanted := false
	name := path
	for _, r := range s.rules {
		switch r.mod {
		case modFilter:
			if wanted {
				continue
			}
			switch r.kind {
			case kindMatch:
				if filenameMatches(r.match, name) {
					wanted = true
				}
			case kindGlob, kindRegex:
				if r.re.Match(name) {
					wanted = true
				}
			}
		case modRename:
			switch r.kind {
			case kindMatch:
				if filenameMatches(r.match, name) {
					name = replaceFirst(name, r.match, r.repl)
				}
			case kindRegex:
				name = r.re.ReplaceAll(name, r.repl)
			}
		}
	}
	if wanted == s.inclusive() {
		return name, true
	}
	return nil, false
}

// inclusive reports the effective selection polarity. Selection is inclusive
// only when the caller did not invert and at least one filter rule exists;
// otherwise every non-inverted path is kept (matching the original's handling
// of "no filter paths" and rename-only specs).
func (s *PathSpec) inclusive() bool { return !s.Invert && s.hasFilter }

// filenameMatches reports whether expr matches pathname or a leading directory
// of it, tolerating a missing trailing slash on a directory expression.
func filenameMatches(expr, pathname []byte) bool {
	if len(expr) == 0 {
		return true
	}
	n := len(expr)
	if !bytes.HasPrefix(pathname, expr) {
		return false
	}
	return expr[n-1] == '/' || len(pathname) == n || pathname[n] == '/'
}

// replaceFirst returns s with the first occurrence of old replaced by repl.
func replaceFirst(s, old, repl []byte) []byte {
	i := bytes.Index(s, old)
	if i < 0 {
		return s
	}
	out := make([]byte, 0, len(s)-len(old)+len(repl))
	out = append(out, s[:i]...)
	out = append(out, repl...)
	out = append(out, s[i+len(old):]...)
	return out
}

// compileGlobRule compiles a shell glob to an anchored RE2 matcher.
func compileGlobRule(glob []byte) (*regexp.Regexp, error) {
	re, err := regexp.Compile(string(GlobToRegex(glob)))
	if err != nil {
		return nil, fmt.Errorf("invalid path glob %q: %w", Decode(glob), err)
	}
	return re, nil
}

// compilePathRegex compiles a user-supplied regular expression, wrapping RE2
// rejections (e.g. backreferences or lookaround) with a clear message.
func compilePathRegex(pattern []byte) (*regexp.Regexp, error) {
	re, err := regexp.Compile(string(pattern))
	if err != nil {
		return nil, fmt.Errorf("invalid path regex %q (RE2 does not support backreferences or lookaround): %w", Decode(pattern), err)
	}
	return re, nil
}

// validatePath rejects absolute paths and '.'/'..' components.
func validatePath(p []byte) error {
	if bytes.HasPrefix(p, []byte("/")) {
		return fmt.Errorf("pathnames cannot begin with a '/': %q", Decode(p))
	}
	for _, comp := range bytes.Split(p, []byte("/")) {
		if bytes.Equal(comp, []byte(".")) || bytes.Equal(comp, []byte("..")) {
			return fmt.Errorf("invalid path component %q found in %q", Decode(comp), Decode(p))
		}
	}
	return nil
}

// validateRename validates both sides of a --path-rename directive.
func validateRename(old, new []byte) error {
	if err := validatePath(old); err != nil {
		return err
	}
	if err := validatePath(new); err != nil {
		return err
	}
	if len(old) > 0 && len(new) > 0 &&
		bytes.HasSuffix(old, []byte("/")) != bytes.HasSuffix(new, []byte("/")) {
		return fmt.Errorf("when renaming, if OLD_NAME and NEW_NAME are both non-empty and either ends with a slash then both must")
	}
	return nil
}

// backrefRe matches Python-style numeric backreferences (\1 .. \99) that are
// valid inside a re.sub replacement string.
var backrefRe = regexp.MustCompile(`\\([0-9]{1,2})`)

// translateBackrefs rewrites Python-style \N backreferences in a regex
// replacement to Go's ${N} syntax and escapes literal '$' so it is not
// interpreted by regexp.ReplaceAll.
func translateBackrefs(repl []byte) []byte {
	escaped := bytes.ReplaceAll(repl, []byte("$"), []byte("$$"))
	return backrefRe.ReplaceAll(escaped, []byte("${$1}"))
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
