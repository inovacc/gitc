package filterrepo

import (
	"bytes"
	"fmt"
	"sort"
)

// FilterFiles applies a PathSpec to a commit's file changes in place,
// reproducing git-filter-repo's _filter_files. Each change's path is run
// through spec.NewName; dropped changes are removed and surviving changes are
// renamed. A deleteall pseudo-change is preserved. When renaming causes two
// paths to collide the collision is resolved where safe (a deletion yields to
// the other side; two identical modifies collapse to one) and otherwise
// reported as an error. The resulting changes are re-sorted by path so output
// is deterministic. It performs no git I/O.
func FilterFiles(commit *Commit, spec *PathSpec) error {
	// Keyed by resulting path. The empty key is reserved for deleteall.
	result := make(map[string]*FileChange, len(commit.FileChanges))

	for _, change := range commit.FileChanges {
		if change.Type == FileDeleteAll {
			result[""] = change
			continue
		}

		newName, keep := spec.NewName(change.Path)
		if !keep {
			continue
		}

		change.Path = newName
		key := string(newName)

		if existing, ok := result[key]; ok {
			switch {
			case change.Type == FileDelete:
				// A deletion of an already-present path: keep the other.
				continue
			case change.Type == FileModify && existing.Type == FileModify &&
				bytes.Equal(change.Mode, existing.Mode) && refEqual(change.Blob, existing.Blob):
				// Identical content at the same path: one copy suffices.
				continue
			case existing.Type != FileDelete:
				return fmt.Errorf("file renaming caused colliding pathnames: %s", Decode(newName))
			}
			// existing is a deletion that this change supersedes; fall through.
		}

		result[key] = change
	}

	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}

	sort.Strings(keys) // byte-lexicographic order, matching the original sort

	changes := make([]*FileChange, 0, len(keys))
	for _, k := range keys {
		changes = append(changes, result[k])
	}

	commit.FileChanges = changes

	return nil
}

// refEqual reports whether two blob references denote the same object.
func refEqual(a, b Ref) bool {
	return a.Mark == b.Mark && bytes.Equal(a.OID, b.OID)
}
