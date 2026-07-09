package filterrepo

import "testing"

// modifyChange builds a trivial FileModify change for the given path/mark.
func modifyChange(path string, blobMark int) *FileChange {
	return &FileChange{
		Type: FileModify,
		Mode: []byte("100644"),
		Blob: Ref{Mark: blobMark},
		Path: []byte(path),
	}
}

func markRef(m int) Ref { return Ref{Mark: m} }

// TestPruneEmptySingleCommit exercises the core auto/always/never decision for a
// single non-merge commit, independent of parent remapping.
func TestPruneEmptySingleCommit(t *testing.T) {
	tests := []struct {
		name           string
		mode           PruneMode
		hadFileChanges bool
		fileChanges    []*FileChange
		parent         Ref // zero == root
		wantKeep       bool
	}{
		{
			name:           "auto newly-empty non-root pruned",
			mode:           PruneAuto,
			hadFileChanges: true,
			fileChanges:    nil,
			parent:         markRef(1),
			wantKeep:       false,
		},
		{
			name:           "auto originally-empty non-root kept",
			mode:           PruneAuto,
			hadFileChanges: false,
			fileChanges:    nil,
			parent:         markRef(1),
			wantKeep:       true,
		},
		{
			name:           "auto non-empty kept",
			mode:           PruneAuto,
			hadFileChanges: true,
			fileChanges:    []*FileChange{modifyChange("a", 2)},
			parent:         markRef(1),
			wantKeep:       true,
		},
		{
			name:           "auto originally-empty root kept",
			mode:           PruneAuto,
			hadFileChanges: false,
			fileChanges:    nil,
			wantKeep:       true,
		},
		{
			name:           "always originally-empty pruned",
			mode:           PruneAlways,
			hadFileChanges: false,
			fileChanges:    nil,
			parent:         markRef(1),
			wantKeep:       false,
		},
		{
			name:           "always non-empty kept",
			mode:           PruneAlways,
			hadFileChanges: true,
			fileChanges:    []*FileChange{modifyChange("a", 2)},
			parent:         markRef(1),
			wantKeep:       true,
		},
		{
			name:           "never newly-empty kept",
			mode:           PruneNever,
			hadFileChanges: true,
			fileChanges:    nil,
			parent:         markRef(1),
			wantKeep:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewCommitFilter(tt.mode, NewIDMap())
			c := &Commit{Mark: 10, Branch: []byte("refs/heads/main"),
				From: tt.parent, FileChanges: tt.fileChanges}

			keep := cf.Tweak(c, tt.hadFileChanges)
			if keep != tt.wantKeep {
				t.Fatalf("keep = %v, want %v", keep, tt.wantKeep)
			}
		})
	}
}

// TestLinearParentRemap prunes two consecutive commits and asserts the surviving
// child re-points to the original grandparent.
func TestLinearParentRemap(t *testing.T) {
	cf := NewCommitFilter(PruneAuto, NewIDMap())

	// A (root, has content) -> B (became empty) -> C (became empty) -> D (content)
	a := &Commit{Mark: 1, Branch: []byte("refs/heads/main"),
		FileChanges: []*FileChange{modifyChange("a", 100)}}
	if keep := cf.Tweak(a, true); !keep {
		t.Fatalf("A should be kept")
	}

	b := &Commit{Mark: 2, Branch: []byte("refs/heads/main"), From: markRef(1)}
	if keep := cf.Tweak(b, true); keep {
		t.Fatalf("B should be pruned")
	}

	c := &Commit{Mark: 3, Branch: []byte("refs/heads/main"), From: markRef(2)}
	if keep := cf.Tweak(c, true); keep {
		t.Fatalf("C should be pruned")
	}

	// D references its immediate (pruned) parent C.
	d := &Commit{Mark: 4, Branch: []byte("refs/heads/main"), From: markRef(3),
		FileChanges: []*FileChange{modifyChange("d", 101)}}
	if keep := cf.Tweak(d, true); !keep {
		t.Fatalf("D should be kept")
	}

	if d.From.Mark != 1 {
		t.Fatalf("D.From = %+v, want mark 1 (A)", d.From)
	}

	if len(d.Merges) != 0 {
		t.Fatalf("D.Merges = %+v, want none", d.Merges)
	}
}

// TestPrunedRootChildBecomesRoot verifies that when the whole first-parent
// history is pruned, the surviving child becomes a root.
func TestPrunedRootChildBecomesRoot(t *testing.T) {
	cf := NewCommitFilter(PruneAlways, NewIDMap())

	// Empty root pruned.
	a := &Commit{Mark: 1, Branch: []byte("refs/heads/main")}
	if keep := cf.Tweak(a, false); keep {
		t.Fatalf("empty root should be pruned under always")
	}

	b := &Commit{Mark: 2, Branch: []byte("refs/heads/main"), From: markRef(1),
		FileChanges: []*FileChange{modifyChange("b", 100)}}
	if keep := cf.Tweak(b, true); !keep {
		t.Fatalf("B should be kept")
	}

	if !b.From.IsZero() {
		t.Fatalf("B.From = %+v, want root (zero)", b.From)
	}
}

// TestMergeParentRemap checks that a merge whose one parent was pruned re-points
// that side to the surviving ancestor while remaining a merge.
func TestMergeParentRemap(t *testing.T) {
	cf := NewCommitFilter(PruneAuto, NewIDMap())

	// mainline: A (content) -> B (empty, pruned)
	a := &Commit{Mark: 1, Branch: []byte("refs/heads/main"),
		FileChanges: []*FileChange{modifyChange("a", 100)}}
	cf.Tweak(a, true)

	b := &Commit{Mark: 2, Branch: []byte("refs/heads/main"), From: markRef(1)}
	if keep := cf.Tweak(b, true); keep {
		t.Fatalf("B should be pruned")
	}

	// side branch: X (content)
	x := &Commit{Mark: 3, Branch: []byte("refs/heads/side"),
		FileChanges: []*FileChange{modifyChange("x", 101)}}
	cf.Tweak(x, true)

	// merge M has parents B (pruned -> A) and X, plus content of its own.
	m := &Commit{Mark: 4, Branch: []byte("refs/heads/main"),
		From: markRef(2), Merges: []Ref{markRef(3)},
		FileChanges: []*FileChange{modifyChange("m", 102)}}
	if keep := cf.Tweak(m, true); !keep {
		t.Fatalf("merge M should be kept")
	}

	if m.From.Mark != 1 {
		t.Fatalf("M.From = %+v, want mark 1 (A)", m.From)
	}

	if len(m.Merges) != 1 || m.Merges[0].Mark != 3 {
		t.Fatalf("M.Merges = %+v, want [mark 3]", m.Merges)
	}
}

// TestMergeDedupDegenerates checks that a merge whose two parents resolve to the
// same surviving commit collapses to an ordinary commit and can then be pruned
// when empty.
func TestMergeDedupDegenerates(t *testing.T) {
	cf := NewCommitFilter(PruneAuto, NewIDMap())

	// A (content) -> B (empty, pruned) and A -> C (empty, pruned).
	a := &Commit{Mark: 1, Branch: []byte("refs/heads/main"),
		FileChanges: []*FileChange{modifyChange("a", 100)}}
	cf.Tweak(a, true)

	b := &Commit{Mark: 2, Branch: []byte("refs/heads/topic"), From: markRef(1)}
	cf.Tweak(b, true)

	c := &Commit{Mark: 3, Branch: []byte("refs/heads/main"), From: markRef(1)}
	cf.Tweak(c, true)

	// Merge of B and C, both resolving to A; the merge itself is empty and the
	// parents were rewritten, so it degenerates and is pruned.
	m := &Commit{Mark: 4, Branch: []byte("refs/heads/main"),
		From: markRef(2), Merges: []Ref{markRef(3)}}
	if keep := cf.Tweak(m, true); keep {
		t.Fatalf("degenerate empty merge should be pruned")
	}

	// A child of the pruned merge re-points to A.
	child := &Commit{Mark: 5, Branch: []byte("refs/heads/main"), From: markRef(4),
		FileChanges: []*FileChange{modifyChange("z", 101)}}
	if keep := cf.Tweak(child, true); !keep {
		t.Fatalf("child should be kept")
	}

	if child.From.Mark != 1 {
		t.Fatalf("child.From = %+v, want mark 1 (A)", child.From)
	}
}

// TestNoFFDuplicateParentPreserved verifies that an intentional duplicate parent
// (identical already in the original, not from pruning) is retained.
func TestNoFFDuplicateParentPreserved(t *testing.T) {
	cf := NewCommitFilter(PruneNever, NewIDMap())

	a := &Commit{Mark: 1, Branch: []byte("refs/heads/main"),
		FileChanges: []*FileChange{modifyChange("a", 100)}}
	cf.Tweak(a, true)

	// A merge that lists A twice without any pruning involved.
	m := &Commit{Mark: 2, Branch: []byte("refs/heads/main"),
		From: markRef(1), Merges: []Ref{markRef(1)}}
	if keep := cf.Tweak(m, true); !keep {
		t.Fatalf("never mode should keep")
	}

	if m.From.Mark != 1 || len(m.Merges) != 1 || m.Merges[0].Mark != 1 {
		t.Fatalf("duplicate non-rewritten parent should be preserved, got From=%+v Merges=%+v", m.From, m.Merges)
	}
}
