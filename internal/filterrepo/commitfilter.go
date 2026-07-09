package filterrepo

import "strconv"

// PruneMode selects how empty commits are handled after file filtering.
type PruneMode int

const (
	// PruneAuto prunes a commit that became empty due to filtering, but keeps a
	// commit that was empty in the original repository unless one of its parents
	// was itself pruned. This is the upstream default.
	PruneAuto PruneMode = iota
	// PruneAlways prunes any non-merge commit that has no file changes, whether
	// it became empty or was authored empty.
	PruneAlways
	// PruneNever keeps every commit regardless of emptiness.
	PruneNever
)

// CommitFilter decides, for each commit that has already had its file changes
// filtered, whether the commit should be kept or pruned as empty, and rewrites
// the commit's parents so that surviving children re-point past any pruned
// ancestors.
//
// It reproduces the prune-empty subset of git-filter-repo's _tweak_commit /
// _prunable / _maybe_trim_extra_parents logic. The full ancestry-graph and
// fast-import content-comparison machinery is intentionally excluded (see the
// limitations noted on Tweak); emptiness is judged purely by the absence of
// FileChange records after filtering.
//
// A CommitFilter is stateful: it accumulates the pruned-commit -> surviving
// parent mapping across the whole stream and therefore must be a single shared
// instance driven by the commit callback in stream order.
type CommitFilter struct {
	// Mode is the prune-empty policy.
	Mode PruneMode

	// ids is the parser's shared mark registry. It is retained for wiring
	// parity with upstream (which routes pruned renames through the global id
	// map); this type does not mutate it, because IDMap.translation is keyed on
	// original fast-export marks and is consulted during parsing, so injecting
	// new-mark keys would alias with unrelated original marks. See prunedTo.
	ids *IDMap

	// prunedTo maps a pruned commit's (new) mark to the reference of its nearest
	// surviving ancestor. A zero Ref value means the entire ancestry was pruned
	// (the child becomes a root). Values are stored already fully resolved, so a
	// single lookup suffices to hop past a chain of pruned parents.
	prunedTo map[int]Ref
}

// NewCommitFilter returns a CommitFilter using the given prune policy and the
// parser's shared mark registry.
func NewCommitFilter(mode PruneMode, ids *IDMap) *CommitFilter {
	return &CommitFilter{Mode: mode, ids: ids, prunedTo: make(map[int]Ref)}
}

// Tweak decides whether commit is kept, after its file changes have already
// been filtered (e.g. by FilterFiles). It first rewrites the commit's parents
// so any reference to a previously pruned commit is redirected to that commit's
// surviving ancestor, de-duplicating identical parents; a merge that collapses
// to a single distinct parent degenerates into an ordinary commit. It then
// applies the prune-empty policy.
//
// hadFileChanges must report whether the ORIGINAL commit (as parsed, before any
// file filtering) carried any file changes. This distinguishes a commit that
// became empty through filtering from one the author intentionally made empty,
// which PruneAuto must not prune.
//
// On keep it returns true with the commit's From/Merges rewritten in place. On
// prune it records the commit's surviving parent, calls commit.Skip, and
// returns false.
//
// Limitations vs. upstream (documented for parity tracking):
//   - Emptiness is structural: any remaining FileChange (including a lone
//     deleteall) counts as non-empty. Content-identical changes that upstream
//     would detect as empty via a fast-import "ls"/"get-mark" comparison are
//     treated as non-empty and kept.
//   - Genuine merge commits (>=2 distinct parents after resolution) are never
//     pruned here; degenerate-merge pruning that needs true ancestry
//     (is_ancestor) is not performed. Only exact-duplicate parents are removed.
func (cf *CommitFilter) Tweak(commit *Commit, hadFileChanges bool) (keep bool) {
	orig := origParents(commit)
	newParents := cf.resolveParents(orig)
	setParents(commit, newParents)

	if cf.shouldPrune(commit, orig, newParents, hadFileChanges) {
		var survivor Ref
		if len(newParents) > 0 {
			survivor = newParents[0]
		}
		cf.prunedTo[commit.Mark] = survivor
		commit.Skip()
		return false
	}
	return true
}

// origParents returns the commit's parents (first parent plus merges) as they
// stand on entry, dropping any zero reference. These correspond to upstream's
// orig_parents for the prune decision.
func origParents(commit *Commit) []Ref {
	var out []Ref
	if !commit.From.IsZero() {
		out = append(out, commit.From)
	}
	for _, m := range commit.Merges {
		if !m.IsZero() {
			out = append(out, m)
		}
	}
	return out
}

// resolveParents redirects each parent past any pruned commit and removes
// duplicates. Following upstream, an exact-duplicate parent is dropped only when
// it resulted from a pruning rewrite; a duplicate that was already identical in
// the original is preserved (e.g. an intentional no-ff merge).
func (cf *CommitFilter) resolveParents(orig []Ref) []Ref {
	var out []Ref
	seen := make(map[string]bool)
	for _, r := range orig {
		rr, drop := cf.resolve(r)
		if drop {
			continue
		}
		key := refKey(rr)
		rewritten := cf.isPruned(r)
		if seen[key] && rewritten {
			continue
		}
		seen[key] = true
		out = append(out, rr)
	}
	return out
}

// resolve maps a single parent reference to its surviving ancestor. The second
// result is true when the parent's entire ancestry was pruned and the parent
// should be dropped.
func (cf *CommitFilter) resolve(r Ref) (Ref, bool) {
	if r.Mark != 0 {
		if s, ok := cf.prunedTo[r.Mark]; ok {
			if s.IsZero() {
				return Ref{}, true
			}
			return s, false
		}
	}
	return r, false
}

// isPruned reports whether the reference points at a commit that was pruned.
func (cf *CommitFilter) isPruned(r Ref) bool {
	if r.Mark == 0 {
		return false
	}
	_, ok := cf.prunedTo[r.Mark]
	return ok
}

// setParents writes the resolved parent list back onto the commit, collapsing a
// degenerated merge into an ordinary commit.
func setParents(commit *Commit, parents []Ref) {
	if len(parents) == 0 {
		commit.From = Ref{}
		commit.Merges = nil
		return
	}
	commit.From = parents[0]
	if len(parents) > 1 {
		commit.Merges = append([]Ref(nil), parents[1:]...)
	} else {
		commit.Merges = nil
	}
}

// shouldPrune implements the prune-empty decision, mirroring _prunable for the
// subset that does not require a fast-import pipe or ancestry graph.
func (cf *CommitFilter) shouldPrune(commit *Commit, orig, newParents []Ref, hadFileChanges bool) bool {
	if cf.Mode == PruneNever {
		return false
	}

	becameEmpty := len(commit.FileChanges) == 0

	// Genuine merge commits are not pruned here (matches upstream's guard for
	// len(parents) >= 2 with no degenerate first-parent).
	if len(newParents) >= 2 {
		return false
	}

	if cf.Mode == PruneAlways {
		return becameEmpty
	}

	// PruneAuto.
	if !hadFileChanges {
		// The commit was empty in the original repository. Only prune it if it
		// is still empty AND at least one of its parents was pruned.
		if !becameEmpty {
			return false
		}
		hadParentsPruned := len(newParents) < len(orig) ||
			(len(orig) == 1 && cf.isPruned(orig[0]))
		return hadParentsPruned
	}

	// The commit originally had file changes; if filtering emptied it, prune.
	if becameEmpty {
		return true
	}

	// Non-empty, or an emptiness that could only be proven by comparing tree
	// content against the new first parent (needs a fast-import pipe we do not
	// have). Keep it.
	return false
}

// refKey returns a stable de-duplication key for a parent reference.
func refKey(r Ref) string {
	if r.Mark != 0 {
		return "m" + strconv.Itoa(r.Mark)
	}
	return "o" + string(r.OID)
}
