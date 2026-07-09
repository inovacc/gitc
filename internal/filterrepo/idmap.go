package filterrepo

// MarkNone is the sentinel mark value meaning "no object" — used when an old
// mark has been remapped to a skipped/pruned object.
const MarkNone = 0

// IDMap maintains the name domain of fast-import marks (the short integer ids
// assigned to blobs and commits). It exists because the marks emitted by
// fast-export are not necessarily the marks we assign in the stream we produce:
// newly created objects consume fresh marks, and pruned objects invalidate a
// mark so that references to them must be redirected.
//
// IDMap is stateful and not safe for concurrent use; a parser owns exactly one.
type IDMap struct {
	nextID      int
	translation map[int]int   // old mark -> new mark (or MarkNone if skipped)
	reverse     map[int][]int // new mark -> every old mark pointing at it
}

// NewIDMap returns an empty IDMap whose first minted mark is 1.
func NewIDMap() *IDMap {
	return &IDMap{
		nextID:      1,
		translation: make(map[int]int),
		reverse:     make(map[int][]int),
	}
}

// New mints and returns the next fresh mark. It must be called once for every
// blob or commit object created.
func (m *IDMap) New() int {
	id := m.nextID
	m.nextID++

	return id
}

// HasRenames reports whether any mark has been remapped.
func (m *IDMap) HasRenames() bool {
	return len(m.translation) > 0
}

// RecordRename records that oldID now refers to newID (which may be MarkNone to
// signal that the object was skipped).
func (m *IDMap) RecordRename(oldID, newID int) {
	if oldID == newID {
		if _, exists := m.translation[oldID]; !exists {
			return
		}
	}

	m.translation[oldID] = newID
	m.reverse[newID] = append(m.reverse[newID], oldID)
}

// Translate resolves oldID to its current mark. The second return value is false
// when the object was skipped (maps to MarkNone); otherwise it is true and the
// first value is the effective mark (oldID itself when never remapped).
func (m *IDMap) Translate(oldID int) (int, bool) {
	if v, ok := m.translation[oldID]; ok {
		return v, v != MarkNone
	}

	return oldID, true
}
