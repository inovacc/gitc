package uuidv7

import (
	"regexp"
	"testing"
)

var canonical = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewFormatAndVersion(t *testing.T) {
	t.Parallel()

	id, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !canonical.MatchString(id) {
		t.Errorf("id %q is not a canonical v7 UUID (version/variant nibble wrong?)", id)
	}
}

func TestNewUniqueAndOrdered(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 1000)

	var prev string

	for i := 0; i < 1000; i++ {
		id, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id generated: %s", id)
		}

		seen[id] = struct{}{}

		// The ms-timestamp prefix means ids never sort before an earlier one
		// generated in a prior millisecond; within the same ms the random tail
		// may reorder, so only assert non-decreasing on the timestamp prefix.
		if prev != "" && id[:12] < prev[:12] {
			t.Errorf("timestamp prefix went backwards: %s before %s", prev, id)
		}

		prev = id
	}
}
