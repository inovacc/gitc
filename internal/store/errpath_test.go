package store

import (
	"path/filepath"
	"testing"
)

func TestOpenOnDirectoryFails(t *testing.T) {
	// Opening a directory as the SQLite file must error, not panic.
	st, err := Open(t.TempDir())
	if err == nil {
		_ = st.Close()

		t.Error("Open on a directory path should fail")
	}
}

func TestQueriesAfterCloseError(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Records(1); err == nil {
		t.Error("Records after Close should error")
	}

	if _, err := st.RawRows(); err == nil {
		t.Error("RawRows after Close should error")
	}

	if _, err := st.Verify(); err == nil {
		t.Error("Verify after Close should error")
	}
}
