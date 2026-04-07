package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpen_NewDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if userDB.Len() != 0 {
		t.Errorf("new DB should be empty, got %d entries", userDB.Len())
	}
}

func TestOpen_ExistingDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")

	content := `alice@example.com: "2024-06-15T10:30:00.000000Z"
bob@example.com: "2024-07-20T14:00:00.000000Z"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if userDB.Len() != 2 {
		t.Errorf("Len() = %d, want 2", userDB.Len())
	}

	ts, ok := userDB.Get("alice@example.com")
	if !ok {
		t.Fatal("alice@example.com not found")
	}
	expected := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	if !ts.Equal(expected) {
		t.Errorf("alice timestamp = %v, want %v", ts, expected)
	}
}

func TestGetSetDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	userDB.Set("test@example.com", now)

	got, ok := userDB.Get("test@example.com")
	if !ok {
		t.Fatal("Get() returned false after Set()")
	}
	if !got.Equal(now) {
		t.Errorf("Get() = %v, want %v", got, now)
	}

	userDB.Delete("test@example.com")
	_, ok = userDB.Get("test@example.com")
	if ok {
		t.Error("Get() returned true after Delete()")
	}
}

func TestAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}

	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	userDB.Set("a@example.com", t1)
	userDB.Set("b@example.com", t2)

	all := userDB.All()
	if len(all) != 2 {
		t.Fatalf("All() returned %d entries, want 2", len(all))
	}
	if !all["a@example.com"].Equal(t1) {
		t.Errorf("a timestamp = %v, want %v", all["a@example.com"], t1)
	}
	if !all["b@example.com"].Equal(t2) {
		t.Errorf("b timestamp = %v, want %v", all["b@example.com"], t2)
	}
}

func TestSave_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}

	ts := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC)
	userDB.Set("saved@example.com", ts)

	if err := userDB.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatalf("Open() after Save() error: %v", err)
	}

	got, ok := reloaded.Get("saved@example.com")
	if !ok {
		t.Fatal("saved@example.com not found after reload")
	}
	if !got.Equal(ts) {
		t.Errorf("reloaded timestamp = %v, want %v", got, ts)
	}
}

func TestOpen_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	userDB, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error on empty file: %v", err)
	}
	if userDB.Len() != 0 {
		t.Errorf("empty file should give empty DB, got %d", userDB.Len())
	}
}
