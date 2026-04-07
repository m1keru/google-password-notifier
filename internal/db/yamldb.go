package db

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const TimeFormat = "2006-01-02T15:04:05.000000Z"

type UserDB struct {
	path  string
	users map[string]string
}

func Open(path string) (*UserDB, error) {
	db := &UserDB{
		path:  path,
		users: make(map[string]string),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, fmt.Errorf("reading db file: %w", err)
	}

	if len(data) == 0 {
		return db, nil
	}

	if err := yaml.Unmarshal(data, &db.users); err != nil {
		return nil, fmt.Errorf("parsing db file: %w", err)
	}

	if db.users == nil {
		db.users = make(map[string]string)
	}

	return db, nil
}

func (db *UserDB) Get(email string) (time.Time, bool) {
	ts, ok := db.users[email]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(TimeFormat, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return time.Time{}, false
		}
	}
	return t, true
}

func (db *UserDB) Set(email string, t time.Time) {
	db.users[email] = t.UTC().Format(TimeFormat)
}

func (db *UserDB) Delete(email string) {
	delete(db.users, email)
}

func (db *UserDB) All() map[string]time.Time {
	result := make(map[string]time.Time, len(db.users))
	for email, ts := range db.users {
		t, err := time.Parse(TimeFormat, ts)
		if err != nil {
			t, err = time.Parse(time.RFC3339Nano, ts)
			if err != nil {
				continue
			}
		}
		result[email] = t
	}
	return result
}

func (db *UserDB) Len() int {
	return len(db.users)
}

// Save writes the DB to disk atomically via temp-file + rename.
func (db *UserDB) Save() error {
	data, err := yaml.Marshal(db.users)
	if err != nil {
		return fmt.Errorf("marshaling db: %w", err)
	}

	dir := filepath.Dir(db.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "users_db_*.yaml")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpPath, db.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}
