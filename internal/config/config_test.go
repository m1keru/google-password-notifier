package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
service_account_key: /tmp/key.json
delegated_email: admin@example.com
app_password: secret
sender_email: alert@example.com
threshold: 10
policy_numdays: 90
users_excluded:
  - skip@example.com
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ServiceAccountKey != "/tmp/key.json" {
		t.Errorf("ServiceAccountKey = %q, want %q", cfg.ServiceAccountKey, "/tmp/key.json")
	}
	if cfg.DelegatedEmail != "admin@example.com" {
		t.Errorf("DelegatedEmail = %q, want %q", cfg.DelegatedEmail, "admin@example.com")
	}
	if cfg.Threshold != 10 {
		t.Errorf("Threshold = %d, want 10", cfg.Threshold)
	}
	if cfg.PolicyNumDays != 90 {
		t.Errorf("PolicyNumDays = %d, want 90", cfg.PolicyNumDays)
	}
	if len(cfg.UsersExcluded) != 1 || cfg.UsersExcluded[0] != "skip@example.com" {
		t.Errorf("UsersExcluded = %v, want [skip@example.com]", cfg.UsersExcluded)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(":::invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing service_account_key", Config{DelegatedEmail: "a", AppPassword: "b", SenderEmail: "c", Threshold: 1, PolicyNumDays: 90}},
		{"missing delegated_email", Config{ServiceAccountKey: "a", AppPassword: "b", SenderEmail: "c", Threshold: 1, PolicyNumDays: 90}},
		{"missing app_password", Config{ServiceAccountKey: "a", DelegatedEmail: "b", SenderEmail: "c", Threshold: 1, PolicyNumDays: 90}},
		{"missing sender_email", Config{ServiceAccountKey: "a", DelegatedEmail: "b", AppPassword: "c", Threshold: 1, PolicyNumDays: 90}},
		{"zero policy_numdays", Config{ServiceAccountKey: "a", DelegatedEmail: "b", AppPassword: "c", SenderEmail: "d", Threshold: 1, PolicyNumDays: 0}},
		{"zero threshold", Config{ServiceAccountKey: "a", DelegatedEmail: "b", AppPassword: "c", SenderEmail: "d", Threshold: 0, PolicyNumDays: 90}},
		{"threshold >= policy_numdays", Config{ServiceAccountKey: "a", DelegatedEmail: "b", AppPassword: "c", SenderEmail: "d", Threshold: 90, PolicyNumDays: 90}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := Config{
		ServiceAccountKey: "/tmp/key.json",
		DelegatedEmail:    "admin@example.com",
		AppPassword:       "secret",
		SenderEmail:       "alert@example.com",
		Threshold:         10,
		PolicyNumDays:     90,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestLoad_LegacyPythonConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
service_account_key: /tmp/key.json
delegated_email: admin@example.com
app_password: secret
sender_email: alert@example.com
treshold: 10
policy_numdays: 90
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Threshold != 10 {
		t.Errorf("Threshold = %d, want 10 (migrated from treshold)", cfg.Threshold)
	}
}

func TestLoad_LegacyServiceAccountJson(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
service_account_json: /tmp/key.json
delegated_email: admin@example.com
app_password: secret
sender_email: alert@example.com
threshold: 10
policy_numdays: 90
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ServiceAccountKey != "/tmp/key.json" {
		t.Errorf("ServiceAccountKey = %q, want /tmp/key.json (migrated from service_account_json)", cfg.ServiceAccountKey)
	}
}

func TestWriteSample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")

	if err := WriteSample(path); err != nil {
		t.Fatalf("WriteSample() error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(sample) error: %v", err)
	}
	if cfg.PolicyNumDays != 90 {
		t.Errorf("sample PolicyNumDays = %d, want 90", cfg.PolicyNumDays)
	}
}
