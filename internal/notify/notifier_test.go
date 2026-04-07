package notify

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m1keru/google-password-notifier/internal/config"
	"github.com/m1keru/google-password-notifier/internal/db"
	"github.com/m1keru/google-password-notifier/internal/reports"
)

type mockFetcher struct {
	events []reports.PasswordEvent
	err    error
}

func (m *mockFetcher) FetchPasswordEvents(_ context.Context, _ time.Time) ([]reports.PasswordEvent, error) {
	return m.events, m.err
}

type mockSender struct {
	sent []sentMessage
}

type sentMessage struct {
	to      string
	subject string
	body    string
}

func (m *mockSender) Send(to, subject, body string) error {
	m.sent = append(m.sent, sentMessage{to: to, subject: subject, body: body})
	return nil
}

func testConfig() *config.Config {
	return &config.Config{
		ServiceAccountKey: "/tmp/key.json",
		DelegatedEmail:    "admin@example.com",
		AppPassword:       "secret",
		SenderEmail:       "alert@example.com",
		Threshold:         10,
		PolicyNumDays:     90,
		UsersExcluded:     []string{"excluded@example.com"},
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRun_ExpiringPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	daysAgo := 85
	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "user@example.com", ChangedAt: time.Now().AddDate(0, 0, -daysAgo)},
		},
	}

	sender := &mockSender{}
	cfg := testConfig()
	n := New(cfg, userDB, fetcher, sender, false, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(sender.sent))
	}
	if sender.sent[0].to != "user@example.com" {
		t.Errorf("sent to %q, want %q", sender.sent[0].to, "user@example.com")
	}
	if !strings.HasPrefix(sender.sent[0].subject, "Google Workspace password expires in ") {
		t.Errorf("subject = %q, want prefix %q", sender.sent[0].subject, "Google Workspace password expires in ")
	}
}

func TestRun_ExpiredPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "old@example.com", ChangedAt: time.Now().AddDate(0, 0, -100)},
		},
	}

	sender := &mockSender{}
	n := New(testConfig(), userDB, fetcher, sender, false, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(sender.sent))
	}
	if sender.sent[0].subject != "Google Workspace password has expired" {
		t.Errorf("subject = %q", sender.sent[0].subject)
	}
}

func TestRun_HealthyPassword(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "fresh@example.com", ChangedAt: time.Now().AddDate(0, 0, -10)},
		},
	}

	sender := &mockSender{}
	n := New(testConfig(), userDB, fetcher, sender, false, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 0 {
		t.Errorf("expected 0 emails for healthy password, got %d", len(sender.sent))
	}
}

func TestRun_ExcludedUsers(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "excluded@example.com", ChangedAt: time.Now().AddDate(0, 0, -100)},
		},
	}

	sender := &mockSender{}
	n := New(testConfig(), userDB, fetcher, sender, false, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 0 {
		t.Errorf("excluded user should not receive email, got %d", len(sender.sent))
	}
}

func TestRun_DryRun(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "user@example.com", ChangedAt: time.Now().AddDate(0, 0, -100)},
		},
	}

	sender := &mockSender{}
	n := New(testConfig(), userDB, fetcher, sender, true, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 0 {
		t.Errorf("dry-run should not send emails, got %d", len(sender.sent))
	}
}

func TestRun_NewerEventOverridesOlder(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.yaml")

	userDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	oldTime := time.Now().AddDate(0, 0, -100)
	newTime := time.Now().AddDate(0, 0, -5)
	fetcher := &mockFetcher{
		events: []reports.PasswordEvent{
			{Email: "user@example.com", ChangedAt: oldTime},
			{Email: "user@example.com", ChangedAt: newTime},
		},
	}

	sender := &mockSender{}
	n := New(testConfig(), userDB, fetcher, sender, false, testLogger())

	if err := n.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if len(sender.sent) != 0 {
		t.Errorf("newer event (5 days ago) should not trigger notification, got %d emails", len(sender.sent))
	}
}
