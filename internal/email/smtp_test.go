package email

import "testing"

func TestNewSMTPSender(t *testing.T) {
	s := NewSMTPSender("from@example.com", "pass123")
	if s.from != "from@example.com" {
		t.Errorf("from = %q, want %q", s.from, "from@example.com")
	}
	if s.password != "pass123" {
		t.Errorf("password = %q, want %q", s.password, "pass123")
	}
	if s.host != "smtp.gmail.com" {
		t.Errorf("host = %q, want %q", s.host, "smtp.gmail.com")
	}
	if s.port != 465 {
		t.Errorf("port = %d, want 465", s.port)
	}
}

func TestSMTPSenderImplementsSender(t *testing.T) {
	var _ Sender = (*SMTPSender)(nil)
}
