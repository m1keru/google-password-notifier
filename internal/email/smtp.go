package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

type Sender interface {
	Send(to, subject, body string) error
}

type SMTPSender struct {
	host     string
	port     int
	from     string
	password string
}

func NewSMTPSender(from, password string) *SMTPSender {
	return &SMTPSender{
		host:     "smtp.gmail.com",
		port:     465,
		from:     from,
		password: password,
	}
}

func (s *SMTPSender) Send(to, subject, body string) error {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.host})
	if err != nil {
		return fmt.Errorf("TLS dial %s: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("creating SMTP client: %w", err)
	}
	defer client.Close()

	if err := client.Auth(smtp.PlainAuth("", s.from, s.password, s.host)); err != nil {
		return fmt.Errorf("SMTP auth: %w", err)
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		s.from, to, subject, body,
	)

	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message writer: %w", err)
	}

	return client.Quit()
}
