package reports

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/option"
)

const timeFormat = "2006-01-02T15:04:05.000000Z"

type PasswordEvent struct {
	Email     string
	ChangedAt time.Time
}

type EventFetcher interface {
	FetchPasswordEvents(ctx context.Context, since time.Time) ([]PasswordEvent, error)
}

type Client struct {
	service *admin.Service
}

func NewClient(ctx context.Context, keyFile, delegatedEmail string) (*Client, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading service account key %s: %w", keyFile, err)
	}

	cfg, err := google.JWTConfigFromJSON(keyData, admin.AdminReportsAuditReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("creating JWT config: %w", err)
	}
	cfg.Subject = delegatedEmail

	service, err := admin.NewService(ctx, option.WithTokenSource(cfg.TokenSource(ctx)))
	if err != nil {
		return nil, fmt.Errorf("creating admin reports service: %w", err)
	}

	return &Client{service: service}, nil
}

// FetchPasswordEvents retrieves all password_edit events since the given time,
// handling pagination automatically.
func (c *Client) FetchPasswordEvents(ctx context.Context, since time.Time) ([]PasswordEvent, error) {
	var events []PasswordEvent

	call := c.service.Activities.List("all", "user_accounts").
		EventName("password_edit").
		StartTime(since.UTC().Format(time.RFC3339)).
		MaxResults(1000)

	err := call.Pages(ctx, func(resp *admin.Activities) error {
		for _, activity := range resp.Items {
			if activity.Actor == nil || activity.Id == nil {
				continue
			}

			changedAt, err := parseTime(activity.Id.Time)
			if err != nil {
				continue
			}

			events = append(events, PasswordEvent{
				Email:     activity.Actor.Email,
				ChangedAt: changedAt,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing password events: %w", err)
	}

	return events, nil
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(timeFormat, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
