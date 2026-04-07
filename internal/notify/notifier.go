package notify

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/m1keru/google-password-notifier/internal/config"
	"github.com/m1keru/google-password-notifier/internal/db"
	"github.com/m1keru/google-password-notifier/internal/email"
	"github.com/m1keru/google-password-notifier/internal/reports"
)

type Notifier struct {
	cfg     *config.Config
	db      *db.UserDB
	fetcher reports.EventFetcher
	sender  email.Sender
	dryRun  bool
	logger  *slog.Logger
}

func New(cfg *config.Config, userDB *db.UserDB, fetcher reports.EventFetcher, sender email.Sender, dryRun bool, logger *slog.Logger) *Notifier {
	return &Notifier{
		cfg:     cfg,
		db:      userDB,
		fetcher: fetcher,
		sender:  sender,
		dryRun:  dryRun,
		logger:  logger,
	}
}

func (n *Notifier) Run(ctx context.Context) error {
	if err := n.syncEvents(ctx); err != nil {
		return fmt.Errorf("syncing events: %w", err)
	}

	n.removeExcludedUsers()

	if err := n.db.Save(); err != nil {
		return fmt.Errorf("saving user db: %w", err)
	}

	n.sendNotifications()
	return nil
}

func (n *Notifier) syncEvents(ctx context.Context) error {
	since := time.Now().AddDate(0, 0, -(n.cfg.PolicyNumDays + 30))
	n.logger.Info("fetching password events", "since", since.Format(time.RFC3339))

	events, err := n.fetcher.FetchPasswordEvents(ctx, since)
	if err != nil {
		return err
	}
	n.logger.Info("fetched password events", "count", len(events))

	for _, event := range events {
		existing, ok := n.db.Get(event.Email)
		if ok && event.ChangedAt.Before(existing) {
			n.logger.Debug("skipping older event",
				"user", event.Email,
				"existing", existing,
				"event", event.ChangedAt,
			)
			continue
		}
		n.db.Set(event.Email, event.ChangedAt)
		n.logger.Debug("updated password date", "user", event.Email, "date", event.ChangedAt)
	}
	return nil
}

func (n *Notifier) removeExcludedUsers() {
	for _, user := range n.cfg.UsersExcluded {
		n.db.Delete(user)
		n.logger.Debug("excluded user removed", "user", user)
	}
}

func (n *Notifier) sendNotifications() {
	for userEmail, changedAt := range n.db.All() {
		daysSinceChange := int(time.Since(changedAt).Hours() / 24)
		daysRemaining := n.cfg.PolicyNumDays - daysSinceChange

		n.logger.Debug("checking user",
			"user", userEmail,
			"days_since_change", daysSinceChange,
			"days_remaining", daysRemaining,
		)

		if daysRemaining < 0 {
			n.notifyExpired(userEmail)
		} else if daysRemaining < n.cfg.Threshold {
			n.notifyExpiring(userEmail, daysRemaining)
		}
	}
}

func (n *Notifier) notifyExpired(userEmail string) {
	subject := "Google Workspace password has expired"
	body := fmt.Sprintf(
		"Dear %s!\n\nYour Google Workspace password has expired. "+
			"Please contact your administrator to reset it.\n",
		userEmail,
	)

	n.logger.Info("password expired", "user", userEmail)
	if n.dryRun {
		n.logger.Info("dry-run: would send expiry notification", "user", userEmail)
		return
	}

	if err := n.sender.Send(userEmail, subject, body); err != nil {
		n.logger.Error("failed to send expiry notification", "user", userEmail, "error", err)
	}
}

func (n *Notifier) notifyExpiring(userEmail string, daysRemaining int) {
	subject := fmt.Sprintf("Google Workspace password expires in %d days", daysRemaining)
	body := fmt.Sprintf(
		"Dear %s!\n\nYour Google Workspace password will expire in %d days. Please update it.\n\n"+
			"How to reset your password:\nhttps://support.google.com/accounts/answer/41078\n",
		userEmail, daysRemaining,
	)

	n.logger.Info("password expiring soon", "user", userEmail, "days_remaining", daysRemaining)
	if n.dryRun {
		n.logger.Info("dry-run: would send expiring notification", "user", userEmail, "days_remaining", daysRemaining)
		return
	}

	if err := n.sender.Send(userEmail, subject, body); err != nil {
		n.logger.Error("failed to send expiring notification", "user", userEmail, "error", err)
	}
}
