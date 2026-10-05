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
		"Hello,\n\n"+
			"This is a friendly note that the Google Workspace password for %s has expired.\n\n"+
			"No worries - this happens, and it's quick to fix. Please reach out to your administrator "+
			"or ask in the support channel, and someone will be glad to help you set a new password.\n\n"+
			"Thank you, and sorry for any inconvenience.\n\n"+
			"Kind regards,\nIT Support\n",
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
	subject := fmt.Sprintf("Google Workspace password expires in %s", pluralDays(daysRemaining))
	body := fmt.Sprintf(
		"Hello,\n\n"+
			"This is a friendly reminder that the Google Workspace password for %s will expire in %s. "+
			"Whenever it's convenient for you, we'd kindly ask you to update it.\n\n"+
			"If you have any questions or would like a hand, please feel free to reach out to your administrator "+
			"or ask in the support channel - we're always happy to help.\n\n"+
			"A small tip: after you change your password, the office Wi-Fi may need up to 30 minutes "+
			"to recognise the new one. If you can't connect right away, please wait a little and try again. "+
			"In the meantime, you're very welcome to stop by your administrator, who will be happy "+
			"to help you connect to a temporary network.\n\n"+
			"Thank you for helping keep our accounts secure!\n\n"+
			"Kind regards,\nIT Support\n",
		userEmail, pluralDays(daysRemaining),
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

func pluralDays(days int) string {
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}
