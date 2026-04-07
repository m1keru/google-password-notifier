package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/m1keru/google-password-notifier/internal/config"
	"github.com/m1keru/google-password-notifier/internal/db"
	"github.com/m1keru/google-password-notifier/internal/email"
	"github.com/m1keru/google-password-notifier/internal/notify"
	"github.com/m1keru/google-password-notifier/internal/reports"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (required)")
	debug := flag.Bool("debug", false, "enable debug logging")
	dryRun := flag.Bool("dry-run", false, "log actions without sending emails")
	showVersion := flag.Bool("version", false, "print version and exit")
	genSample := flag.String("generate-sample", "", "write a sample config to the given path and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("google-password-notifier", version)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *genSample != "" {
		if err := config.WriteSample(*genSample); err != nil {
			logger.Error("generating sample config", "error", err)
			os.Exit(1)
		}
		logger.Info("sample config written", "path", *genSample)
		return
	}

	if *configPath == "" {
		logger.Error("-config flag is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(filepath.Dir(*configPath), "users_db.yaml")
	userDB, err := db.Open(dbPath)
	if err != nil {
		logger.Error("opening user database", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	reportsClient, err := reports.NewClient(ctx, cfg.ServiceAccountKey, cfg.DelegatedEmail)
	if err != nil {
		logger.Error("creating Google reports client", "error", err)
		os.Exit(1)
	}

	sender := email.NewSMTPSender(cfg.SenderEmail, cfg.AppPassword)

	notifier := notify.New(cfg, userDB, reportsClient, sender, *dryRun, logger)
	if err := notifier.Run(ctx); err != nil {
		logger.Error("notifier failed", "error", err)
		os.Exit(1)
	}

	logger.Info("completed successfully")
}
