package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServiceAccountKey string   `yaml:"service_account_key"`
	DelegatedEmail    string   `yaml:"delegated_email"`
	AppPassword       string   `yaml:"app_password"`
	SenderEmail       string   `yaml:"sender_email"`
	Threshold         int      `yaml:"threshold"`
	PolicyNumDays     int      `yaml:"policy_numdays"`
	UsersExcluded     []string `yaml:"users_excluded"`

	// Deprecated: old Python config used "treshold" (typo). Kept for backward compatibility.
	ThresholdCompat int `yaml:"treshold"`

	// Deprecated: old Python config used "service_account_json". Kept for backward compatibility.
	ServiceAccountKeyCompat string `yaml:"service_account_json"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg.applyCompat()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// applyCompat migrates deprecated field names from the old Python config format.
func (c *Config) applyCompat() {
	if c.Threshold == 0 && c.ThresholdCompat != 0 {
		c.Threshold = c.ThresholdCompat
	}
	if c.ServiceAccountKey == "" && c.ServiceAccountKeyCompat != "" {
		c.ServiceAccountKey = c.ServiceAccountKeyCompat
	}
}

func (c *Config) Validate() error {
	if c.ServiceAccountKey == "" {
		return fmt.Errorf("service_account_key is required")
	}
	if c.DelegatedEmail == "" {
		return fmt.Errorf("delegated_email is required")
	}
	if c.AppPassword == "" {
		return fmt.Errorf("app_password is required")
	}
	if c.SenderEmail == "" {
		return fmt.Errorf("sender_email is required")
	}
	if c.PolicyNumDays <= 0 {
		return fmt.Errorf("policy_numdays must be positive")
	}
	if c.Threshold <= 0 {
		return fmt.Errorf("threshold must be positive")
	}
	if c.Threshold >= c.PolicyNumDays {
		return fmt.Errorf("threshold (%d) must be less than policy_numdays (%d)", c.Threshold, c.PolicyNumDays)
	}
	return nil
}

var SampleConfig = Config{
	ServiceAccountKey: "/etc/google-password-notifier/service-account.json",
	DelegatedEmail:    "admin@example.com",
	AppPassword:       "your-app-password",
	SenderEmail:       "alert@example.com",
	Threshold:         10,
	PolicyNumDays:     90,
	UsersExcluded:     []string{"excluded@example.com"},
}

func WriteSample(path string) error {
	data, err := yaml.Marshal(&SampleConfig)
	if err != nil {
		return fmt.Errorf("marshaling sample config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
