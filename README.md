# google-password-notifier

A CLI tool that monitors Google Workspace password-change events and notifies users before their passwords expire via email.

It persists the last known password-change timestamp per user in a local YAML file, allowing it to track expiration beyond Google's ~6-month Security Audit retention limit.

## How it works

1. Authenticates to **Google Admin SDK Reports API** using a service account with domain-wide delegation.
2. Fetches all `password_edit` audit events (with full pagination).
3. Merges events into a local `users_db.yaml` database, keeping only the most recent password change per user.
4. Removes excluded users from tracking.
5. Sends email notifications via **Gmail SMTP** (SSL, port 465) when:
   - A password has **expired** (past `policy_numdays`).
   - A password is **about to expire** (remaining days below `threshold`).

## Build

```bash
go build -o bin/google-password-notifier ./cmd/notifier/
```

Or using Make:

```bash
make build
```

## Install from source

```bash
go install github.com/m1keru/google-password-notifier/cmd/notifier@latest
```

## Docker

```bash
docker build -t google-password-notifier .

docker run --rm \
  -v /path/to/config:/config:ro \
  -v /path/to/service-account.json:/etc/secret.json:ro \
  google-password-notifier -config /config/config.yaml
```

## Configure

### Google Cloud setup

1. Create a **service account** in the GCP Console.
2. Enable the **Admin SDK API** for the project.
3. Download a **JSON key** for the service account.
4. In the **Google Admin Console** (admin.google.com), go to **Security > API Controls > Domain-wide Delegation** and grant the service account the scope:
   ```
   https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```
5. Assign the service account the **Reports Auditor** admin role (or equivalent).

### Config file

Create a YAML config file (see [sample-config.yaml](sample-config.yaml)):

```yaml
service_account_key: /etc/google-password-notifier/service-account.json
delegated_email: admin@example.com
app_password: your-gmail-app-password
sender_email: alert@example.com
threshold: 10
policy_numdays: 90
users_excluded:
  - serviceaccount@example.com
```

| Key                   | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `service_account_key` | Path to the GCP service account JSON key file                    |
| `delegated_email`     | Google Workspace admin email for domain-wide delegation          |
| `app_password`        | Gmail App Password for SMTP authentication                       |
| `sender_email`        | "From" address for notification emails                           |
| `threshold`           | Number of days before expiry to start sending warnings           |
| `policy_numdays`      | Password policy duration in days                                 |
| `users_excluded`      | List of email addresses to skip (service accounts, admins, etc.) |

You can also generate a sample config:

```bash
google-password-notifier -generate-sample /path/to/sample-config.yaml
```

## Run

```bash
google-password-notifier -config /path/to/config.yaml
```

### Flags

| Flag               | Description                              |
|--------------------|------------------------------------------|
| `-config`          | Path to config file (required)           |
| `-debug`           | Enable debug logging                     |
| `-dry-run`         | Log notifications without sending emails |
| `-version`         | Print version and exit                   |
| `-generate-sample` | Write a sample config to the given path  |

### Cron example

```cron
0 9 * * * /usr/local/bin/google-password-notifier -config /etc/google-password-notifier/config.yaml 2>> /var/log/password-notifier.log
```

## Development

```bash
make test       # run tests with race detector
make lint       # run golangci-lint
make build      # build binary to bin/
make clean      # remove build artifacts
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
