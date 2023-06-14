# build
``` bash
cd google-password-notifier
poetry install
poetry build
```

# install
``` bash
python3 -m venv .venv
source .venv/bin/activate && python -m pip install dist/google_password_notifier-*-py3-none-any.whl
```
# configure
* Go to google cloud console and setup service account with global permissions to `admin.reports.audit.readonly` (Audit events reader)
* Create a secret p12 key for this service account. Download it.
* Go to admin.google.com and grant this account permissions to read events (TODO: enter role name)
# run
```bash
source .venv/bin/activate && google-password-notifier -c /path/to/config_file.yaml
```

# sample config

``` yaml
---
service_account_email: "passwords-audit@xxx-audit.iam.gserviceaccount.com"
app_password: "123"
delegated_email: "xxx@xxx.com"
treshold: 10
sender_email: xxx@xxx.com
service_account_p12: /etc/google-password-notifier/secret.p12
```
