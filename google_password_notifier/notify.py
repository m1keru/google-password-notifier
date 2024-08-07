import ssl
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from googleapiclient.discovery import build
from oauth2client.service_account import ServiceAccountCredentials
import httplib2
import logging
import yaml
import os
import argparse
from pathlib import Path


FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

SAMPLE_CFG = {
    "service_account_email": "passwords-audit@example.iam.gserviceaccount.com",
    "app_password": "",
    "delegated_email": "admin@example.com",
    "treshold": 10,
    "sender_email": "alert@example.com",
    "service_account_p12": "/etc/google-password-notifier/secret.p12",
    "users_excluded": [
        "example2@example.com"
    ],
    "policy_numdays": 90
}


class GoogleNotifier(object):
    def __init__(self, config_file):
        try:
            self._CFG_PATH = Path(config_file).parent
            self.make_config_dir(config_file)
            with open(config_file, 'r') as file:
                self.cfg = yaml.safe_load(file)
            self._SERVICE_ACCOUNT_EMAIL = self.cfg["service_account_email"]
            self._APP_PASSWORD = self.cfg["app_password"]
            self._DELEGATED_EMAIL = self.cfg["delegated_email"]
            self._TRESHOLD = self.cfg["treshold"]
            self._SENDER = self.cfg["sender_email"]
            self._SERVICE_ACCOUNT_P12 = self.cfg["service_account_p12"]
            self._USERS_EXCLUDED = self.cfg["users_excluded"]
            self._RETENTION = self.cfg["policy_numdays"]
        except Exception as e:
            print(f"prepare config file {e}")
            return

    def make_config_dir(self, config_file):
        if not os.path.exists(self._CFG_PATH):
            os.makedirs(self._CFG_PATH)
            with open(f"{self._CFG_PATH}/sample-config.yaml", 'w') as file:
                yaml.dump(SAMPLE_CFG, file)

    def send_email(self, to, msg_text):
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = self._SENDER
        receiver_email = to
        password = self._APP_PASSWORD
        msg = EmailMessage()
        msg.set_content(msg_text)
        msg['Subject'] = "Google password expire soon!"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg, from_addr=sender_email,
                                to_addrs=receiver_email)

    def create_reports_service(self):
        credentials = ServiceAccountCredentials.from_p12_keyfile(
            self._SERVICE_ACCOUNT_EMAIL,
            self._SERVICE_ACCOUNT_P12, 'notasecret',
            scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly'])  # noqa: E501
        credentials = credentials.create_delegated(self._DELEGATED_EMAIL)
        http = credentials.authorize(httplib2.Http())
        return build('admin', 'reports_v1', http=http)

    def load_users_db(self):
        try:
            self.user_db = yaml.safe_load(open(f"{self._CFG_PATH}/users_db.yaml", "r"))  # noqa: E501
            logging.debug("{self._CFG_PATH}/users_db.yaml found, loading")
        except Exception as e:
            self.user_db = {}
            logging.error(f"No users db found: {e}")

    def store_users_db(self):
        try:
            with open(f"{self._CFG_PATH}/users_db.yaml", "w") as db_file:
                yaml.dump(self.user_db, db_file, default_flow_style=False, sort_keys=False)  # noqa: E501
        except Exception as e:
            logging.error(f"Unable to store users_db in {self._CFG_PATH}/users_db.yaml. {e}")  # noqa: E501

    def get_usersdb(self):
        LOG_MONTHS = (datetime.now() - timedelta(days=self._RETENTION + 30)).isoformat() + "Z"  # noqa: E501
        svc = self.create_reports_service()
        request = svc.activities().list(
            applicationName='user_accounts', userKey='all',
            eventName='password_edit', startTime=(LOG_MONTHS))
        response = request.execute()
        self.load_users_db()
        for event in response['items']:
            user = event['actor']['email']
            event_date = event['id']['time']
            event_datetime = datetime.strptime(event_date, FORMAT)
            if user in self.user_db.keys() and (event_datetime < datetime.strptime(self.user_db[user], FORMAT)):  # noqa: E501
                logging.debug(
                    f"Existing record for user: {user}  {self.user_db[user]} newer than {event_date} ")  # noqa: E501
                continue
            self.user_db[user] = event_date
            logging.debug(f"set password date for {user} = {event_date}")
        for excluded_user in self._USERS_EXCLUDED:
            logging.debug(f"pop user {excluded_user} from list")
            if excluded_user in self.user_db.keys():
                self.user_db.pop(excluded_user)
        self.store_users_db()
        return self.user_db

    def notify(self):
        for email in self.user_db:
            event_date = datetime.strptime(self.user_db[email], FORMAT)
            delta = (datetime.now() - event_date).days
            logging.debug(
                f"user: {email}, event: {event_date},  delta: {delta}")
            if (self._RETENTION - delta) < 0:
                print(f"Password expired for user {email}")
                msg = f"Dear {email}! Your password is expired! Please ask admins to reset it for you!"  # noqa: E501
                self.send_email(email, msg)
                continue
            if (self._RETENTION - delta) < self._TRESHOLD:
                msg = f"""Dear {email}! Your password is about to expire in {self._RETENTION-delta} days! Please update it!
How to reset password:
https://support.google.com/accounts/answer/41078?hl=en&co=GENIE.Platform%3DDesktop
                """  # noqa: E501
                self.send_email(email, msg)
                print(
                    f"Notify user {email} that password expires in  {self._RETENTION-delta} days")  # noqa: E501


def run():
    parser = argparse.ArgumentParser(
        prog='Google Password Notifier',
        description='Notifies when password is about to expire',
        epilog='Text at the bottom of help')
    parser.add_argument('-c', '--config')
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()
    import pprint
    pprint.pprint(args)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if not args.config:
        print("Please specify config file")
        return
    cli = GoogleNotifier(args.config)
    cli.get_usersdb()
    cli.notify()


if __name__ == "__main__":
    run()
