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
    "service_account_p12": "/etc/google-password-notifier/secret.p12"
}


class GoogleNotifier(object):
    def __init__(self, config_file):
        try:
            self.make_config_dir(config_file)
            with open(config_file, 'r') as file:
                self.cfg = yaml.safe_load(file)
            self._SERVICE_ACCOUNT_EMAIL = self.cfg["service_account_email"]
            self._APP_PASSWORD = self.cfg["app_password"]
            self._DELEGATED_EMAIL = self.cfg["delegated_email"]
            self._TRESHOLD = self.cfg["treshold"]
            self._SENDER = self.cfg["sender_email"]
            self._SERVICE_ACCOUNT_P12 = self.cfg["service_account_p12"]
        except Exception as e:
            print(f"prepare config file {e}")
            return

    def make_config_dir(self, config_file):
        cfg_path = Path(config_file).parent
        if not os.path.exists(cfg_path):
            os.makedirs(cfg_path)
            with open(f"{cfg_path}/sample-config.yaml", 'w') as file:
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

    def get_usersdb(self):
        FOUR_MONTHS = (datetime.now() - timedelta(days=120)).isoformat()+"Z"
        svc = self.create_reports_service()
        request = svc.activities().list(
            applicationName='user_accounts', userKey='all',
            eventName='password_edit', startTime=(FOUR_MONTHS))
        response = request.execute()
        self.user_db = {}
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
        return self.user_db

    def notify(self):
        for email in self.user_db:
            event_date = datetime.strptime(self.user_db[email], FORMAT)
            delta = (datetime.now() - event_date).days
            logging.debug(
                f"user: {email}, event: {event_date},  delta: {delta}")
            if (90 - delta) < 0:
                print(f"Password expired for user {email}")
                msg = f"Dear {email}! Your password is expired! Please ask admins to reset it for you!"  # noqa: E501
                self.send_email(email, msg)
                continue
            if (90 - delta) < self._TRESHOLD:
                msg = f"""Dear {email}! Your password is about to expire in {90-delta} days! Please update it!
How to reset password:
https://support.google.com/accounts/answer/41078?hl=en&co=GENIE.Platform%3DDesktop
                """  # noqa: E501
                self.send_email(email, msg)
                print(
                    f"Notify user {email} that password expires in  {90-delta} days")  # noqa: E501


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
    cli = GoogleNotifier(args.config)
    cli.get_usersdb()
    cli.notify()


if __name__ == "__main__":
    run()
