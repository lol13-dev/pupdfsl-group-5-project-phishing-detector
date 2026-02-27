import smtplib
from email.mime.text import MIMEText

sender = "emailkamu@gmail.com"
password = "APP_PASSWORD_16_CHAR"

msg = MIMEText("Test email from ProtectYou")
msg["From"] = sender
msg["To"] = sender
msg["Subject"] = "SMTP Test"

with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
    s.login(sender, password)
    s.send_message(msg)

print("SUCCESS")