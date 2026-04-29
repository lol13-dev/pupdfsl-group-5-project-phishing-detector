from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

SENDGRID_API_KEY = "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"
SENDER_EMAIL = "wida.iryon@student.president.ac.id"
receiver_email = "test@student.president.ac.id"

message = Mail(
    from_email=SENDER_EMAIL,
    to_emails=receiver_email,
    subject="Test",
    html_content="Test"
)

try:
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(message)
    print("Status:", response.status_code)
except Exception as e:
    print("Error:", e)
