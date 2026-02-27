import streamlit as st
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def send_result_email(receiver_email, label, probs, stats):
    """
    Send phishing detection result via SendGrid using Streamlit secrets.
    """

    try:
        SENDGRID_API_KEY = st.secrets["SENDGRID_API_KEY"]
        SENDER_EMAIL = st.secrets["EMAIL_SENDER"]
    except KeyError as e:
        raise Exception(f"Missing secret configuration: {e}")

    prob_value = probs.get(label, 0)

    html_content = f"""
    <h2>{label.upper()}</h2>
    <p>Probability: {prob_value}%</p>
    <p>Total Scans: {stats.get('total')}</p>
    <p>Total Phishing: {stats.get('phishing')}</p>
    """

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=receiver_email,
        subject="PUPD Email Scan Result",
        html_content=html_content
    )

    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(message)

    if response.status_code >= 400:
        raise Exception(f"SendGrid error: {response.status_code}")

    return True