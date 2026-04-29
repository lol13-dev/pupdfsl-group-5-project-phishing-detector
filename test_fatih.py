import os
import joblib
import re
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from database import save_detection, get_stats

os.environ['SENDGRID_API_KEY'] = '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'
os.environ['EMAIL_SENDER'] = 'wida.iryon@student.president.ac.id'

def clean(text):
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'http\S+|www\.\S+', ' URL ', text)
    text = re.sub(r'\d+', ' NUM ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.lower().strip()

model = joblib.load('models/systemic_phish_lr.joblib')

subject = 'URGENT: Your Bank Account Will Be Suspended'
body = 'Dear Fatih, we detected suspicious activity. Click here to verify your identity immediately: http://bca-klik-secure.net/login. Failure to do so will result in permanent suspension.'
receiver_email = 'fatihputrarizki@gmail.com'

text = clean(subject + ' ' + body)
proba = model.predict_proba([text])[0]
classes = list(model.classes_)
phishing_index = classes.index('phishing')
legit_index = classes.index('legit')
phishing_prob = round(float(proba[phishing_index]) * 100, 2)
legit_prob = round(float(proba[legit_index]) * 100, 2)
label = 'phishing' if phishing_prob >= legit_prob else 'legit'

domain = receiver_email.split('@')[-1]
user_type = 'President University' if 'student' in domain else 'External User'
save_detection(receiver_email, domain, user_type, label, phishing_prob, legit_prob)

stats = get_stats()

prob_value = phishing_prob if label == 'phishing' else legit_prob
html_content = f'<h2>{label.upper()} DETECTED</h2><p>Probability: {prob_value}%</p><p>Total Scans: {stats.get("total")}</p><p>Total Phishing: {stats.get("phishing")}</p>'

message = Mail(
    from_email=os.environ['EMAIL_SENDER'],
    to_emails=receiver_email,
    subject='PUPD Email Scan Result: ' + label.upper(),
    html_content=html_content
)

sg = SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
try:
    response = sg.send(message)
    print(f'DETECTED: {label.upper()} ({prob_value}%).')
    print(f'Email berhasil dikirim ke {receiver_email}! Status code: {response.status_code}')
except Exception as e:
    print(f'Gagal kirim email: {e}')
