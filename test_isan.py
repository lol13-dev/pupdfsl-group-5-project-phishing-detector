import os
import joblib
import re
from utils.analysis_utils import full_analysis
from database import save_detection, get_stats, init_db
from utils.stats_utils import compute_statistics
from utils.email_utils import send_result_email

import streamlit as st
import collections
st.secrets = collections.defaultdict(str)
st.secrets['SENDGRID_API_KEY'] = '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'
st.secrets['EMAIL_SENDER'] = 'wida.iryon@student.president.ac.id'

init_db()

def clean(text):
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'http\S+|www\.\S+', ' URL ', text)
    text = re.sub(r'\d+', ' NUM ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.lower().strip()

model = joblib.load('models/systemic_phish_lr.joblib')

subject = 'URGENT: Your PayPal Account Has Been Restricted'
body = 'Dear Customer,\n\nWe detected unusual login activity on your PayPal account. To protect your financial security, your account has been temporarily restricted.\n\nYou must verify your identity immediately to restore full access. Failure to do so within 24 hours will result in permanent account suspension and cancellation of all pending transfers.\n\nPlease click the secure link below to update your billing information and verify your account:\nhttp://paypal-security-update.xyz/login\n\nThank you,\nThe PayPal Security Team'

receiver_email = 'fatihputrarizki@gmail.com'

text = clean(subject + ' ' + body)
proba = model.predict_proba([text])[0]
classes = list(model.classes_)
phishing_index = classes.index('phishing')
legit_index = classes.index('legit')
phishing_prob = round(float(proba[phishing_index]) * 100, 2)
legit_prob = round(float(proba[legit_index]) * 100, 2)
label = 'phishing' if phishing_prob >= legit_prob else 'legit'
probs = {'phishing': phishing_prob, 'legit': legit_prob}

analysis = full_analysis(subject, body)
stats = compute_statistics()

try:
    send_result_email(receiver_email, label, probs, stats, analysis)
    print('Email berhasil dikirim ke', receiver_email)
except Exception as e:
    print('Gagal kirim email:', e)
