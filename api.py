# ===============================
# IMPORTS
# ===============================
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
import joblib
import re
import os
import toml
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from database import init_db, save_detection, get_all_detections, get_stats

# Load secrets from .streamlit/secrets.toml to environment variables if present
secrets_path = Path(".streamlit/secrets.toml")
if secrets_path.exists():
    try:
        secrets = toml.load(secrets_path)
        if "SENDGRID_API_KEY" in secrets:
            os.environ["SENDGRID_API_KEY"] = secrets["SENDGRID_API_KEY"]
        if "EMAIL_SENDER" in secrets:
            os.environ["SENDER_EMAIL"] = secrets["EMAIL_SENDER"]
    except Exception as e:
        print(f"[WARNING] Failed to load secrets.toml: {e}")

# ===============================
# APP INIT
# ===============================
app = FastAPI(title="ProtectYou Backend API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# ===============================
# LOAD MODEL
# ===============================
MODEL_PATH = Path("models/systemic_phish_lr.joblib")

if not MODEL_PATH.exists():
    raise FileNotFoundError("Model not found. Run train.py first.")

model = joblib.load(MODEL_PATH)

# ===============================
# SCHEMAS
# ===============================
class EmailRequest(BaseModel):
    subject: Optional[str] = ""
    body: str
    receiver_email: Optional[str] = ""


class EmailSendRequest(BaseModel):
    receiver_email: str
    label: str
    phishing_probability: float
    legit_probability: float


# ===============================
# CLEAN FUNCTION
# ===============================
def clean(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()


# ===============================
# SEND EMAIL
# ===============================
def send_email_backend(receiver_email, label, phishing_prob, legit_prob):

    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    SENDER_EMAIL = os.getenv("SENDER_EMAIL")

    if not SENDGRID_API_KEY or not SENDER_EMAIL:
        print("[WARNING] Email configuration missing. Skipping email send.")
        return

    prob_value = phishing_prob if label == "phishing" else legit_prob

    html_content = f"""
    <h2>{label.upper()}</h2>
    <p>Probability: {prob_value}%</p>
    """

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=receiver_email,
        subject="PUPD Email Scan Result",
        html_content=html_content
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        print(f"[WARNING] SendGrid email failed: {e}")


# ===============================
# ENDPOINTS
# ===============================
@app.get("/health")
def health():
    return {"status": "online"}


@app.post("/predict")
def predict_email(data: EmailRequest, request: Request, background_tasks: BackgroundTasks):

    subject = data.subject or ""
    body = data.body or ""
    text = clean(subject + " " + body)

    proba = model.predict_proba([text])[0]
    classes = list(model.classes_)

    phishing_index = classes.index("phishing")
    legit_index = classes.index("legit")

    phishing_prob = round(float(proba[phishing_index]) * 100, 2)
    legit_prob = round(float(proba[legit_index]) * 100, 2)

    label = "phishing" if phishing_prob >= legit_prob else "legit"

    # DOMAIN & USER TYPE — only process if email is provided
    receiver_email = data.receiver_email or ""
    if receiver_email and "@" in receiver_email:
        domain = receiver_email.split("@")[-1]

        if "student" in domain:
            user_type = "President University"
        else:
            user_type = "External User"

        # SAVE TO MYSQL
        background_tasks.add_task(
            save_detection,
            receiver_email,
            domain,
            user_type,
            label,
            phishing_prob,
            legit_prob
        )

        # SEND EMAIL (non-blocking, won't crash if it fails)
        background_tasks.add_task(
            send_email_backend,
            receiver_email,
            label,
            phishing_prob,
            legit_prob
        )

    return {
        "prediction": label,
        "phishing_probability": phishing_prob,
        "legit_probability": legit_prob
    }


@app.get("/logs")
def logs():
    return get_all_detections()


@app.get("/stats")
def stats():
    return get_stats()
# Trigger API Reload
