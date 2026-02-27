# ===============================
# IMPORTS
# ===============================
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import joblib
import re
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from database import init_db, save_detection, get_all_detections, get_stats

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
    subject: str
    body: str
    receiver_email: str


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
        raise HTTPException(status_code=500, detail="Email configuration missing")

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

    sg = SendGridAPIClient(SENDGRID_API_KEY)
    sg.send(message)


# ===============================
# ENDPOINTS
# ===============================
@app.get("/health")
def health():
    return {"status": "online"}


@app.post("/predict")
def predict_email(data: EmailRequest, request: Request):

    text = clean(data.subject + " " + data.body)

    proba = model.predict_proba([text])[0]
    classes = list(model.classes_)

    phishing_index = classes.index("phishing")
    legit_index = classes.index("legit")

    phishing_prob = round(float(proba[phishing_index]) * 100, 2)
    legit_prob = round(float(proba[legit_index]) * 100, 2)

    label = "phishing" if phishing_prob >= legit_prob else "legit"

    # DOMAIN & USER TYPE
    domain = data.receiver_email.split("@")[-1]

    if "student" in domain:
        user_type = "President University"
    else:
        user_type = "External User"

    # SAVE TO MYSQL
    save_detection(
        data.receiver_email,
        domain,
        user_type,
        label,
        phishing_prob,
        legit_prob
    )

    # SEND EMAIL
    send_email_backend(
        data.receiver_email,
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