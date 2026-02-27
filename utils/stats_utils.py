import pandas as pd
from pathlib import Path
from datetime import datetime
from pandas.errors import EmptyDataError

STATS_PATH = Path("data/stats.csv")
STATS_PATH.parent.mkdir(exist_ok=True)

COLUMNS = ["email", "domain", "user_type", "prediction", "timestamp"]

def save_stat(email, label):
    domain = email.split("@")[-1] if "@" in email else "unknown"

    user_type = (
        "President University"
        if domain.endswith("president.ac.id")
        else "Public"
    )

    row = {
        "email": email,
        "domain": domain,
        "user_type": user_type,
        "prediction": label,
        "timestamp": datetime.now()
    }

    try:
        if STATS_PATH.exists() and STATS_PATH.stat().st_size > 0:
            df = pd.read_csv(STATS_PATH)
        else:
            df = pd.DataFrame(columns=COLUMNS)
    except EmptyDataError:
        df = pd.DataFrame(columns=COLUMNS)

    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    df.to_csv(STATS_PATH, index=False)


def load_stats():
    if not STATS_PATH.exists() or STATS_PATH.stat().st_size == 0:
        return pd.DataFrame(columns=COLUMNS)
    return pd.read_csv(STATS_PATH)


def compute_statistics():
    df = load_stats()
    if df.empty:
        return None

    total = len(df)
    phishing_count = (df["prediction"] == "phishing").sum()
    legit_count = (df["prediction"] == "legit").sum()

    phishing_rate = round(phishing_count / total * 100, 2)

    return {
        "total": total,
        "phishing": phishing_count,
        "legit": legit_count,
        "phishing_rate": phishing_rate
    }