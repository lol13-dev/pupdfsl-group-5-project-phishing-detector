# IMPORTS
import pandas as pd
from pathlib import Path
import re
import sys
import numpy as np

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib

# -------------------------------------------
# 0) File setup
# -------------------------------------------
HERE = Path(__file__).parent
CSV_PATH = HERE / "emails.csv"
MODEL_DIR = HERE / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "systemic_phish_lr.joblib"

if not CSV_PATH.exists():
    sys.exit(f"[ERROR] Dataset not found: {CSV_PATH}")

# -------------------------------------------
# 1) Load dataset
# -------------------------------------------
df = pd.read_csv(CSV_PATH)
df.columns = df.columns.str.lower()

required_cols = {"label", "subject", "body"}
if not required_cols.issubset(df.columns):
    sys.exit("[ERROR] Dataset must contain label, subject, body")

df = df.dropna(subset=["label", "subject", "body"]).copy()
df = df.drop_duplicates(subset=["subject", "body"])

# Normalize labels
df["label"] = df["label"].str.lower().str.strip()
valid_labels = ["phishing", "legit"]
df = df[df["label"].isin(valid_labels)]

print("\n[INFO] Label Distribution:")
print(df["label"].value_counts())

if df["label"].nunique() < 2:
    sys.exit("[ERROR] Need at least 2 classes.")

# -------------------------------------------
# 2) Combine & clean text (ADVANCED EXTRACTION)
# -------------------------------------------
df["text"] = df["subject"].astype(str) + " " + df["body"].astype(str)

def clean(text):
    # Strip HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Catch URL and IP Address patterns commonly used in phishing
    text = re.sub(r"http\S+|www\.\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", " SUSPICIOUS_URL ", text)
    # Mask random numbers so the model focuses on sentence structure
    text = re.sub(r"\d+", " NUM ", text)
    # Remove extra whitespaces
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()

print("[INFO] Cleaning text dataset...")
df["text"] = df["text"].apply(clean)

# -------------------------------------------
# 3) Train/test split
# -------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    df["text"],
    df["label"],
    test_size=0.3,
    random_state=42,
    stratify=df["label"]
)

print("\n[DEBUG] Test Distribution:")
print(pd.Series(y_test).value_counts())

# -------------------------------------------
# 4) Build Stronger Pipeline (GRADE 5 AI SECURITY)
# -------------------------------------------
print("\n[INFO] Initializing Advanced Ensemble Architecture...")

pipe = Pipeline([
    # ADVANCED NLP FEATURE EXTRACTION
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 3),         # Capture up to 3-word combinations (Trigrams) e.g., "update your password"
        max_features=50000,         # Expand the AI's vocabulary memory
        min_df=2,                   # Drop typos/noise words that appear only once
        max_df=0.8,                 # Ignore common words appearing in 80%+ of emails
        sublinear_tf=True,          # Logarithmic scaling to prevent spam word domination (Advanced Technique)
        stop_words="english"
    )),
    # ENSEMBLE LEARNING MODEL (RANDOM FOREST)
    ("clf", RandomForestClassifier(
        n_estimators=200,           # Utilize 200 decision trees simultaneously
        max_depth=50,               # Limit depth to prevent the AI from memorizing/overfitting
        min_samples_split=5,        # Strict node splitting rules
        class_weight="balanced",    # Auto-balance if legit/phishing data is skewed
        n_jobs=-1,                  # Utilize all available CPU cores for faster training
        random_state=42
    ))
])

print("[INFO] Training the model (This might take a moment using all CPU cores)...")
pipe.fit(X_train, y_train)

# -------------------------------------------
# 5) Evaluation
# -------------------------------------------
y_pred = pipe.predict(X_test)
y_proba = pipe.predict_proba(X_test)[:, 1]  # Phishing probability

print("\n=== Classification Report ===")
print(classification_report(
    y_test,
    y_pred,
    labels=valid_labels,
    digits=4,
    zero_division=0
))

print("\n=== Confusion Matrix ===")
cm = confusion_matrix(y_test, y_pred, labels=valid_labels)

cm_df = pd.DataFrame(
    cm,
    index=[f"Actual_{l}" for l in valid_labels],
    columns=[f"Predicted_{l}" for l in valid_labels]
)
print(cm_df)

# ROC-AUC
try:
    y_test_binary = (y_test == "phishing").astype(int)
    auc = roc_auc_score(y_test_binary, y_proba)
    print(f"\nROC-AUC Score: {auc:.4f}")
except:
    print("\nROC-AUC could not be calculated.")

# -------------------------------------------
# 6) Save model
# -------------------------------------------
joblib.dump(pipe, MODEL_PATH)
print(f"\n[OK] ADVANCED MODEL SUCCESSFULLY SAVED TO: {MODEL_PATH.resolve()}")
print("[INFO] Model architecture is now based on Random Forest Ensemble with Sublinear TF-IDF.")