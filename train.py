# IMPORTS
import pandas as pd
from pathlib import Path
import re
import sys
import numpy as np

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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
# 2) Combine & clean text
# -------------------------------------------
df["text"] = df["subject"].astype(str) + " " + df["body"].astype(str)

def clean(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()

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
# 4) Build Stronger Pipeline
# -------------------------------------------
pipe = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=40000,
        min_df=1,
        max_df=0.9,
        stop_words="english"
    )),
    ("clf", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))
])

pipe.fit(X_train, y_train)

# -------------------------------------------
# 5) Evaluation
# -------------------------------------------
y_pred = pipe.predict(X_test)
y_proba = pipe.predict_proba(X_test)[:, 1]  # phishing probability

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

# ROC AUC (ADDED)
try:
    y_test_binary = (y_test == "phishing").astype(int)
    auc = roc_auc_score(y_test_binary, y_proba)
    print(f"\nROC-AUC Score: {auc:.4f}")
except:
    print("\nROC-AUC could not be calculated.")

# Cross validation
cv_scores = cross_val_score(pipe, df["text"], df["label"], cv=5)
print(f"\nCross Validation Accuracy: {cv_scores.mean():.4f}")

# -------------------------------------------
# 6) Save model
# -------------------------------------------
joblib.dump(pipe, MODEL_PATH)
print(f"\n[OK] Model saved to: {MODEL_PATH.resolve()}")