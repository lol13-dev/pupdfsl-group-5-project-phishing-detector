import mysql.connector
import os
from datetime import datetime

# CONNECTION FOR MySQL Databases
def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "protectyou_user"),
        password=os.getenv("DB_PASSWORD", "AppPass123!"),
        database=os.getenv("DB_NAME", "protectyou_db")
    )

def init_db():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            domain VARCHAR(255),
            user_type VARCHAR(100),
            prediction VARCHAR(50),
            phishing_probability FLOAT,
            legit_probability FLOAT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    cursor.close()
    connection.close()

def save_detection(email, domain, user_type, prediction, phishing_prob, legit_prob):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO detections 
        (email, domain, user_type, prediction, phishing_probability, legit_probability)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (email, domain, user_type, prediction, phishing_prob, legit_prob))

    connection.commit()
    cursor.close()
    connection.close()

def get_all_detections():
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM detections ORDER BY created_at DESC")
    results = cursor.fetchall()

    cursor.close()
    connection.close()

    return results

def get_stats():
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total FROM detections")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as phishing FROM detections WHERE prediction='phishing'")
    phishing = cursor.fetchone()["phishing"]

    cursor.execute("SELECT COUNT(*) as legit FROM detections WHERE prediction='legit'")
    legit = cursor.fetchone()["legit"]

    cursor.close()
    connection.close()

    phishing_rate = round((phishing / total) * 100, 2) if total > 0 else 0

    return {
        "total": total,
        "phishing": phishing,
        "legit": legit,
        "phishing_rate": phishing_rate
    }