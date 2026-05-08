import mysql.connector
import os
import typing
from datetime import datetime

# CONNECTION FOR MySQL Databases
def get_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "protectyou_db")
        )
    except mysql.connector.Error:
        return None

def init_db():
    # First, try to create the database if it doesn't exist
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "")
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS protectyou_db")
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error:
        print("[WARNING] Could not connect to MySQL. Database features will be unavailable.")
        return

    # Now connect to the database and create the table
    connection = get_connection()
    if connection is None:
        print("[WARNING] Could not connect to MySQL database.")
        return

    try:
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
    except mysql.connector.Error as e:
        print(f"[WARNING] Database table creation failed: {e}")

def save_detection(email, domain, user_type, prediction, phishing_prob, legit_prob):
    connection = get_connection()
    if connection is None:
        print("[WARNING] MySQL not available. Skipping database save.")
        return

    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO detections 
            (email, domain, user_type, prediction, phishing_probability, legit_probability)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (email, domain, user_type, prediction, phishing_prob, legit_prob))
        connection.commit()
        cursor.close()
        connection.close()
    except mysql.connector.Error as e:
        print(f"[WARNING] Failed to save detection: {e}")

def get_all_detections():
    connection = get_connection()
    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM detections ORDER BY created_at DESC")
        results = cursor.fetchall()
        cursor.close()
        connection.close()
        return results
    except mysql.connector.Error:
        return []

def get_stats():
    connection = get_connection()
    if connection is None:
        return {"total": 0, "phishing": 0, "legit": 0, "phishing_rate": 0}

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM detections")
        row_total = cursor.fetchone()
        # Bungkus dengan str() agar Pylance yakin ini aman untuk di-int()
        total = int(str(row_total[0])) if row_total else 0

        cursor.execute("SELECT COUNT(*) FROM detections WHERE prediction='phishing'")
        row_phish = cursor.fetchone()
        phishing = int(str(row_phish[0])) if row_phish else 0

        cursor.execute("SELECT COUNT(*) FROM detections WHERE prediction='legit'")
        row_legit = cursor.fetchone()
        legit = int(str(row_legit[0])) if row_legit else 0

        cursor.close()
        connection.close()

        phishing_rate = round((phishing / total) * 100, 2) if total > 0 else 0

        return {
            "total": total,
            "phishing": phishing,
            "legit": legit,
            "phishing_rate": phishing_rate
        }
    except mysql.connector.Error:
        return {"total": 0, "phishing": 0, "legit": 0, "phishing_rate": 0}