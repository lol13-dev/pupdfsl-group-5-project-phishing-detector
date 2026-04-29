import requests

url = "http://127.0.0.1:8000/predict"
payload = {
    "subject": "Urgent Check",
    "body": "Please click the link",
    "receiver_email": "test@student.president.ac.id"
}

try:
    response = requests.post(url, json=payload)
    print("Status:", response.status_code)
    print("Response:", response.text)
except Exception as e:
    print("Error:", e)
