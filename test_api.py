from fastapi.testclient import TestClient
from api import app

client = TestClient(app)

response = client.post(
    "/predict",
    json={"subject": "Test", "body": "This is a test body", "receiver_email": "test@student.president.ac.id"}
)
print("Status code:", response.status_code)
print("Response JSON:", response.json())
