import pandas as pd
import random
import os

legit_subjects = [
    "Meeting at {time}", "Project update: {project}", "Lunch today?", 
    "Invoice #{num} attached", "Welcome to the team", "Your flight itinerary", 
    "Q3 Marketing Report", "Class schedule for {semester}", "Library overdue notice", 
    "University event: {event}", "Homework submission confirmed", "Weekly sync",
    "Notes from yesterday's meeting", "Happy birthday!", "Question regarding {topic}",
    "Task assignment: {project}", "Please review document", "Coffee break?",
    "Feedback on your presentation", "Schedule change for {semester}"
]

legit_bodies = [
    "Hi, let's meet at {time}. Regards.", 
    "The {project} project is on track. See attached.", 
    "Let's grab lunch at {place}.", 
    "Please find the invoice attached for your records.", 
    "Welcome to the team! We are glad to have you.", 
    "Here is your flight itinerary for your upcoming trip.", 
    "The report is attached. Let me know if you have questions.", 
    "Your class schedule for {semester} is ready.", 
    "Please return the book by {time}.", 
    "Join us for the {event} tomorrow.", 
    "Your homework has been submitted successfully.",
    "See you at the sync later.",
    "I've attached the notes from yesterday's meeting. Thanks.",
    "Wishing you a very happy birthday!",
    "Could you clarify the point about {topic}?",
    "Can you please review the attached document before the meeting at {time}?",
    "Just a quick reminder about our meeting regarding {project}.",
    "Let's grab a coffee at {place} and discuss {topic}.",
    "Great presentation today! I really liked the part about {topic}.",
    "Please note the schedule change for the {event}."
]

phish_subjects = [
    "URGENT: Account Suspended", "Action Required: Verify Your Email", 
    "Password Reset Required", "You won a {prize}", "Claim your iPhone", 
    "Bank Account Alert: {bank}", "PayPal Security Notice", "Unusual login activity", 
    "Update your payment details", "Your package could not be delivered", 
    "President University: IT Helpdesk Alert", "Final Warning: Account Deletion",
    "Security Alert: Compromised Password", "Important: Update your mailbox quota",
    "Invoice #{num} Overdue - Pay Immediately", "Verify your identity now",
    "Your subscription has expired", "Account locked due to multiple failed logins",
    "A document has been shared with you", "IT Support: Required System Update"
]

phish_bodies = [
    "Your account will be suspended in 24 hours. Click here to verify: http://{evil}/verify", 
    "Please verify your email address immediately to avoid account closure. Link: www.{evil}/auth", 
    "Click the link below to reset your password within 2 hours. http://{evil}", 
    "You won a {prize}. Claim it here: www.{evil}/claim", 
    "Claim your free iPhone today by clicking this link: http://{evil}", 
    "Alert: Unusual activity on your {bank} account. Log in to verify: http://{evil}", 
    "Your PayPal account is restricted. Update your billing details immediately at {evil}.", 
    "Someone logged into your account from a new device. Click here if it wasn't you: http://{evil}", 
    "Your payment failed. Update details now to keep your subscription active: {evil}", 
    "Track your package here. It could not be delivered due to missing address: http://{evil}", 
    "Dear student, your university account will be deleted unless you verify it here: http://{evil}/pu-verify",
    "FINAL WARNING: We will close your account unless you update your profile here: http://{evil}",
    "Your mailbox is full. Upgrade your quota for free here: www.{evil}/quota",
    "You have an unpaid invoice of $450. Pay immediately using the link: http://{evil}",
    "We noticed suspicious activity. Verify your identity at http://{evil} to unlock your account.",
    "Your antivirus subscription expired. Renew now at a discount: http://{evil}",
    "You have a pending document shared via OneDrive. View it here: http://{evil}",
    "Required update from IT Helpdesk. Install the patch here: http://{evil}/update.exe"
]

fillers = {
    "time": ["10 AM", "2 PM", "14:00", "tomorrow morning", "next Monday", "Friday at 3 PM"],
    "project": ["Alpha", "Beta", "Website Redesign", "Data Migration", "Q4 Planning", "Cybersecurity Upgrade"],
    "num": ["1029", "8473", "9921", "1002", "5543", "7781"],
    "semester": ["Fall 2026", "Spring 2026", "Summer", "Even Semester"],
    "event": ["Career Fair", "Guest Lecture", "Alumni Meetup", "Hackathon", "Graduation"],
    "topic": ["budget", "timeline", "requirements", "design", "deployment", "marketing"],
    "place": ["the cafeteria", "Starbucks", "the usual spot", "the food court", "room 201"],
    "prize": ["$1000 Amazon Gift Card", "new iPad", "trip to Bali", "$500 Cash", "Bitcoin giveaway"],
    "bank": ["BCA", "Mandiri", "BNI", "Chase", "Bank of America", "BRI"],
    "evil": ["secure-update.com", "login-verify-account.net", "free-prize-claim.org", "it-helpdesk-portal.com", "verify-your-id.net", "paypal-security-update.com", "bca-klik-secure.net"]
}

def generate_text(template):
    text = template
    for key, values in fillers.items():
        if f"{{{key}}}" in text:
            text = text.replace(f"{{{key}}}", random.choice(values))
    return text

def expand_dataset():
    data = []
    
    # Generate 1500 legitimate emails
    for _ in range(1500):
        data.append({
            "label": "legit",
            "subject": generate_text(random.choice(legit_subjects)),
            "body": generate_text(random.choice(legit_bodies))
        })

    # Generate 1500 phishing emails
    for _ in range(1500):
        data.append({
            "label": "phishing",
            "subject": generate_text(random.choice(phish_subjects)),
            "body": generate_text(random.choice(phish_bodies))
        })

    df_new = pd.DataFrame(data)

    csv_path = "emails.csv"
    if os.path.exists(csv_path):
        df_old = pd.read_csv(csv_path)
        df_combined = pd.concat([df_old, df_new], ignore_index=True)
    else:
        df_combined = df_new

    # Shuffle the dataset thoroughly
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save back to CSV
    df_combined.to_csv(csv_path, index=False)
    print(f"[SUCCESS] Dataset expanded! New total emails: {len(df_combined)}")

if __name__ == "__main__":
    expand_dataset()
