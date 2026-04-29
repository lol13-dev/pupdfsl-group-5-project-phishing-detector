"""
PUPD Advanced Phishing Indicator Analysis Engine
Performs deep content analysis to identify specific phishing indicators.
"""
import re
from datetime import datetime


# ============================
# INDICATOR DEFINITIONS
# ============================

URGENCY_WORDS = [
    "urgent", "immediately", "right now", "asap", "hurry", "expire",
    "suspended", "terminated", "locked", "disabled", "closed",
    "within 24 hours", "within 48 hours", "act now", "time sensitive",
    "deadline", "final warning", "last chance", "don't delay",
    "segera", "sekarang juga", "akan ditutup", "akan diblokir"
]

THREAT_WORDS = [
    "suspend", "block", "restrict", "delete", "terminate", "close",
    "unauthorized", "compromised", "breach", "hack", "illegal",
    "violation", "penalty", "legal action", "permanent", "forever",
    "blokir", "hapus", "ditangguhkan"
]

CREDENTIAL_WORDS = [
    "verify your", "confirm your", "update your", "reset your",
    "enter your password", "login credentials", "account details",
    "billing information", "payment method", "credit card",
    "social security", "bank account", "pin number", "cvv",
    "masukkan kata sandi", "verifikasi akun"
]

REWARD_WORDS = [
    "congratulations", "you won", "you've been selected", "free",
    "gift card", "prize", "winner", "claim", "reward", "bonus",
    "lottery", "million dollars", "inheritance", "bitcoin",
    "selamat", "hadiah", "gratis", "menang"
]

IMPERSONATION_WORDS = [
    "helpdesk", "it support", "admin", "security team",
    "customer service", "technical support", "paypal", "microsoft",
    "apple", "google", "amazon", "netflix", "bank", "irs",
    "president university"
]


def analyze_urls(text):
    """Analyze URLs found in the email text for suspicious patterns."""
    indicators = []
    urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text, re.IGNORECASE)

    if urls:
        indicators.append({
            "type": "url_presence",
            "severity": "medium",
            "icon": "🔗",
            "title": "External Links Detected",
            "detail": f"Found {len(urls)} link(s) in the email body.",
            "urls": urls
        })

        for url in urls:
            # Check for IP address in URL
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                indicators.append({
                    "type": "ip_url",
                    "severity": "high",
                    "icon": "🚨",
                    "title": "IP-Based URL Detected",
                    "detail": f"URL uses raw IP address instead of domain name: {url}"
                })

            # Check for suspicious TLD
            suspicious_tlds = ['.xyz', '.top', '.click', '.loan', '.win', '.bid', '.club', '.gq', '.ml', '.tk', '.cf']
            for tld in suspicious_tlds:
                if url.lower().endswith(tld) or tld + '/' in url.lower():
                    indicators.append({
                        "type": "suspicious_tld",
                        "severity": "high",
                        "icon": "⚠️",
                        "title": "Suspicious Domain Extension",
                        "detail": f"URL uses suspicious TLD '{tld}': {url}"
                    })

            # Check for login/verify/secure keywords in URL
            url_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'auth', 'signin']
            found_kw = [kw for kw in url_keywords if kw in url.lower()]
            if found_kw:
                indicators.append({
                    "type": "phishing_url_keywords",
                    "severity": "high",
                    "icon": "🎣",
                    "title": "Phishing Keywords in URL",
                    "detail": f"URL contains authentication-related words ({', '.join(found_kw)}): {url}"
                })

            # Check for brand name spoofing in URL
            brands = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix', 'bca', 'mandiri', 'bni', 'bri']
            found_brands = [b for b in brands if b in url.lower()]
            if found_brands:
                official_domains = {
                    'paypal': 'paypal.com', 'microsoft': 'microsoft.com', 'apple': 'apple.com',
                    'google': 'google.com', 'amazon': 'amazon.com', 'netflix': 'netflix.com',
                    'bca': 'klikbca.com', 'mandiri': 'bankmandiri.co.id', 'bni': 'bni.co.id', 'bri': 'bri.co.id'
                }
                for brand in found_brands:
                    official = official_domains.get(brand, '')
                    if official and official not in url.lower():
                        indicators.append({
                            "type": "brand_spoofing",
                            "severity": "critical",
                            "icon": "🛑",
                            "title": f"Possible Brand Impersonation ({brand.title()})",
                            "detail": f"URL mentions '{brand}' but does NOT point to official domain ({official}): {url}"
                        })

    return indicators


def analyze_language(text):
    """Analyze language patterns for phishing indicators."""
    indicators = []
    text_lower = text.lower()

    # 1. Urgency Analysis
    found_urgency = [w for w in URGENCY_WORDS if w in text_lower]
    if found_urgency:
        indicators.append({
            "type": "urgency",
            "severity": "high" if len(found_urgency) >= 2 else "medium",
            "icon": "⏰",
            "title": "Urgency Language Detected",
            "detail": f"Email uses high-pressure/urgency words: {', '.join(found_urgency)}"
        })

    # 2. Threat Analysis
    found_threats = [w for w in THREAT_WORDS if w in text_lower]
    if found_threats:
        indicators.append({
            "type": "threats",
            "severity": "high",
            "icon": "💀",
            "title": "Threatening Language Detected",
            "detail": f"Email contains threatening consequences: {', '.join(found_threats)}"
        })

    # 3. Credential Harvesting
    found_creds = [w for w in CREDENTIAL_WORDS if w in text_lower]
    if found_creds:
        indicators.append({
            "type": "credential_request",
            "severity": "critical",
            "icon": "🔑",
            "title": "Credential Request Detected",
            "detail": f"Email asks for sensitive information: {', '.join(found_creds)}"
        })

    # 4. Reward/Prize Bait
    found_rewards = [w for w in REWARD_WORDS if w in text_lower]
    if found_rewards:
        indicators.append({
            "type": "reward_bait",
            "severity": "high",
            "icon": "🎁",
            "title": "Reward/Prize Bait Detected",
            "detail": f"Email lures with rewards or prizes: {', '.join(found_rewards)}"
        })

    # 5. Impersonation
    found_impersonation = [w for w in IMPERSONATION_WORDS if w in text_lower]
    if found_impersonation:
        indicators.append({
            "type": "impersonation",
            "severity": "medium",
            "icon": "🎭",
            "title": "Possible Authority Impersonation",
            "detail": f"Email claims to be from: {', '.join(found_impersonation)}"
        })

    return indicators


def analyze_structure(subject, body):
    """Analyze email structure for suspicious patterns."""
    indicators = []
    full_text = (subject + " " + body).lower()

    # 1. All caps in subject
    if subject and len(subject) > 5:
        caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
        if caps_ratio > 0.5:
            indicators.append({
                "type": "caps_subject",
                "severity": "medium",
                "icon": "📢",
                "title": "Excessive Capitalization in Subject",
                "detail": f"Subject line has {round(caps_ratio * 100)}% uppercase letters — a common pressure tactic."
            })

    # 2. Exclamation marks
    exclamation_count = full_text.count('!')
    if exclamation_count >= 3:
        indicators.append({
            "type": "exclamation_marks",
            "severity": "low",
            "icon": "❗",
            "title": "Excessive Exclamation Marks",
            "detail": f"Email contains {exclamation_count} exclamation marks, suggesting exaggerated urgency."
        })

    # 3. Generic greeting
    generic_greetings = ["dear customer", "dear user", "dear valued", "dear sir", "dear account holder", "dear member"]
    found_greeting = [g for g in generic_greetings if g in full_text]
    if found_greeting:
        indicators.append({
            "type": "generic_greeting",
            "severity": "medium",
            "icon": "👤",
            "title": "Generic Greeting Used",
            "detail": f"Email uses impersonal greeting ('{found_greeting[0]}') instead of your real name."
        })

    # 4. Grammar/Spelling red flags
    grammar_flags = ["kindly do the needful", "revert back", "do the necessary", "click below link"]
    found_grammar = [g for g in grammar_flags if g in full_text]
    if found_grammar:
        indicators.append({
            "type": "grammar",
            "severity": "low",
            "icon": "📝",
            "title": "Unusual Grammar Detected",
            "detail": f"Email contains phrases uncommon in professional communication: {', '.join(found_grammar)}"
        })

    # 5. HTML content detected
    if re.search(r'<[a-zA-Z][^>]*>', subject + " " + body):
        indicators.append({
            "type": "html_content",
            "severity": "low",
            "icon": "🌐",
            "title": "HTML Content in Email Body",
            "detail": "Email contains HTML markup, which could be used to disguise malicious links."
        })

    return indicators


def compute_risk_score(indicators):
    """Compute overall risk score based on indicators."""
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    total_score = 0
    for ind in indicators:
        total_score += severity_weights.get(ind["severity"], 0)

    # Cap at 100
    risk_score = min(total_score, 100)
    return risk_score


def get_risk_level(risk_score):
    """Convert risk score to a human-readable level."""
    if risk_score >= 70:
        return {"level": "CRITICAL", "color": "#ff1744", "emoji": "🔴"}
    elif risk_score >= 40:
        return {"level": "HIGH", "color": "#ff9100", "emoji": "🟠"}
    elif risk_score >= 20:
        return {"level": "MODERATE", "color": "#ffea00", "emoji": "🟡"}
    else:
        return {"level": "LOW", "color": "#00e676", "emoji": "🟢"}


def full_analysis(subject, body):
    """
    Run full phishing analysis on email content.
    Returns a dict with indicators, risk score, and risk level.
    """
    original_text = subject + " " + body

    # Run all analysis engines
    url_indicators = analyze_urls(original_text)
    language_indicators = analyze_language(original_text)
    structure_indicators = analyze_structure(subject, body)

    all_indicators = url_indicators + language_indicators + structure_indicators

    # Deduplicate by type
    seen_types = set()
    unique_indicators = []
    for ind in all_indicators:
        if ind["type"] not in seen_types:
            seen_types.add(ind["type"])
            unique_indicators.append(ind)

    risk_score = compute_risk_score(unique_indicators)
    risk_level = get_risk_level(risk_score)

    return {
        "indicators": unique_indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "engines_used": ["URL Scanner", "Language Analyzer", "Structure Analyzer", "ML Classifier"]
    }
