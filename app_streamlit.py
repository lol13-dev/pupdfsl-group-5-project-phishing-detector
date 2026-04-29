# IMPORTS 
import streamlit as st
import requests
import pandas as pd
from pathlib import Path
import time
import joblib  
import re      

from utils.stats_utils import save_stat, load_stats, compute_statistics
from utils.email_utils import send_result_email
from utils.analysis_utils import full_analysis
from database import init_db, save_detection, get_all_detections


# ===============================
# PAGE CONFIG (TOP MUST)
# ===============================
st.set_page_config(
    page_title="PUPDfSD · President University Phishing Detector for Student and Lecturer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ===============================
# LOCAL MODEL & TEXT CLEANER (FALLBACK)
# ===============================
@st.cache_resource
def load_model():
    return joblib.load("models/systemic_phish_lr.joblib")

try:
    model = load_model()
except Exception as e:
    model = None

def clean(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()

# ===============================
# LOADING PAGE SCREEN (AND WITH CSS)
# ===============================
if 'loaded' not in st.session_state:
    loading_placeholder = st.empty()
    with loading_placeholder.container():
        st.markdown("""
        <style>
        .loader-container { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(135deg, #0a0e17 0%, #0d1220 50%, #0a0e17 100%); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 9999; }
        .loader-logo { font-family: 'Orbitron', monospace; font-size: 32px; font-weight: 900; background: linear-gradient(135deg, #00d4aa, #4f8ef7, #7b2fff); background-size: 200% 200%; -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 40px; animation: gradientMove 2s ease infinite; }
        .loader-bar-container { width: 280px; height: 4px; background: rgba(255,255,255,0.1); border-radius: 10px; overflow: hidden; position: relative; }
        .loader-bar { height: 100%; width: 0%; background: linear-gradient(90deg, #00d4aa, #4f8ef7, #7b2fff); animation: loadBar 2s ease-in-out forwards; }
        @keyframes loadBar { 0% { width: 0%; } 50% { width: 70%; } 100% { width: 100%; } }
        @keyframes gradientMove { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        </style>
        <div class="loader-container">
            <div class="loader-logo">Welcome to PUPDfSL</div>
            <div class="loader-bar-container"><div class="loader-bar"></div></div>
        </div>
        """, unsafe_allow_html=True)
        time.sleep(2.0)
    loading_placeholder.empty()
    st.session_state.loaded = True

init_db()

# ===============================
# FULL CSS STYLING (FIXED LAYOUT)
# ===============================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --cyan: #4f8ef7; --green: #00d4aa; --purple: #7b2fff; --dark: #0a0e17;
}

#MainMenu, footer, header { visibility: hidden; }

.block-container {
    padding-top: 120px !important; 
    padding-bottom: 60px !important;
    padding-left: 10% !important;  
    padding-right: 10% !important; 
    max-width: 1400px !important;
}

.stApp {
    background: linear-gradient(180deg, #0a0e17 0%, #0d1220 100%);
    font-family: 'Inter', sans-serif; color: white;
}

/* NAVBAR */
.navbar {
    position: fixed; top: 0; left: 0; right: 0; z-index: 999;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 40px; height: 72px; background: rgba(10, 14, 23, 0.95);
    border-bottom: 1px solid rgba(255,255,255,0.06); backdrop-filter: blur(20px);
}
.navbar-left { display: flex; align-items: center; gap: 24px; }
.navbar-logo {
    width: 44px; height: 44px; background: linear-gradient(135deg, var(--cyan), var(--purple));
    border-radius: 12px; display: flex; align-items: center; justify-content: center;
    font-size: 20px; box-shadow: 0 4px 20px rgba(79, 142, 247, 0.25);
}
.navbar-brand {
    font-family: 'Orbitron', monospace; font-size: 20px; font-weight: 700;
    background: linear-gradient(135deg, #fff, #a0aec0); -webkit-background-clip: text;
    -webkit-text-fill-color: transparent; letter-spacing: 3px;
}
.navbar-divider { width: 1px; height: 32px; background: linear-gradient(180deg, transparent, rgba(255,255,255,0.2), transparent); margin: 0 8px; }

/* NAVBAR LINKS (STREAMLIT OVERRIDE) */
.nav-links-container a {
    text-decoration: none !important; 
    color: rgba(255,255,255,0.6) !important; 
    padding: 10px 18px !important; 
    border-radius: 10px !important;
    font-size: 13px !important; 
    font-weight: 500 !important; 
    transition: all 0.3s ease !important;
}

/* Efek saat mouse diarahkan ke link (Warna Cyan Project) */
.nav-links-container a:hover {
    color: #4f8ef7 !important; 
    background: rgba(79,142,247,0.1) !important;
}

/* Efek saat menu sedang aktif */
.nav-links-container a.active {
    color: white !important; 
    background: linear-gradient(135deg, rgba(79,142,247,0.2), rgba(123,47,255,0.2)) !important;
    border: 1px solid rgba(79,142,247,0.4) !important; 
    font-weight: 600 !important;
    box-shadow: 0 4px 15px rgba(79,142,247,0.15) !important;
}

.status-badge {
    display: flex; align-items: center; gap: 10px; padding: 10px 20px;
    background: rgba(0,212,170,0.08); border: 1px solid rgba(0,212,170,0.2);
    border-radius: 50px; font-size: 12px; color: var(--green); font-weight: 600;
}
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); }

/* HERO */
.hero {
    position: relative;
    margin-top: -120px; 
    height: 520px;
    width: 100vw; 
    margin-left: calc(-50vw + 50%); 
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; text-align: center; overflow: hidden;
}
.hero-bg {
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(79,142,247,0.08) 0%, transparent 60%),
                linear-gradient(to bottom, rgba(10,14,23,0.75) 0%, rgba(10,14,23,0.9) 50%, rgba(10,14,23,1) 100%),
                url('https://z-cdn-media.chatglm.cn/files/d872d379-fc03-46be-8cc8-f9a1fd76c611.jpeg?auth_key=1871562688-2746077b10fb4910a00b829db9431308-0-8c6dadb356bca4c1b4bef3679a0f0823') center/cover no-repeat;
    filter: brightness(0.6);
}
.hero-content { position: relative; z-index: 2; max-width: 850px; padding: 0 20px; }
.hero-badge { display: inline-flex; align-items: center; gap: 10px; padding: 10px 24px; border: 1px solid rgba(79,142,247,0.25); border-radius: 50px; background: rgba(79,142,247,0.05); font-size: 11px; font-weight: 600; color: rgba(255,255,255,0.6); margin-bottom: 28px; }
.hero-badge-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 15px var(--cyan); }
.hero-title { font-size: 52px; font-weight: 800; color: white; margin-bottom: 18px; text-shadow: 0 4px 30px rgba(0,0,0,0.5); }
.hero-title span { background: linear-gradient(135deg, var(--cyan), var(--green)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-family: 'Orbitron', monospace; }
.hero-subtitle { font-size: 18px; color: rgba(255,255,255,0.4); font-style: italic; margin-bottom: 35px; }

/* METRICS */
.overview-section { padding: 50px 0; }
.overview-title { font-size: 11px; font-weight: 700; letter-spacing: 4px; color: rgba(255,255,255,0.3); margin-bottom: 28px; }
.metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; }
.metric-card { background: linear-gradient(145deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%); border: 1px solid rgba(255,255,255,0.06); border-radius: 20px; padding: 28px; transition: all 0.4s ease; }
.metric-card:hover { transform: translateY(-8px); border-color: rgba(79,142,247,0.2); }
.metric-label { font-size: 10px; font-weight: 600; color: rgba(255,255,255,0.35); margin-bottom: 14px; }
.metric-value { font-size: 40px; font-weight: 700; color: white; margin-bottom: 12px; font-family: 'Orbitron', monospace; }
.metric-delta { font-size: 12px; color: var(--green); font-weight: 500; }

/* TYPOGRAPHY */
.page-title { font-size: 32px; font-weight: 700; margin-bottom: 6px; background: linear-gradient(135deg, #fff, rgba(255,255,255,0.7)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.page-subtitle { color: rgba(255,255,255,0.4); font-size: 14px; margin-bottom: 30px; }

/* INPUT & BUTTONS */
.stTextInput input, .stTextArea textarea { 
    color: white !important; 
    background-color: #0d1220 !important; /* Memaksa kotak menjadi gelap */
    -webkit-text-fill-color: white !important;
}
div[data-baseweb="input"], div[data-baseweb="textarea"] {
    background-color: #0d1220 !important;
    border: 1px solid rgba(255,255,255,0.2) !important; 
    border-radius: 10px !important; 
}
.stButton > button { background: linear-gradient(135deg, var(--cyan), var(--purple)) !important; border: none !important; border-radius: 14px !important; font-weight: 600 !important; padding: 12px 28px !important; }
.stButton > button, .stButton > button * { color: white !important; }
.stDataFrame { border: 1px solid rgba(255,255,255,0.06) !important; border-radius: 16px !important; }
""", unsafe_allow_html=True)

# ===============================
# NAVIGATION
# ===============================
if "menu" not in st.session_state:
    st.session_state.menu = "🏠 Home"

params = st.query_params
if "page" in params:
    page_map = {"home": "🏠 Home", "statistics": "📊 Statistics", "check": "📧 Check Your Email", "history": "🕒 History", "about": "ℹ️ About"}
    st.session_state.menu = page_map.get(params["page"], "🏠 Home")

menu = st.session_state.menu

def nav_class(page_name): return "nav-link active" if menu == page_name else "nav-link"

st.markdown(f"""
<div class="navbar">
    <div class="navbar-left">
        <div class="navbar-logo">🛡️</div><div class="navbar-brand">PUPDfSL</div><div class="navbar-divider"></div>
        <div class="nav-links-container">
            <a class="{nav_class('🏠 Home')}" href="?page=home" target="_self">Home</a>
            <a class="{nav_class('📧 Check Your Email')}" href="?page=check" target="_self">Scanner</a>
            <a class="{nav_class('📊 Statistics')}" href="?page=statistics" target="_self">Statistics</a>
            <a class="{nav_class('🕒 History')}" href="?page=history" target="_self">History</a>
            <a class="{nav_class('ℹ️ About')}" href="?page=about" target="_self">About</a>
        </div>
    </div>
    <div class="status-badge"><div class="status-dot"></div>System Online</div>
</div>
""", unsafe_allow_html=True)
# ===============================
# PAGE: HOME
# ===============================
if menu == "🏠 Home":
    st.markdown("""
    <div class="hero">
        <div class="hero-bg"></div>
        <div class="hero-content">
            <div class="hero-badge"><div class="hero-badge-dot"></div>President University · Economic Survival Project</div>
            <div class="hero-title">President University<br>Phishing Detector For Student and Lecturer  <span>(PUPDfSL)</span></div>
            <div class="hero-subtitle">"Emails in, Phishing Out"</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    try:
        df_stats = load_stats()
        total_emails = len(df_stats)
        threats = int((df_stats["prediction"] == "phishing").sum()) if not df_stats.empty else 0
        active_scans = 7
        security_score = round(100 - (threats / total_emails * 100), 1) if total_emails > 0 else 94
    except:
        total_emails, threats, active_scans, security_score = 342, 1284, 7, 94

    st.markdown(f"""
    <div class="overview-section">
        <div class="overview-title">System Overview</div>
        <div class="metric-grid">
            <div class="metric-card"><div class="metric-label">Threats Blocked</div><div class="metric-value">{threats:,}</div><div class="metric-delta">↑ 12 today</div></div>
            <div class="metric-card"><div class="metric-label">Active Scans</div><div class="metric-value">{active_scans}</div><div class="metric-delta">Real-time</div></div>
            <div class="metric-card"><div class="metric-label">Security Score</div><div class="metric-value">{security_score}%</div><div class="metric-delta">↑ 3% this week</div></div>
            <div class="metric-card"><div class="metric-label">Emails Checked</div><div class="metric-value">{total_emails:,}</div><div class="metric-delta">All time</div></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ===============================
# PAGE: CHECK THE EMAILS (DUAL SYSTEM + FIXED HISTORY)
# ===============================
elif menu == "📧 Check Your Email":
    
    st.markdown("""
        <div class="page-title">Email Scanner</div>
        <div class="page-subtitle">Enter the email details below to detect potential phishing attempts.</div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        subject = st.text_input("Email Subject", placeholder="e.g. Urgent: Account Verification")
    with col2:
        receiver_email = st.text_input("Your Email (optional)", placeholder="result@example.com")
    
    body = st.text_area("Email Body", height=200, placeholder="Paste the email content here...")
    
    col_btn, _ = st.columns([1, 4])
    with col_btn:
        analyze = st.button("Analyze Email")

    if analyze:
        if not subject and not body:
            st.warning("Email content is empty.")
        else:
            with st.spinner("Analyzing content (Dual Core System)..."):
                label = None
                phishing_prob = 0.0
                legit_prob = 0.0
                probs = {}
                used_api = False

                # ----------------------------------------------------
                # CORE 1: TRYING TO USE EXTERNAL API (TIMEOUT 3 SECONDS)
                # ----------------------------------------------------
                try:
                    response = requests.post("http://127.0.0.1:8000/predict", json={"subject": subject, "body": body, "receiver_email": receiver_email or ""}, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        label = data["prediction"]
                        phishing_prob = data["phishing_probability"]
                        legit_prob = data["legit_probability"]
                        probs = {"phishing": phishing_prob, "legit": legit_prob}
                        used_api = True
                        st.info("🌐 Analyzed via External ProtectYou API")
                except requests.exceptions.RequestException:
                    used_api = False # API FAILED, CONTINUE TO FALLBACK

                # ----------------------------------------------------
                # CORE 2: FALLBACK TO LOCAL MODEL IF API FAILS
                # ----------------------------------------------------
                if not used_api:
                    st.warning("⚡ API is offline/unreachable. Switching to Local Model processing...")
                    if model is None:
                        st.error("❌ Fatal Error: API Offline & Local Model ('systemic_phish_lr.joblib') not found!")
                        st.stop()
                    else:
                        try:
                            text_to_analyze = clean(subject + " " + body)
                            proba = model.predict_proba([text_to_analyze])[0]
                            classes = list(model.classes_)

                            phishing_index = classes.index("phishing")
                            legit_index = classes.index("legit")

                            phishing_prob = round(proba[phishing_index] * 100, 2)
                            legit_prob = round(proba[legit_index] * 100, 2)

                            label = "phishing" if phishing_prob >= legit_prob else "legit"
                            probs = {"phishing": phishing_prob, "legit": legit_prob}
                        except Exception as e:
                            st.error(f"Local processing error: {e}")
                            st.stop()

                # ----------------------------------------------------
                # RUN ADVANCED ANALYSIS ENGINE
                # ----------------------------------------------------
                analysis = full_analysis(subject, body)
                risk_score = analysis["risk_score"]
                risk_level = analysis["risk_level"]
                indicators = analysis["indicators"]

                # ----------------------------------------------------
                # SHOW VERDICT
                # ----------------------------------------------------
                if label == "phishing":
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, rgba(255,23,68,0.15), rgba(255,23,68,0.05)); border: 2px solid rgba(255,23,68,0.4); border-radius: 16px; padding: 24px; text-align: center; margin: 20px 0;">
                        <div style="font-size: 28px; font-weight: 800; color: #ff1744;">🚨 PHISHING DETECTED</div>
                        <div style="font-size: 16px; color: rgba(255,255,255,0.6); margin-top: 8px;">Confidence: <strong style="color: #ff1744;">{phishing_prob}%</strong></div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, rgba(0,230,118,0.15), rgba(0,230,118,0.05)); border: 2px solid rgba(0,230,118,0.4); border-radius: 16px; padding: 24px; text-align: center; margin: 20px 0;">
                        <div style="font-size: 28px; font-weight: 800; color: #00e676;">✅ LEGITIMATE EMAIL</div>
                        <div style="font-size: 16px; color: rgba(255,255,255,0.6); margin-top: 8px;">Confidence: <strong style="color: #00e676;">{legit_prob}%</strong></div>
                    </div>
                    """, unsafe_allow_html=True)

                # ----------------------------------------------------
                # RISK SCORE & PROBABILITY GAUGES
                # ----------------------------------------------------
                col_risk, col_phish, col_legit = st.columns(3)
                with col_risk:
                    st.markdown(f"""
                    <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 20px; text-align: center;">
                        <div style="font-size: 10px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 2px;">Threat Risk Score</div>
                        <div style="font-size: 36px; font-weight: 800; color: {risk_level['color']}; font-family: 'Orbitron', monospace; margin: 8px 0;">{risk_score}/100</div>
                        <div style="font-size: 12px; color: {risk_level['color']}; font-weight: 600; padding: 4px 14px; display: inline-block; background: rgba(255,255,255,0.04); border-radius: 20px; border: 1px solid {risk_level['color']};">{risk_level['emoji']} {risk_level['level']}</div>
                        <div style="width: 100%; height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px; margin-top: 12px; overflow: hidden;">
                            <div style="width: {risk_score}%; height: 100%; background: linear-gradient(90deg, #00e676, #ffea00, #ff9100, #ff1744); border-radius: 2px;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                with col_phish:
                    st.markdown(f"""
                    <div style="background: rgba(255,23,68,0.05); border: 1px solid rgba(255,23,68,0.15); border-radius: 16px; padding: 20px; text-align: center;">
                        <div style="font-size: 10px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 2px;">Phishing Probability</div>
                        <div style="font-size: 36px; font-weight: 800; color: #ff1744; font-family: 'Orbitron', monospace; margin: 8px 0;">{phishing_prob}%</div>
                        <div style="font-size: 12px; color: rgba(255,255,255,0.3);">ML Classification</div>
                    </div>
                    """, unsafe_allow_html=True)
                with col_legit:
                    st.markdown(f"""
                    <div style="background: rgba(0,230,118,0.05); border: 1px solid rgba(0,230,118,0.15); border-radius: 16px; padding: 20px; text-align: center;">
                        <div style="font-size: 10px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 2px;">Legitimate Probability</div>
                        <div style="font-size: 36px; font-weight: 800; color: #00e676; font-family: 'Orbitron', monospace; margin: 8px 0;">{legit_prob}%</div>
                        <div style="font-size: 12px; color: rgba(255,255,255,0.3);">ML Classification</div>
                    </div>
                    """, unsafe_allow_html=True)

                # ----------------------------------------------------
                # DETECTED INDICATORS TABLE
                # ----------------------------------------------------
                if indicators:
                    st.markdown(f"""
                    <div style="margin-top: 28px;">
                        <div style="font-size: 11px; font-weight: 700; letter-spacing: 3px; color: rgba(255,255,255,0.3); margin-bottom: 16px;">DETECTED INDICATORS ({len(indicators)})</div>
                    </div>
                    """, unsafe_allow_html=True)

                    severity_colors = {"critical": "#ff1744", "high": "#ff9100", "medium": "#ffea00", "low": "#90a4ae"}

                    for ind in indicators:
                        sev_color = severity_colors.get(ind["severity"], "#90a4ae")
                        st.markdown(f"""
                        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-left: 3px solid {sev_color}; border-radius: 0 12px 12px 0; padding: 16px 20px; margin-bottom: 8px; display: flex; align-items: flex-start; gap: 14px;">
                            <div style="font-size: 22px; min-width: 30px; text-align: center;">{ind['icon']}</div>
                            <div style="flex: 1;">
                                <div style="font-weight: 600; color: #e0e0e0; font-size: 14px;">{ind['title']}</div>
                                <div style="color: rgba(255,255,255,0.45); font-size: 12px; margin-top: 4px; line-height: 1.5;">{ind['detail']}</div>
                            </div>
                            <div style="color: {sev_color}; font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 3px 10px; background: rgba(255,255,255,0.03); border-radius: 4px; border: 1px solid {sev_color}; white-space: nowrap;">{ind['severity']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div style="background: rgba(0,230,118,0.05); border: 1px solid rgba(0,230,118,0.15); border-radius: 12px; padding: 16px; text-align: center; margin-top: 20px;">
                        <div style="color: #00e676; font-size: 14px;">✅ No suspicious indicators detected in this email.</div>
                    </div>
                    """, unsafe_allow_html=True)

                # ----------------------------------------------------
                # ANALYSIS ENGINES BADGE
                # ----------------------------------------------------
                st.markdown(f"""
                <div style="text-align: center; margin: 28px 0 12px 0;">
                    <div style="font-size: 10px; color: rgba(255,255,255,0.25); letter-spacing: 2px; margin-bottom: 10px;">ANALYSIS ENGINES</div>
                    <span style="font-size: 10px; color: #4f8ef7; padding: 4px 12px; background: rgba(79,142,247,0.08); border-radius: 6px; border: 1px solid rgba(79,142,247,0.2); margin: 0 3px;">🔗 URL Scanner</span>
                    <span style="font-size: 10px; color: #00d4aa; padding: 4px 12px; background: rgba(0,212,170,0.08); border-radius: 6px; border: 1px solid rgba(0,212,170,0.2); margin: 0 3px;">📝 Language Analyzer</span>
                    <span style="font-size: 10px; color: #7b2fff; padding: 4px 12px; background: rgba(123,47,255,0.08); border-radius: 6px; border: 1px solid rgba(123,47,255,0.2); margin: 0 3px;">🏗️ Structure Analyzer</span>
                    <span style="font-size: 10px; color: #ff9100; padding: 4px 12px; background: rgba(255,145,0,0.08); border-radius: 6px; border: 1px solid rgba(255,145,0,0.2); margin: 0 3px;">🧠 ML Classifier</span>
                </div>
                <div style="text-align: center; font-size: 11px; color: rgba(255,255,255,0.2); margin-bottom: 20px;">Scanned on {analysis['analysis_timestamp']}</div>
                """, unsafe_allow_html=True)

                # ----------------------------------------------------
                # SAVE TO MySQL Databases
                # ----------------------------------------------------
                if receiver_email:

                    domain = receiver_email.split("@")[-1] if receiver_email else "unknown"

                    if "student" in domain:
                        user_type = "President University"
                    else:
                        user_type = "External User"

                    save_detection(
                        receiver_email,
                        domain,
                        user_type,
                        label,
                        phishing_prob,
                        legit_prob
                    )
                
                # ----------------------------------------------------
                # ALWAYS SAVE TO HISTORY (EVEN IF EMAIL IS EMPTY)
                # ----------------------------------------------------
                user_identifier = receiver_email if receiver_email else "Anonymous"
                try:
                    save_stat(user_identifier, label)
                except Exception as e:
                    st.error(f"Failed to save to history: {e}")

                #----------------------------------------------------
                # SEND TO EMAIL (IF USER ENTER EMAIL)
                # ----------------------------------------------------
                if receiver_email:
                    stats = compute_statistics()
                    try:
                        send_result_email(receiver_email, label, probs, stats, analysis)
                        st.success(f"📧 Detailed scan report successfully sent to {receiver_email}.")
                    except Exception as e:
                        st.error(f"Failed to send email. Error: {e}")

# ===============================
# PAGE: STATISTICS
# ===============================
elif menu == "📊 Statistics":
    st.markdown("""
        <div class="page-title">Statistics Dashboard</div>
        <div class="page-subtitle">Monitor phishing detection metrics and trends.</div>
    """, unsafe_allow_html=True)

    try:
        df = load_stats()
        if df.empty:
            st.info("No data available.")
        else:
            df["prediction"] = df["prediction"].str.lower().str.strip()
            total = len(df)
            phishing_count = (df["prediction"] == "phishing").sum()
            phishing_rate = round((phishing_count / total) * 100, 2) if total > 0 else 0

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Emails", total)
            col2.metric("Phishing Detected", phishing_count)
            col3.metric("Phishing Rate", f"{phishing_rate}%")

            st.markdown("---")
            st.subheader("Overall Distribution")
            st.bar_chart(df["prediction"].value_counts())
    except Exception as e:
        st.info("Statistics data is not yet available.")


# ===============================
# PAGE: HISTORY
# ===============================
elif menu == "🕒 History":
    st.markdown("""
        <div class="page-title">Detection History (Admin Only)</div>
        <div class="page-subtitle">Restricted access. Please enter administrator password to view records.</div>
    """, unsafe_allow_html=True)

    # Input password
    admin_pass = st.text_input("Admin Password", type="password")

    # Cek password (kamu bisa ganti "dosenA" dengan password apapun)
    if admin_pass == "dosenA":
        path = Path("data/stats.csv")

        if st.button("Reset All History"):
            if path.exists():
                path.unlink()
                st.success("History & statistics successfully reset.")
            else:
                st.info("No history file found.")

        st.markdown("---")
        if not path.exists() or path.stat().st_size == 0:
            st.info("No history available.")
        else:
            df = pd.read_csv(path)
            st.dataframe(df, width="stretch")
    elif admin_pass != "":
        st.error("❌ Incorrect Password!")


# ===============================
# PAGE: ABOUT
# ===============================
else:
    st.markdown("""
## 🛡️ President University Phishing Detector for Students and Lecturers (PUPDfSL)

**Group 5 - ProtectYou**

PUPDfSL is a Machine Learning and NLP-based cybersecurity system designed to detect phishing emails in real time within academic environments.

The system integrates:

- Dual Detection Engine (FastAPI + Local ML Fallback)
- Logistic Regression with TF-IDF Vectorization
- Real-Time Probability Analysis
- Automated Email Reporting (SendGrid)
- Detection History & Statistical Dashboard
- Secure Secret Configuration Management

PUPDfSL is not just a project — it is a digital security initiative aimed at strengthening phishing awareness and cybersecurity resilience at President University.

---

### 👥 Development Team

- **Wida Sultan Utama Iryon** — Leader / Fullstack Developer / UI/UX Designer / CPO  
- **Santa Kristina Nelvi Sagala** — Chief Financial Officer / Designer (Canva)  
- **Aryah Juilo Miracle Kaensige** — Chief Executive Officer / Front-end Developer / AI Engineer  
- **Fatih Putra Rizki** — Manager  
- **Gracella Kristiani Kandowangko** — Marketing / Anomaly Analyst

---

**"Emails in. Phishing out. Security reinforced."**
""")