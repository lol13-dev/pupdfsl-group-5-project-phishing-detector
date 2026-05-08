import streamlit as st
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime


def send_result_email(receiver_email, label, probs, stats, analysis=None):
    """
    Send a professional, detailed phishing detection result via SendGrid.
    """

    try:
        SENDGRID_API_KEY = st.secrets["SENDGRID_API_KEY"]
        SENDER_EMAIL = st.secrets["EMAIL_SENDER"]
    except KeyError as e:
        raise Exception(f"Missing secret configuration: {e}")

    prob_value = probs.get(label, 0)
    timestamp = datetime.now().strftime("%B %d, %Y at %H:%M:%S")

    # Determine verdict styling
    if label == "phishing":
        verdict_color = "#ff1744"
        verdict_bg = "#2d0a0a"
        verdict_border = "#ff1744"
        verdict_text = "⚠️ PHISHING DETECTED"
        verdict_desc = "This email has been identified as a <strong>potential phishing attempt</strong>. We strongly recommend that you do NOT click any links, download attachments, or reply to this email."
    else:
        verdict_color = "#00e676"
        verdict_bg = "#0a2d1a"
        verdict_border = "#00e676"
        verdict_text = "✅ LEGITIMATE EMAIL"
        verdict_desc = "This email appears to be <strong>legitimate</strong> based on our analysis. However, always exercise caution with links and attachments from unknown senders."

    # Build indicators HTML
    indicators_html = ""
    risk_html = ""

    if analysis and analysis.get("indicators"):
        risk_score = analysis.get("risk_score", 0)
        risk_level = analysis.get("risk_level", {})

        risk_html = f"""
        <div style="background: #1a1a2e; border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid #2a2a4a;">
            <div style="font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px;">Threat Risk Score</div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="font-size: 36px; font-weight: 800; color: {risk_level.get('color', '#fff')}; font-family: 'Courier New', monospace;">{risk_score}/100</div>
                <div style="font-size: 14px; color: {risk_level.get('color', '#fff')}; font-weight: 600; padding: 4px 16px; background: rgba(255,255,255,0.05); border-radius: 20px; border: 1px solid {risk_level.get('color', '#333')};">{risk_level.get('emoji', '')} {risk_level.get('level', 'N/A')}</div>
            </div>
            <div style="width: 100%; height: 6px; background: #2a2a4a; border-radius: 3px; margin-top: 12px; overflow: hidden;">
                <div style="width: {risk_score}%; height: 100%; background: linear-gradient(90deg, #00e676, #ffea00, #ff9100, #ff1744); border-radius: 3px;"></div>
            </div>
        </div>
        """

        indicators_rows = ""
        severity_colors = {"critical": "#ff1744", "high": "#ff9100", "medium": "#ffea00", "low": "#90a4ae"}

        for ind in analysis["indicators"]:
            sev_color = severity_colors.get(ind["severity"], "#90a4ae")
            indicators_rows += f"""
            <tr>
                <td style="padding: 12px 16px; border-bottom: 1px solid #2a2a4a; font-size: 18px; text-align: center; width: 40px;">{ind['icon']}</td>
                <td style="padding: 12px 16px; border-bottom: 1px solid #2a2a4a;">
                    <div style="font-weight: 600; color: #e0e0e0; font-size: 14px;">{ind['title']}</div>
                    <div style="color: #888; font-size: 12px; margin-top: 4px;">{ind['detail']}</div>
                </td>
                <td style="padding: 12px 16px; border-bottom: 1px solid #2a2a4a; text-align: center;">
                    <span style="color: {sev_color}; font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 3px 10px; background: rgba(255,255,255,0.04); border-radius: 4px; border: 1px solid {sev_color};">{ind['severity']}</span>
                </td>
            </tr>
            """

        indicators_html = f"""
        <div style="margin: 20px 0;">
            <div style="font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 14px;">Detected Indicators ({len(analysis['indicators'])})</div>
            <table style="width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 12px; overflow: hidden; border: 1px solid #2a2a4a;">
                <thead>
                    <tr style="background: #12122a;">
                        <th style="padding: 10px; color: #666; font-size: 11px; text-align: center;">Icon</th>
                        <th style="padding: 10px; color: #666; font-size: 11px; text-align: left;">Indicator</th>
                        <th style="padding: 10px; color: #666; font-size: 11px; text-align: center;">Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {indicators_rows}
                </tbody>
            </table>
        </div>
        """

    # Build the full professional email
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; background-color: #0a0e17; font-family: 'Segoe UI', Arial, sans-serif;">
        <div style="max-width: 640px; margin: 0 auto; background: #0f1320; border-radius: 16px; overflow: hidden; border: 1px solid #1e2235;">

            <!-- HEADER -->
            <div style="background: linear-gradient(135deg, #0d1b3e 0%, #1a0a3e 100%); padding: 32px; text-align: center; border-bottom: 1px solid #2a2a4a;">
                <div style="display: inline-block; background: linear-gradient(135deg, #4f8ef7, #7b2fff); padding: 10px 16px; border-radius: 12px; margin-bottom: 16px;">
                    <span style="font-size: 24px;">🛡️</span>
                </div>
                <div style="font-size: 22px; font-weight: 800; color: white; letter-spacing: 4px; font-family: 'Courier New', monospace;">PUPDfSL</div>
                <div style="font-size: 11px; color: #666; margin-top: 4px; letter-spacing: 1px;">President University Phishing Detector</div>
            </div>

            <!-- BODY -->
            <div style="padding: 32px;">

                <!-- SCAN TIMESTAMP -->
                <div style="font-size: 11px; color: #555; margin-bottom: 20px;">
                    📅 Scan completed on: {timestamp}
                </div>

                <!-- VERDICT -->
                <div style="background: {verdict_bg}; border: 2px solid {verdict_border}; border-radius: 14px; padding: 24px; text-align: center; margin-bottom: 24px;">
                    <div style="font-size: 24px; font-weight: 800; color: {verdict_color}; margin-bottom: 8px;">{verdict_text}</div>
                    <div style="font-size: 13px; color: #aaa; line-height: 1.6;">{verdict_desc}</div>
                </div>

                <!-- PROBABILITY -->
                <div style="display: flex; gap: 12px; margin-bottom: 24px;">
                    <div style="flex: 1; background: #1a1a2e; border-radius: 12px; padding: 18px; text-align: center; border: 1px solid #2a2a4a;">
                        <div style="font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px;">Phishing</div>
                        <div style="font-size: 28px; font-weight: 700; color: #ff1744; font-family: 'Courier New', monospace; margin-top: 6px;">{probs.get('phishing', 0)}%</div>
                    </div>
                    <div style="flex: 1; background: #1a1a2e; border-radius: 12px; padding: 18px; text-align: center; border: 1px solid #2a2a4a;">
                        <div style="font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px;">Legitimate</div>
                        <div style="font-size: 28px; font-weight: 700; color: #00e676; font-family: 'Courier New', monospace; margin-top: 6px;">{probs.get('legit', 0)}%</div>
                    </div>
                </div>

                <!-- RISK SCORE -->
                {risk_html}

                <!-- INDICATORS -->
                {indicators_html}

                <!-- GLOBAL STATS -->
                <div style="background: #1a1a2e; border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid #2a2a4a;">
                    <div style="font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 14px;">Global Statistics</div>
                    <table style="width: 100%;">
                        <tr>
                            <td style="color: #aaa; font-size: 13px; padding: 4px 0;">Total Emails Scanned</td>
                            <td style="color: white; font-weight: 600; text-align: right; font-size: 13px;">{stats.get('total', 0)}</td>
                        </tr>
                        <tr>
                            <td style="color: #aaa; font-size: 13px; padding: 4px 0;">Phishing Detected</td>
                            <td style="color: #ff1744; font-weight: 600; text-align: right; font-size: 13px;">{stats.get('phishing', 0)}</td>
                        </tr>
                        <tr>
                            <td style="color: #aaa; font-size: 13px; padding: 4px 0;">Legitimate Emails</td>
                            <td style="color: #00e676; font-weight: 600; text-align: right; font-size: 13px;">{stats.get('legit', 0)}</td>
                        </tr>
                        <tr>
                            <td style="color: #aaa; font-size: 13px; padding: 4px 0;">Phishing Rate</td>
                            <td style="color: #ff9100; font-weight: 600; text-align: right; font-size: 13px;">{stats.get('phishing_rate', 0)}%</td>
                        </tr>
                    </table>
                </div>

                <!-- ENGINES -->
                <div style="text-align: center; margin: 20px 0;">
                    <div style="font-size: 10px; color: #555; letter-spacing: 1px; margin-bottom: 8px;">ANALYSIS ENGINES</div>
                    <div style="display: inline-flex; gap: 6px; flex-wrap: wrap; justify-content: center;">
                        <span style="font-size: 10px; color: #4f8ef7; padding: 4px 10px; background: rgba(79,142,247,0.1); border-radius: 6px; border: 1px solid rgba(79,142,247,0.2);">🔗 URL Scanner</span>
                        <span style="font-size: 10px; color: #00d4aa; padding: 4px 10px; background: rgba(0,212,170,0.1); border-radius: 6px; border: 1px solid rgba(0,212,170,0.2);">📝 Language Analyzer</span>
                        <span style="font-size: 10px; color: #7b2fff; padding: 4px 10px; background: rgba(123,47,255,0.1); border-radius: 6px; border: 1px solid rgba(123,47,255,0.2);">🏗️ Structure Analyzer</span>
                        <span style="font-size: 10px; color: #ff9100; padding: 4px 10px; background: rgba(255,145,0,0.1); border-radius: 6px; border: 1px solid rgba(255,145,0,0.2);">🧠 ML Classifier</span>
                    </div>
                </div>

            </div>

            <!-- FOOTER -->
            <div style="background: #0a0c15; padding: 24px 32px; border-top: 1px solid #1e2235; text-align: center;">
                <div style="font-size: 11px; color: #444; line-height: 1.8;">
                    This report was generated by <strong style="color: #4f8ef7;">PUPDfSL</strong> — President University Phishing Detector<br>
                    Group 5 · ProtectYou · Economic Survival Project<br>
                    <span style="font-style: italic;">"Emails in. Phishing out. Security reinforced."</span>
                </div>
            </div>

        </div>
    </body>
    </html>
    """

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=receiver_email,
        subject=f"PUPDfSL Scan Report: {verdict_text}",
        html_content=html_content
    )

    sg = SendGridAPIClient(SENDGRID_API_KEY)
    response = sg.send(message)

    if response.status_code >= 400:
        raise Exception(f"SendGrid error: {response.status_code}")

    return True