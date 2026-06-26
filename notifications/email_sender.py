import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
load_dotenv()

def send_critical_alerts(alerts, session_summary=""):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    recipient = os.getenv("ALERT_EMAIL")
    if not all([smtp_user, smtp_pass, recipient]):
        print("Email neconfigurat - skip")
        return

    critical = [a for a in alerts if a.get("severity") == "CRITICAL"]
    if not critical:
        return


    subject = "[IDS ALERT] " + str(len(critical)) + " alerte CRITICAL detectate"

    alert_lines = ""
    for a in critical:
        alert_lines += "\n  Tip: " + str(a.get("type", ""))
        alert_lines += "\n  IP Sursa: " + str(a.get("src_ip", "-"))
        alert_lines += "\n  Detalii: " + str(a.get("detail", ""))
        ts = a.get("timestamp", "")
        try:
            from datetime import datetime
            ts = datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        alert_lines += "\n  Timestamp: " + str(ts)
        alert_lines += "\n"

    body = "IDS Dashboard - Alerte de securitate\n\n"
    body += str(len(critical)) + " alerte CRITICAL detectate:\n"
    body += alert_lines
    if session_summary:
        body += "\nAnaliza AI sesiune:\n" + session_summary + "\n"
    body += "\n---\nIDS Dashboard"

    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, recipient, msg.as_string())
        server.quit()
        print("Email trimis: " + str(len(critical)) + " alerte CRITICAL")
    except Exception as e:
        print("Eroare email: " + str(e))
