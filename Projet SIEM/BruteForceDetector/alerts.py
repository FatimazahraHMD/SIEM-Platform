from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import EMAIL_ADDRESS, EMAIL_PASSWORD, EMAIL_TO


def send_email(alert_type, ip, username, attempts):

    subject = f"[ALERTE] {alert_type} détectée"

    body = f"""
Une attaque de type {alert_type} a été détectée.

Date : {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}

Adresse IP source : {ip}

Utilisateur ciblé : {username}

Nombre de tentatives : {attempts}

Cette alerte a été générée automatiquement par BruteForceDetector.
"""

    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print("[EMAIL] Alerte envoyée avec succès.")

    except Exception as e:
        print(f"[ERREUR EMAIL] {e}")


def save_alert(es, alert_type, ip, username, attempts):

    alert = {
        "@timestamp": datetime.utcnow().isoformat(),
        "alert_type": alert_type,
        "source_ip": ip,
        "username": username,
        "attempts": attempts,
        "severity": "High"
    }

    es.index(
        index="alerts-bruteforce",
        document=alert
    )

    print(f"[ALERTE] Enregistrée dans Elasticsearch : {ip}")

    send_email(alert_type, ip, username, attempts)
