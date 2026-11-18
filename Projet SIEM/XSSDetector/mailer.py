import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_ADDRESS, EMAIL_PASSWORD, EMAIL_TO

def get_machine_name(ip):
    machines = {
        "192.168.10.20": "Windows",
        "192.168.10.10": "Kali Linux",
        "192.168.10.1": "CentOS"
    }
    return machines.get(ip, "Machine inconnue")

def send_email(source_ip, field_name, payload, pattern_name, filename, subtype="stored"):
    machine = get_machine_name(source_ip)
    labels = {"stored": "Stocké", "reflected": "Réfléchi", "dom": "DOM-based"}
    label = labels.get(subtype, subtype)
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_TO
    msg["Subject"] = f"Alerte XSS {label} détectée"

    body = f"""
Une tentative d'injection XSS ({label}) a été détectée.

Machine source : {machine}
Adresse IP : {source_ip}
Champ concerné : {field_name}
Motif détecté : {pattern_name}
Payload : {payload}
Fichier source : {filename}
Date : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    msg.attach(MIMEText(body, "plain"))
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, EMAIL_TO, msg.as_string())
        server.quit()
        print("[OK] Email envoyé.")
    except Exception as e:
        print("[ERREUR] Email :", e)
