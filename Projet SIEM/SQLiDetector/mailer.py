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

def send_email(source_ip, field_name, payload, pattern_name, source):
    machine = get_machine_name(source_ip)
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_TO
    msg["Subject"] = "Alerte SQL Injection détectée"

    body = f"""
Une tentative d'injection SQL a été détectée.

Machine source : {machine}
Adresse IP : {source_ip}
Champ concerné : {field_name}
Motif détecté : {pattern_name}
Payload : {payload}
Fichier source : {source}
Date : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Action recommandée :
Vérifiez la requête concernée et assurez-vous que les paramètres
utilisateur sont correctement validés et paramétrés avant toute exécution SQL.
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
