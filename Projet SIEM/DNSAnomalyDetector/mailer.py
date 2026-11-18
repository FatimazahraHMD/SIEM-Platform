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

def send_email(victim_ip, domain, answers_seen):
    machine = get_machine_name(victim_ip)
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_TO
    msg["Subject"] = "Alerte DNS Spoofing détectée"

    answers_text = "\n".join(f"  - {a}" for a in answers_seen)
    body = f"""
Une anomalie DNS a été détectée (réponses incohérentes pour la même requête),
signature typique d'une tentative de DNS Spoofing.

Machine victime : {machine}
Adresse IP : {victim_ip}
Domaine concerné : {domain}

Réponses distinctes observées pour cette même requête :
{answers_text}

Date : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Action recommandée :
Vérifiez l'intégrité du trafic DNS et la présence éventuelle d'un
positionnement en interception (ARP Poisoning) sur le réseau.
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
