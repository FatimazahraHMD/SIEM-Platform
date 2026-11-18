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


def send_email(ip, old_mac, new_mac):

    machine = get_machine_name(ip)

    msg = MIMEMultipart()

    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_TO
    msg["Subject"] = " Alerte ARP Poisoning détectée"

    body = f"""
Une attaque ARP Poisoning a été détectée sur le réseau.

Machine concernée : {machine}

Adresse IP : {ip}

Ancienne adresse MAC : {old_mac}
Nouvelle adresse MAC : {new_mac}

Date de détection : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Action recommandée :
Vérifiez immédiatement le réseau afin de confirmer l'intégrité des associations ARP.
"""

    msg.attach(MIMEText(body, "plain"))

    try:

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        server.login(
            EMAIL_ADDRESS,
            EMAIL_PASSWORD
        )

        server.sendmail(
            EMAIL_ADDRESS,
            EMAIL_TO,
            msg.as_string()
        )

        server.quit()

    except Exception as e:

        print("[ERREUR] Email :", e)
