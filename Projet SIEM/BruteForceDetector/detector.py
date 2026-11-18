from datetime import datetime, timedelta
from alerts import save_alert

# Mémorise les dernières alertes envoyées
last_alerts = {}


def detect_bruteforce(es, events):

    smb_ips = {}
    rdp_ips = {}

    for event in events:

        try:
            data = event["_source"]["winlog"]["event_data"]

            logon_type = data.get("LogonType")
            ip = data.get("IpAddress")
            username = data.get("TargetUserName", "Inconnu")

            # Ignorer les événements sans adresse IP
            if not ip or ip == "-":
                continue

            # SMB (LogonType 3)
            if logon_type == "3":

                if ip not in smb_ips:
                    smb_ips[ip] = {
                        "count": 0,
                        "username": username
                    }

                smb_ips[ip]["count"] += 1

            # RDP (LogonType 10)
            elif logon_type == "10":

                if ip not in rdp_ips:
                    rdp_ips[ip] = {
                        "count": 0,
                        "username": username
                    }

                rdp_ips[ip]["count"] += 1

        except Exception:
            continue

    # Détection SMB
    for ip, info in smb_ips.items():

        if info["count"] >= 5:

            key = ("SMB", ip)
            now = datetime.now()

            if key not in last_alerts or now - last_alerts[key] > timedelta(minutes=1):

                print(f"[ALERTE SMB] Brute Force Réseau détectée depuis {ip} ({info['count']} tentatives)")

                save_alert(
                    es,
                    "SMB Brute Force",
                    ip,
                    info["username"],
                    info["count"]
                )

                last_alerts[key] = now

    # Détection RDP
    for ip, info in rdp_ips.items():

        if info["count"] >= 5:

            key = ("RDP", ip)
            now = datetime.now()

            if key not in last_alerts or now - last_alerts[key] > timedelta(minutes=1):

                print(f"[ALERTE RDP] Brute Force RDP détectée depuis {ip} ({info['count']} tentatives)")

                save_alert(
                    es,
                    "RDP Brute Force",
                    ip,
                    info["username"],
                    info["count"]
                )

                last_alerts[key] = now
