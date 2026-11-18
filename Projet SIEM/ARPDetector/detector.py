from datetime import datetime

from mailer import send_email, get_machine_name

previous_table = {}
alert_sent = set()


def create_alert(ip, old_mac, new_mac):

    return {
        "@timestamp": datetime.utcnow().isoformat(),
        "event": {
            "kind": "alert",
            "category": "network",
            "type": "arp_poisoning",
            "severity": "high"
        },
        "host": {
            "name": get_machine_name(ip)
        },
        "source": {
            "ip": ip,
            "mac": old_mac
        },
        "destination": {
            "mac": new_mac
        },
        "message": f"ARP Poisoning détecté pour {ip}"
    }


def detect_arp_spoofing(es, current_table):

    global previous_table, alert_sent

    if not previous_table:
        previous_table = current_table.copy()
        return

    for ip, new_mac in current_table.items():

        if ip not in previous_table:
            continue

        old_mac = previous_table[ip]

        if old_mac != new_mac:

            if ip not in alert_sent:

                print("\n")
                print("[ALERTE] ARP Poisoning détecté")
                print(f"Machine      : {get_machine_name(ip)}")
                print(f"Adresse IP   : {ip}")
                print(f"Ancienne MAC : {old_mac}")
                print(f"Nouvelle MAC : {new_mac}")
                print("\n")

                es.index(
                    index="arp-alerts",
                    document=create_alert(ip, old_mac, new_mac)
                )

                print("[OK] Alerte envoyée vers Elasticsearch.")

                send_email(ip, old_mac, new_mac)

                print("[OK] Email envoyé.")

                alert_sent.add(ip)

        else:

            alert_sent.discard(ip)

    previous_table = current_table.copy()
