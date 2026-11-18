import time
from datetime import datetime, timezone
from config import EVE_LOG_PATH, INDEX_NAME, POLL_INTERVAL
from elastic_client import connect
from mailer import send_email
from dns_rules import parse_dns_events, AnomalyDetector

def index_alert(es, victim_ip, domain, answers_seen):
    if es is None:
        return
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "dns_spoofing",
        "victim_ip": victim_ip,
        "domain": domain,
        "answers_seen": answers_seen,
    }
    try:
        es.index(index=INDEX_NAME, document=doc)
        print(f"[OK] Alerte indexée dans '{INDEX_NAME}'.")
    except Exception as e:
        print("[ERREUR] Indexation :", e)

def main():
    print("DNSAnomalyDetector")
    es = connect()
    detector = AnomalyDetector()

    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, 2)  # se positionne à la fin du fichier
        print("[INFO] En attente de nouvelles réponses DNS...\n")

        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(POLL_INTERVAL)
                    continue

                dns_event = parse_dns_events(line)
                if not dns_event:
                    continue
                result = detector.check(dns_event)
                if result:
                    print(f"[ALERTE DNS] domaine={result['domain']} | victime={result['victim_ip']} | réponses={result['answers_seen']}")
                    index_alert(es, result["victim_ip"], result["domain"], result["answers_seen"])
                    send_email(result["victim_ip"], result["domain"], result["answers_seen"])

        except KeyboardInterrupt:
            print("\n[INFO] Arrêt.")

if __name__ == "__main__":
    main()
