import time

from elastic_client import connect
from search_logs import get_failed_logins
from detector import detect_bruteforce

print("[INFO] Détecteur de Brute Force démarré...")

es = connect()

if es is None:
    print("[ERREUR] Impossible de se connecter à Elasticsearch.")
    exit(1)

while True:
    events = get_failed_logins(es)

    if events:
        detect_bruteforce(es, events)
    else:
        print("[INFO] Aucun nouvel événement.")

    time.sleep(30)
