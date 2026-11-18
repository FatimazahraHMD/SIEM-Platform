import time

from elastic_client import connect
from arp_table import get_arp_table
from detector import detect_arp_spoofing

print("[INFO] ARP Detector démarré...")

es = connect()

if es is None:
    print("[ERREUR] Impossible de se connecter à Elasticsearch.")
    exit(1)

while True:

    arp_table = get_arp_table()

    detect_arp_spoofing(es, arp_table)

    time.sleep(5)
