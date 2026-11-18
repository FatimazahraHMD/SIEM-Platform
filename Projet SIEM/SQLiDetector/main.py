import time
from datetime import datetime, timezone
from config import HTTP_LOG_PATH, INDEX_NAME, POLL_INTERVAL
from elastic_client import connect
from mailer import send_email
from sqli_rules import parse_http_log_line, scan_uri

def index_alert(es, source_ip, field_name, pattern_name, payload, source):
    if es is None:
        return
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "sql_injection",
        "source_ip": source_ip,
        "field": field_name,
        "matched_pattern": pattern_name,
        "payload": payload,
        "source_file": source,
    }
    try:
        es.index(index=INDEX_NAME, document=doc)
        print(f"[OK] Alerte indexée dans '{INDEX_NAME}'.")
    except Exception as e:
        print("[ERREUR] Indexation :", e)

def process_http_line(es, line):
    parsed = parse_http_log_line(line)
    if not parsed:
        return
    source_ip, uri = parsed
    findings = scan_uri(uri)
    for pattern_name, payload in findings:
        print(f"[ALERTE SQLi] uri={uri} | IP={source_ip} | motif={pattern_name}")
        index_alert(es, source_ip, "uri", pattern_name, payload, "http.log")
        send_email(source_ip, "uri", payload, pattern_name, "http.log")

def main():
    print("SQLiDetector")
    es = connect()

    http_file = open(HTTP_LOG_PATH, "r")
    http_file.seek(0, 2)  # se positionne à la fin
    print("[INFO] En attente de nouvelles requêtes...\n")

    try:
        while True:
            line = http_file.readline()
            if line:
                process_http_line(es, line)
            else:
                time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt.")
    finally:
        http_file.close()

if __name__ == "__main__":
    main()
