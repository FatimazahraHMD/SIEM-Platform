import os
import time
from datetime import datetime, timezone
from config import EXTRACT_DIR, HTTP_LOG_PATH, INDEX_NAME, POLL_INTERVAL
from elastic_client import connect
from mailer import send_email
from xss_rules import (
    decode_body, scan_fields, extract_fuid_from_filename, get_source_ip,
    parse_http_log_line, scan_uri,
)

def index_alert(es, source_ip, field_name, pattern_name, payload, source, subtype):
    if es is None:
        return
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "xss",
        "alert_subtype": subtype,
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

def process_stored_file(es, filepath):
    filename = os.path.basename(filepath)
    try:
        with open(filepath, "r", errors="ignore") as f:
            raw_content = f.read()
    except Exception as e:
        print(f"[ERREUR] Lecture {filename} :", e)
        return

    fields = decode_body(raw_content)
    findings = scan_fields(fields)
    if not findings:
        return

    fuid = extract_fuid_from_filename(filename)
    source_ip = get_source_ip(fuid)

    for field_name, pattern_name, payload in findings:
        print(f"[ALERTE XSS STOCKÉ] {filename} | IP={source_ip} | champ={field_name} | motif={pattern_name}")
        index_alert(es, source_ip, field_name, pattern_name, payload, filename, "stored")
        send_email(source_ip, field_name, payload, pattern_name, filename, "stored")

def process_http_line(es, line):
    parsed = parse_http_log_line(line)
    if not parsed:
        return
    source_ip, uri = parsed
    findings = scan_uri(uri)

    if uri.startswith("/welcome"):
        subtype, label = "dom", "DOM-BASED"
    else:
        subtype, label = "reflected", "REFLECHI"

    for pattern_name, payload in findings:
        print(f"[ALERTE XSS {label}] uri={uri} | IP={source_ip} | motif={pattern_name}")
        index_alert(es, source_ip, "uri", pattern_name, payload, "http.log", subtype)
        send_email(source_ip, "uri", payload, pattern_name, "http.log", subtype)
def main():
    print(" XSSDetector ")
    es = connect()

    if not os.path.isdir(EXTRACT_DIR):
        print(f"[ERREUR] Dossier {EXTRACT_DIR} introuvable.")
        return

    processed = set(os.listdir(EXTRACT_DIR))
    print(f"[INFO] {len(processed)} fichier(s) ignoré(s) au démarrage.")

    http_file = open(HTTP_LOG_PATH, "r")
    http_file.seek(0, 2)  # se positionne à la fin
    print("[INFO] En attente de nouvelles requêtes...\n")

    try:
        while True:
            # --- Stored XSS ---
            current_files = set(os.listdir(EXTRACT_DIR))
            for filename in current_files - processed:
                process_stored_file(es, os.path.join(EXTRACT_DIR, filename))
            processed = current_files

            # --- Reflected XSS ---
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
