import re
from urllib.parse import unquote_plus, parse_qsl

XSS_PATTERNS = [
    ("balise <script>", re.compile(r"<\s*script[^>]*>", re.IGNORECASE)),
    ("gestionnaire d'événement HTML", re.compile(
       r"on(error|load|click|mouseover|mouseout|focus|blur|change|submit|keyup|keydown)\s*=",
       re.IGNORECASE
    )),
    ("javascript: URI", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("balise <iframe>", re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE)),
    ("document.cookie", re.compile(r"document\s*\.\s*cookie", re.IGNORECASE)),
]

def decode_body(raw_text):
    try:
        pairs = parse_qsl(raw_text, keep_blank_values=True)
        return {k: unquote_plus(v) for k, v in pairs}
    except Exception:
        return {}

def scan_fields(fields):
    findings = []
    for field_name, value in fields.items():
        for pattern_name, pattern in XSS_PATTERNS:
            if pattern.search(value):
                findings.append((field_name, pattern_name, value))
    return findings

def extract_fuid_from_filename(filename):
    match = re.search(r"HTTP-([A-Za-z0-9]+)$", filename)
    return match.group(1) if match else None

import time

def get_source_ip(fuid, files_log_path="/var/log/zeek/logs/current/files.log", retries=3, delay=1):
    if not fuid:
        return "Inconnue"
    for _ in range(retries):
        try:
            with open(files_log_path, "r", errors="ignore") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    cols = line.rstrip("\n").split("\t")
                    if len(cols) > 2 and cols[1] == fuid:
                        return cols[2]
        except FileNotFoundError:
            pass
        time.sleep(delay)
    return "Inconnue"
from urllib.parse import unquote

def parse_http_log_line(line):
    """Extrait (source_ip, uri) d'une ligne http.log, ou None si non pertinente."""
    if line.startswith("#") or not line.strip():
        return None
    cols = line.rstrip("\n").split("\t")
    if len(cols) < 10:
        return None
    method, source_ip, uri = cols[7], cols[2], cols[9]
    if method != "GET":
        return None
    return source_ip, unquote(uri)


def scan_uri(uri):
    """Applique les mêmes motifs XSS à une URI décodée (Reflected XSS)."""
    findings = []
    for pattern_name, pattern in XSS_PATTERNS:
        if pattern.search(uri):
            findings.append((pattern_name, uri))
    return findings
