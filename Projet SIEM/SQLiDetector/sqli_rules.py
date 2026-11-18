import re
from urllib.parse import unquote_plus

SQLI_PATTERNS = [
    ("contournement OR '1'='1'", re.compile(r"'\s*or\s*'?\d\s*'?\s*=\s*'?\d", re.IGNORECASE)),
    ("UNION SELECT", re.compile(r"union\s+select", re.IGNORECASE)),
    ("commentaire SQL (--)", re.compile(r"--\s", re.IGNORECASE)),
    ("commentaire SQL (#)", re.compile(r"#", re.IGNORECASE)),
    ("point-virgule multi-requête", re.compile(r";\s*(drop|delete|insert|update)", re.IGNORECASE)),
    ("fonction SLEEP (time-based)", re.compile(r"sleep\s*\(", re.IGNORECASE)),
    ("extractvalue (error-based)", re.compile(r"extractvalue\s*\(", re.IGNORECASE)),
    ("injection booléenne (OR/AND '=')", re.compile(r"'\s*(or|and)\s*'?\d\s*'?\s*=\s*'?\d", re.IGNORECASE)),
    ("guillemet suspect suivi d'opérateur", re.compile(r"'\s*(or|and)\s+", re.IGNORECASE)),]


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
    return source_ip, unquote_plus(uri)


def scan_uri(uri):
    """Applique les motifs SQLi à une URI décodée."""
    findings = []
    for pattern_name, pattern in SQLI_PATTERNS:
        if pattern.search(uri):
            findings.append((pattern_name, uri))
    return findings
