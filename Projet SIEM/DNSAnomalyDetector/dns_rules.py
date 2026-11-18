import json
import time
from config import TIME_WINDOW

def parse_dns_events(line):
    try:
        event = json.loads(line)
    except ValueError:
        return None

    if event.get("event_type") != "dns":
        return None
    dns = event.get("dns", {})
    kind = dns.get("type")
    if kind not in ("query", "answer"):
        return None

    key = (dns.get("id"), dns.get("rrname"))
    result = {"type": kind, "domain": dns.get("rrname"), "key": key, "time": time.time()}

    if kind == "query":
        result["victim_ip"] = event.get("src_ip")
    else:
        ips = sorted(a["rdata"] for a in dns.get("answers", []) if a.get("rrtype") == "A")
        if not ips:
            return None
        result["ips"] = tuple(ips)

    return result


class AnomalyDetector:
    def __init__(self):
        self.query_victim = {}
        self.last_answer = {}

    def check(self, event):
        key = event["key"]
        now = event["time"]

        if event["type"] == "query":
            self.query_victim[key] = (event["victim_ip"], now)
            return None

        victim_ip, query_ts = self.query_victim.get(key, ("Inconnue", 0))
        prev = self.last_answer.get(key)
        anomaly = None
        if prev:
            prev_ips, prev_ts = prev
            no_new_query_since = query_ts <= prev_ts
            if no_new_query_since and prev_ips != event["ips"] and now - prev_ts <= TIME_WINDOW:
                anomaly = {"victim_ip": victim_ip, "domain": event["domain"],
                           "answers_seen": [list(prev_ips), list(event["ips"])]}

        self.last_answer[key] = (event["ips"], now)
        return anomaly
