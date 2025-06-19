from collections import defaultdict
import time

ICMP_COUNTER = defaultdict(list)

def detect_icmp_flood(packet, threshold_config):
    if packet.haslayer("ICMP"):
        src_ip = packet("IP").src
        now = time.time()

        ICMP_COUNTER[src_ip].append(now)
        window = threshold_config["window_seconds"]
        count = threshold_config["count"]

        ICMP_COUNTER[src_ip] = [t for t in ICMP_COUNTER[src_ip] if now - t <= window]

        if len(ICMP_COUNTER[src_ip]) >= count:
            return True
    return False
