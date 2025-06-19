from collections import defaultdict
import time

SYN_COUNTER = defaultdict(list)

def detect_syn_scan(packet, threshold_config):
    if packet.haslayer("TCP") and packet.haslayer("IP"):
        if packet["TCP"].flags == "S" or packet["TCP"].flags == "SA":
            src_ip = packet["IP"].src
            now = time.time()

            SYN_COUNTER[src_ip].append(now)
            window = threshold_config["window_seconds"]
            count = threshold_config["count"]

            SYN_COUNTER[src_ip] = [t for t in SYN_COUNTER[src_ip] if now - t <= window]

            if len(SYN_COUNTER[src_ip]) >= count:
                return True
    return False

