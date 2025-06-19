from ids.utils.logger import log_alert
from datetime import datetime

def handler_alert(alert_type, packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst

    message = {
        "timestamp": timestamp,
        "alert_type": alert_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "description": ""
    }

    if alert_type == "SYN_SCAN":
        message["description"] = f"Potential SYN Scan detected on {src_ip} to {dst_ip}"
        message["dport"] = packet["TCP"].dport
    elif alert_type == "ICMP_FLOOD":
        message["description"] = f"Potential ICMP Flood detected on {src_ip} to {dst_ip}"
    
    
    print(f"[!] ALERT: {message['description']}")
    print("-" * 40)
    log_alert(message)
