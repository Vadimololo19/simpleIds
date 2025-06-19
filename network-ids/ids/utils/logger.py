import json
from datetime import datetime

def log_alert(alert):
    with open("alerts.log", "a") as f:
        entry = {
            "timestamp": str(datetime.now()),
            "type": alert["type"],
            "src_ip": alert["src_ip"],
            "dst_ip": alert["dst_ip"],
            "description": alert["description"]
        }
        f.write(json.dumps(entry) + "\n")
