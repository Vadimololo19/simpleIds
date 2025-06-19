# ids/utils/logger.py
import json
from datetime import datetime
import os

# Путь к папке с логами
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

ALERT_LOG_PATH = os.path.join(LOG_DIR, "alerts.log")
UNKNOWN_LOG_PATH = os.path.join(LOG_DIR, "unknown_packets.log")
ALL_PACKETS_LOG_PATH = os.path.join(LOG_DIR, "all_packets.log")


def log_alert(alert):
    """Логирует сигнатуры атак (SYN_SCAN, ICMP_FLOOD и т.д.)"""
    try:
        with open(ALERT_LOG_PATH, "a") as f:
            entry = {
                "timestamp": str(datetime.now()),
                "type": alert.get("alert_type", "UNKNOWN"),
                "src_ip": alert["src_ip"],
                "dst_ip": alert["dst_ip"],
                "description": alert["description"]
            }
            f.write(json.dumps(entry) + "\n")
            f.flush()
    except Exception as e:
        print(f"[LOGGER ERROR] Не удалось записать alert: {e}")


def log_unknown_packet(packet):
    """Логирует неизвестные или неподдерживаемые пакеты"""
    try:
        entry = {
            "timestamp": str(datetime.now()),
            "type": "UNKNOWN_PACKET",
            "summary": packet.summary(),
            "raw": repr(packet)
        }
        with open(UNKNOWN_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
    except Exception as e:
        print(f"[LOGGER ERROR] Не удалось записать unknown packet: {e}")


def log_packet(packet):
    """Логирует ВСЕ пакеты"""
    try:
        entry = {
            "timestamp": str(datetime.now()),
            "type": "RAW_PACKET",
            "summary": packet.summary(),
            "raw": repr(packet)
        }
        with open(ALL_PACKETS_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
    except Exception as e:
        print(f"[LOGGER ERROR] Не удалось записать raw packet: {e}")
