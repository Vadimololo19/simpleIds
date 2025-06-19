from ids.utils.logger import log_alert
from datetime import datetime

def handler_alert(alert_type, packet):
    try:
        print("[DEBUG] handler_alert вызван")

        # Защита от отсутствующих слоёв
        if not (packet.haslayer("IP") or packet.haslayer("IPv6")):
            print("[ERROR] Пакет не содержит поддерживаемые сетевые протоколы")
            return

        src_ip = dst_ip = "unknown"
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
        elif packet.haslayer("IPv6"):
            src_ip = packet["IPv6"].src
            dst_ip = packet["IPv6"].dst

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        message = {
            "timestamp": timestamp,
            "alert_type": alert_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "description": ""
        }

        if alert_type == "SYN_SCAN":
            message["description"] = f"Potential SYN Scan detected from {src_ip} to {dst_ip}"
            if packet.haslayer("TCP"):
                message["dport"] = packet["TCP"].dport
        elif alert_type == "ICMP_FLOOD":
            message["description"] = f"Potential ICMP Flood detected from {src_ip} to {dst_ip}"

        print("[DEBUG] Сообщение для лога:", message)
        print("[DEBUG] Вызываю log_alert...")
        log_alert(message)
        print("[DEBUG] Лог успешно записан")

    except Exception as e:
        print(f"[HANDLER ERROR] Ошибка в handler_alert: {e}")
