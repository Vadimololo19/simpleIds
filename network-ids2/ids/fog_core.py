from scapy.all import AsyncSniffer
from ids.detectors.syn_scan import detect_syn_scan
from ids.detectors.icmp_flood import detect_icmp_flood
from ids.alerts.alert_manager import handler_alert


def packet_handler(packet, thresholds):
    try:
        # Проверяем, есть ли в пакете IP или ICMP
        if not (packet.haslayer("IP") or packet.haslayer("ICMP")):
            return  # Игнорируем ненужные/битые пакеты

        # Обработка SYN сканирования
        if detect_syn_scan(packet, thresholds["syn_scan"]):
            handler_alert("SYN_SCAN", packet)

        # Обработка ICMP flood
        if detect_icmp_flood(packet, thresholds["icmp_flood"]):
            handler_alert("ICMP_FLOOD", packet)

    except Exception as e:
        print(f"[PACKET ERROR] {e} | Тип пакета: {packet.__class__.__name__}")
        # Для диагностики можно раскомментировать:
        #packet.show()
        handler_alert("UNKNOWN", packet)


def start_ids(config):
    interface = config["interface"]
    thresholds = config["thresholds"]

    print(f"[*] Starting Network IDS on interface: {interface}")
    print(f"[*] Listening for suspicious activity...")

    sniffer = AsyncSniffer(
        iface=interface,
        prn=lambda pkt: packet_handler(pkt, thresholds),
        store=False,
        filter="tcp or icmp"
    )

    sniffer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
        sniffer.stop()
        sniffer.join()
        print("[*] IDS stopped.")
# core.py
from scapy.all import AsyncSniffer
from ids.detectors.syn_scan import detect_syn_scan
from ids.detectors.icmp_flood import detect_icmp_flood
from ids.alerts.alert_manager import handler_alert
from ids.utils.logger import log_unknown_packet, log_packet


def packet_handler(packet, thresholds):
    """
    Основной обработчик пакетов. Вызывается для каждого перехваченного пакета.
    """
    try:
        # 1. Логируем ВСЕ пакеты
        log_packet(packet)

        # 2. Проверяем, есть ли поддерживаемые слои (IP или ICMP)
        if not (packet.haslayer("IP") or packet.haslayer("ICMP")):
            print("[?] UNKNOWN PACKET")
            print(f"    Raw summary: {packet.summary()}")
            print("-" * 40)
            log_unknown_packet(packet)
            return

        # 3. Обнаружение SYN Scan
        if detect_syn_scan(packet, thresholds["syn_scan"]):
            print("[DEBUG] SYN_SCAN обнаружен")
            handler_alert("SYN_SCAN", packet)

        # 4. Обнаружение ICMP Flood
        if detect_icmp_flood(packet, thresholds["icmp_flood"]):
            print("[DEBUG] ICMP_FLOOD обнаружен")
            handler_alert("ICMP_FLOOD", packet)

    except Exception as e:
        print(f"[PACKET ERROR] {e} | Тип пакета: {packet.__class__.__name__}")
        print(f"    Raw summary: {packet.summary()}")
        print("-" * 40)


def start_ids(config):
    """
    Запускает IDS с заданными параметрами из конфигурации.
    """
    interface = config["interface"]
    thresholds = config["thresholds"]

    print(f"[*] Starting Network IDS on interface: {interface}")
    print(f"[*] Listening for suspicious activity...")

    sniffer = AsyncSniffer(
        iface=interface,
        prn=lambda pkt: packet_handler(pkt, thresholds),
        store=False,
        filter="tcp or icmp"
    )

    sniffer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
        sniffer.stop()
        sniffer.join()
        print("[*] IDS stopped.")
