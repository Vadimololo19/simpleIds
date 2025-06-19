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
