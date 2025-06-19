import asyncio
import threading
from telegram import Bot
from telegram.error import TelegramError
from scapy.all import AsyncSniffer, Packet

# Импорты детекторов
from ids.detectors.syn_scan import detect_syn_scan
from ids.detectors.icmp_flood import detect_icmp_flood
from ids.alerts.alert_manager import handler_alert

# Конфигурация бота и канала
BOT_TOKEN = "8022646991:AAG4CJXXrdBDSUm661ppGyCV81cTp791aVU"
CHANNEL_ID = -1002496841826
TOPIC_ID = 4272  # ID топика

# Глобальный event loop для отдельного потока
loop = None

def get_event_loop():
    global loop
    if loop is None:
        loop = asyncio.new_event_loop()

        # Запускаем event loop в фоновом потоке
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
    return loop


async def send_message_to_channel(bot_token: str, channel_id: str, topic_id: int, message_text: str):
    """Отправляет сообщение в Telegram."""
    try:
        bot = Bot(token=bot_token)
        await bot.send_message(
            chat_id=channel_id,
            text=message_text,
            message_thread_id=topic_id
        )
        return True
    except TelegramError as e:
        print(f"[Telegram Error] Не удалось отправить сообщение: {e}")
        return False


def async_send_message(message_text: str):
    """Безопасно отправляет сообщение в Telegram из любого потока."""
    loop = get_event_loop()
    asyncio.run_coroutine_threadsafe(
        send_message_to_channel(BOT_TOKEN, CHANNEL_ID, TOPIC_ID, message_text),
        loop
    )


def packet_handler(packet, thresholds):
    """Обработчик пакетов."""
    try:
        if not (packet.haslayer("IP") or packet.haslayer("ICMP")):
            msg = f"[?] UNKNOWN PACKET | Type: {packet.__class__.__name__}\nRaw summary: {packet.summary()}"
            print(msg)
            print("-" * 40)
            async_send_message(msg)
            return

        if detect_syn_scan(packet, thresholds["syn_scan"]):
            alert_msg = handler_alert("SYN_SCAN", packet)
            async_send_message(alert_msg)

        if detect_icmp_flood(packet, thresholds["icmp_flood"]):
            alert_msg = handler_alert("ICMP_FLOOD", packet)
            async_send_message(alert_msg)

    except Exception as e:
        error_msg = f"[PACKET ERROR] {e} | Тип пакета: {packet.__class__.__name__}\nRaw summary: {packet.summary()}"
        print(error_msg)
        print("-" * 40)
        async_send_message(error_msg)


def start_ids(config):
    """Запуск IDS-системы."""
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
