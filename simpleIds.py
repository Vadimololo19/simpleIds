cat simpleIds
from scapy.all import sniff, TCP, IP
from scapy.config import conf
import datetime

conf.debug_dissector = 2


def detect_port_scan(packet):
    global seen_alerts
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        src_dst = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        if flags == "S" or flags == "SA":

            print("*" * 40)
            print(f"[!] POTENTIAL SYN SCAN DETECTED")
            print(f"[*] Source IP: {src_ip}")
            print(f"[*] Destination IP: {src_dst}")
            print(f"[*] Source Port: {src_port}")
            print(f"[*] Destination Port: {dst_port}")
            print(f"[*] Timestamp: {datetime.datetime.now()}")
            print("*" * 40)


def start_sniffer():
    print("[*] Starting sniffer...")
    interface = input("[*] Enter interface name: ")
    sniff(prn=detect_port_scan, store=False, filter="tcp", iface=f"{interface}")

if __name__ == "__main__":
    start_sniffer()
