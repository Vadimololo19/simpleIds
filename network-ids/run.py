from scapy.all import sniff, IP, TCP, Ether
from ids.core import start_ids
from ids.utils.config_loader import load_config

def main():
    config = load_config()
    print("[*] Starting Network IDS")
    start_ids(config)

if __name__ == "__main__":
    main()
