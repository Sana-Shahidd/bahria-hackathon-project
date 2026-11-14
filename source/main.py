# Starts the live packet sensor (needs root + scapy + a real interface).
# For a demo without a network lab, use:  python source/replay.py
from sniffer import start_sniffer

if __name__ == "__main__":
    start_sniffer()
