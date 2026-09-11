#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer
Author: Adib (Adib18804)
"""

import argparse
import datetime
import os
import sys
import signal
import time

from scapy.all import (
    sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw,
)
from colorama import Fore, Style, init

init(autoreset=True)

captured_packets = []
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Global flag for stop
STOP = {"flag": False}


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_protocol_name(packet):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        if packet[TCP].dport in (80,) or packet[TCP].sport in (80,):
            return "HTTP"
        if packet[TCP].dport in (443,) or packet[TCP].sport in (443,):
            return "HTTPS/TLS"
        if packet[TCP].dport in (22,) or packet[TCP].sport in (22,):
            return "SSH"
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return f"IP (proto {packet[IP].proto})"
    return "Unknown"


def get_payload_preview(packet, max_len=60):
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        text = payload.decode("latin-1", errors="replace")
        text = "".join(c if (32 <= ord(c) <= 126) else "." for c in text)
        if len(text) > max_len:
            text = text[:max_len] + "..."
        return text
    return ""


def get_dns_query(packet):
    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        try:
            return packet[DNS].qd.qname.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


def process_packet(packet):
    captured_packets.append(packet)

    proto = get_protocol_name(packet)
    src_ip = dst_ip = "-"
    src_port = dst_port = "-"
    extra = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        extra = f"op={'request' if packet[ARP].op == 1 else 'reply'}"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        extra = f"flags={packet[TCP].flags}"
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if proto == "DNS":
        q = get_dns_query(packet)
        if q:
            extra = f"query={q}"

    payload = get_payload_preview(packet)

    color = {
        "TCP": Fore.CYAN, "UDP": Fore.GREEN, "HTTP": Fore.YELLOW,
        "HTTPS/TLS": Fore.MAGENTA, "DNS": Fore.BLUE, "ICMP": Fore.RED,
        "ARP": Fore.LIGHTBLACK_EX,
    }.get(proto, Fore.WHITE)

    print(
        f"{Fore.LIGHTBLACK_EX}[{timestamp()}]{Style.RESET_ALL} "
        f"{color}{proto:<10}{Style.RESET_ALL} "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"{Fore.LIGHTBLACK_EX}{extra}{Style.RESET_ALL}"
    )
    if payload:
        print(f"    {Fore.LIGHTBLACK_EX}payload:{Style.RESET_ALL} {payload}")


def save_packets():
    if captured_packets:
        fname = os.path.join(
            LOG_DIR,
            f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
        )
        wrpcap(fname, captured_packets)
        print(f"{Fore.GREEN}[+] Saved {len(captured_packets)} packets to {fname}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No packets captured.{Style.RESET_ALL}")


def handle_ctrl_c(signum, frame):
    print(f"\n{Fore.YELLOW}[!] Ctrl+C received. Stopping...{Style.RESET_ALL}")
    STOP["flag"] = True


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Task 1 - Basic Network Sniffer")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-c", "--count", type=int, default=0)
    parser.add_argument("-f", "--filter", default=None)
    args = parser.parse_args()

    print(f"{Fore.CYAN}{'='*70}")
    print(f" CodeAlpha - Basic Network Sniffer")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f" Interface : {args.interface or 'auto'}")
    print(f" Count     : {args.count or 'infinite (Ctrl+C to stop)'}")
    print(f" Filter    : {args.filter or 'none'}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Register Ctrl+C handler
    signal.signal(signal.SIGINT, handle_ctrl_c)

    try:
        # Loop with timeout=1 — this way Python can process Ctrl+C every second
        while not STOP["flag"]:
            sniff(
                iface=args.interface,
                filter=args.filter,
                prn=process_packet,
                count=args.count if args.count > 0 else 0,
                store=False,
                timeout=1,
            )
            # If count-based, exit after first round
            if args.count > 0:
                break
    except PermissionError:
        print(f"{Fore.RED}[!] Permission denied. Run as Administrator.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.YELLOW}[!] Stopping capture...{Style.RESET_ALL}")
    save_packets()


if __name__ == "__main__":
    main()
