#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer
Author: <Your Name>
Description:
    Captures live network traffic, analyzes packet structure,
    identifies protocols (TCP/UDP/ICMP/ARP/DNS/HTTP), extracts
    source/destination IPs, ports, and payloads. Saves packets
    to a .pcap file and logs a readable summary.
"""

import argparse
import datetime
import os
import sys
import signal

from scapy.all import (
    sniff,
    wrpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    Raw,
    Ether,
)
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ------------------------------------------------------------------
# Global state
# ------------------------------------------------------------------
captured_packets = []
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Protocol number -> name mapping (partial)
IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------
def timestamp() -> str:
    """Return current time as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_protocol_name(packet) -> str:
    """Determine the highest-level protocol name for a packet."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return "HTTP"
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            return "HTTPS/TLS"
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:
            return "SSH"
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return "FTP"
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


def get_payload_preview(packet, max_len: int = 60) -> str:
    """Return a printable preview of the packet payload."""
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        try:
            text = payload.decode("latin-1", errors="replace")
            text = "".join(c if (32 <= ord(c) <= 126) else "." for c in text)
        except Exception:
            text = payload.hex()
        if len(text) > max_len:
            text = text[:max_len] + "..."
        return text
    return ""


def get_dns_query(packet) -> str:
    """Extract DNS query name if present."""
    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        try:
            return packet[DNS].qd.qname.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


# ------------------------------------------------------------------
# Packet processing
# ------------------------------------------------------------------
def process_packet(packet):
    """Analyze a single captured packet and print a summary."""
    captured_packets.append(packet)

    proto = get_protocol_name(packet)
    src_ip = dst_ip = "-"
    src_port = dst_port = "-"
    extra = ""

    # --- Layer 3 ---
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

    # --- Layer 4 ---
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        extra = f"flags={flags}"
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # --- DNS ---
    if proto == "DNS":
        q = get_dns_query(packet)
        if q:
            extra = f"query={q}"

    # --- Payload ---
    payload = get_payload_preview(packet)

    # --- Color by protocol ---
    color = {
        "TCP": Fore.CYAN,
        "UDP": Fore.GREEN,
        "HTTP": Fore.YELLOW,
        "HTTPS/TLS": Fore.MAGENTA,
        "DNS": Fore.BLUE,
        "ICMP": Fore.RED,
        "ARP": Fore.LIGHTBLACK_EX,
    }.get(proto, Fore.WHITE)

    # --- Print ---
    line = (
        f"{Fore.LIGHTBLACK_EX}[{timestamp()}]{Style.RESET_ALL} "
        f"{color}{proto:<10}{Style.RESET_ALL} "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"{Fore.LIGHTBLACK_EX}{extra}{Style.RESET_ALL}"
    )
    print(line)

    if payload:
        print(f"    {Fore.LIGHTBLACK_EX}payload:{Style.RESET_ALL} {payload}")


# ------------------------------------------------------------------
# Save / exit
# ------------------------------------------------------------------
def save_and_exit(signum=None, frame=None):
    """Save captured packets to a .pcap file and exit cleanly."""
    print(f"\n{Fore.YELLOW}[!] Stopping capture...{Style.RESET_ALL}")

    if captured_packets:
        fname = os.path.join(
            LOG_DIR,
            f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
        )
        wrpcap(fname, captured_packets)
        print(
            f"{Fore.GREEN}[+] Saved {len(captured_packets)} packets to "
            f"{fname}{Style.RESET_ALL}"
        )
    else:
        print(f"{Fore.RED}[-] No packets captured.{Style.RESET_ALL}")

    sys.exit(0)


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 - Basic Network Sniffer"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: Scapy auto-selects)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = infinite)"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help="BPF filter (e.g. 'tcp', 'udp port 53', 'icmp')"
    )
    args = parser.parse_args()

    print(f"{Fore.CYAN}{'='*70}")
    print(f" CodeAlpha - Basic Network Sniffer")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f" Interface : {args.interface or 'auto'}")
    print(f" Count     : {args.count or 'infinite (Ctrl+C to stop)'}")
    print(f" Filter    : {args.filter or 'none'}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Register Ctrl+C handler to save pcap before exit
    signal.signal(signal.SIGINT, save_and_exit)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print(
            f"{Fore.RED}[!] Permission denied. "
            f"Run as root/administrator.{Style.RESET_ALL}"
        )
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        if args.count > 0:
            save_and_exit()


if __name__ == "__main__":
    main()