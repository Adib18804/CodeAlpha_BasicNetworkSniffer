# CodeAlpha_BasicNetworkSniffer

A Python-based network sniffer built for the **CodeAlpha Cyber Security Internship — Task 1**.

## Features
- Live packet capture using **Scapy**
- Protocol identification: TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH, FTP
- Displays source/destination IP & port
- TCP flag decoding
- DNS query extraction
- Payload preview (printable ASCII or hex fallback)
- Colored console output
- Saves all packets to a timestamped `.pcap` file (openable in Wireshark)
- BPF filter support (e.g. `tcp`, `udp port 53`, `icmp`)
- Graceful Ctrl+C handling

## Requirements
- Python 3.8+
- Scapy 2.5+
- **Windows**: [Npcap](https://npcap.com/) installed (WinPcap API-compatible mode)
- **Linux/macOS**: libpcap (usually pre-installed)

## Installation
```bash
git clone https://github.com/Adib18804/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
pip install -r requirements.txt
