#!/usr/bin/env python3
"""
nids.py — CodeAlpha Task 4: Network Intrusion Detection System
==============================================================
A lightweight Python NIDS using Scapy that detects:
  • Port scans (SYN scan, NULL scan, FIN scan, XMAS scan)
  • Brute-force login attempts (SSH, FTP, Telnet, HTTP)
  • ICMP flood / ping sweep
  • ARP spoofing / poisoning
  • DNS exfiltration (oversized queries)
  • Suspicious payload patterns (shell commands, SQLi, XSS probes)

Outputs:
  • Colour-coded real-time terminal alerts
  • JSON alert log  (nids_alerts.json)
  • Plain-text log  (nids_alerts.log)
  • Live stats updated every 10 s
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
from collections import defaultdict
from threading import Lock, Thread

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
except ImportError:
    print("[!] Install scapy:  pip install scapy")
    sys.exit(1)

# ─── Terminal colours ─────────────────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
RED  = "\033[91m";  LRED   = "\033[31m"
YEL  = "\033[93m";  GRN    = "\033[92m"
CYN  = "\033[96m";  BLU    = "\033[94m"
MAG  = "\033[95m";  GREY   = "\033[90m"

SEV_COLOUR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": MAG, "LOW": CYN, "INFO": GRN}
SEV_ICON   = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}

# ─── Alert store ──────────────────────────────────────────────────────────────
alerts: list[dict] = []
alert_lock = Lock()
stats: dict = defaultdict(int)

LOG_JSON = "nids_alerts.json"
LOG_TXT  = "nids_alerts.log"

# ─── Sliding-window trackers ──────────────────────────────────────────────────
# { src_ip: [timestamps] }
syn_tracker:   dict = defaultdict(list)
icmp_tracker:  dict = defaultdict(list)
brute_tracker: dict = defaultdict(list)   # key: (src, dport)
arp_table:     dict = {}                   # { ip: mac }  — for ARP spoof detection
lock = Lock()

# ─── Suspicious payload patterns ─────────────────────────────────────────────
PAYLOAD_SIGS = [
    (re.compile(rb"(union\s+select|drop\s+table|insert\s+into|1=1)", re.I),
     "SQL Injection probe"),
    (re.compile(rb"(<script|onerror=|javascript:|alert\()", re.I),
     "XSS probe"),
    (re.compile(rb"(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)", re.I),
     "Shell command in payload"),
    (re.compile(rb"(\.\.\/|\.\.\\)", re.I),
     "Path traversal attempt"),
    (re.compile(rb"(eval\(|base64_decode\(|exec\()", re.I),
     "Code execution attempt"),
]


# ─── Core alert function ──────────────────────────────────────────────────────

def fire_alert(severity: str, category: str, src: str, dst: str, detail: str, packet=None):
    ts = datetime.datetime.now().isoformat(timespec="milliseconds")
    alert = {
        "timestamp": ts,
        "severity":  severity,
        "category":  category,
        "src":       src,
        "dst":       dst,
        "detail":    detail,
    }
    sc = SEV_COLOUR[severity]
    icon = SEV_ICON[severity]
    print(
        f"\n{BOLD}{sc}{'━'*70}{R}\n"
        f"  {icon}  {BOLD}{sc}{severity:8s}{R}  {BOLD}{category}{R}\n"
        f"  {GREY}Time:{R}   {ts}\n"
        f"  {GREY}Src:{R}    {BLU}{src}{R}  →  {RED}{dst}{R}\n"
        f"  {GREY}Detail:{R} {detail}\n"
        f"{sc}{'━'*70}{R}"
    )
    with alert_lock:
        alerts.append(alert)
        stats[severity] += 1
        stats["total"] += 1
        # Append to JSON (rewrite entire file for simplicity)
        with open(LOG_JSON, "w") as f:
            json.dump(alerts, f, indent=2)
        # Append to text log
        with open(LOG_TXT, "a") as f:
            f.write(f"[{ts}] {severity:8s} | {category} | {src} -> {dst} | {detail}\n")


# ─── Detection engines ────────────────────────────────────────────────────────

def _prune(lst, window=5):
    """Keep only timestamps within the last `window` seconds."""
    cutoff = time.time() - window
    return [t for t in lst if t > cutoff]


def detect_port_scan(packet):
    """SYN, NULL, FIN, XMAS scan detection."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    ip  = packet[IP]
    tcp = packet[TCP]
    flags = str(tcp.flags)
    src, dst = ip.src, ip.dst

    # SYN scan: SYN without ACK
    if "S" in flags and "A" not in flags:
        with lock:
            syn_tracker[src].append(time.time())
            syn_tracker[src] = _prune(syn_tracker[src])
            count = len(syn_tracker[src])
        if count == 10:
            fire_alert("HIGH", "Port Scan — SYN Scan", src, dst,
                       f"{count} SYN packets in 5 s → likely nmap -sS")
        elif count == 50:
            fire_alert("CRITICAL", "Port Scan — SYN Flood/Scan", src, dst,
                       f"{count} SYN packets in 5 s → aggressive scan or DoS")
        return

    # NULL scan: no flags
    if flags == "":
        fire_alert("MEDIUM", "Port Scan — NULL Scan", src, f"{dst}:{tcp.dport}",
                   "TCP packet with no flags set (nmap -sN)")

    # FIN scan: only FIN
    elif flags == "F":
        fire_alert("MEDIUM", "Port Scan — FIN Scan", src, f"{dst}:{tcp.dport}",
                   "TCP FIN-only packet (nmap -sF)")

    # XMAS scan: FIN + PSH + URG
    elif "F" in flags and "P" in flags and "U" in flags:
        fire_alert("HIGH", "Port Scan — XMAS Scan", src, f"{dst}:{tcp.dport}",
                   "TCP FIN+PSH+URG (nmap -sX) — evasion attempt")


def detect_brute_force(packet):
    """SSH / FTP / Telnet / HTTP login brute-force."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    ip, tcp = packet[IP], packet[TCP]
    if "A" not in str(tcp.flags):
        return
    BRUTE_PORTS = {22: "SSH", 21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT"}
    if tcp.dport not in BRUTE_PORTS:
        return
    key = (ip.src, tcp.dport)
    with lock:
        brute_tracker[key].append(time.time())
        brute_tracker[key] = _prune(brute_tracker[key], window=10)
        count = len(brute_tracker[key])
    proto = BRUTE_PORTS[tcp.dport]
    if count == 15:
        fire_alert("HIGH", f"Brute Force — {proto}", ip.src, f"{ip.dst}:{tcp.dport}",
                   f"{count} connection attempts in 10 s on port {tcp.dport}")
    elif count == 50:
        fire_alert("CRITICAL", f"Brute Force — {proto}", ip.src, f"{ip.dst}:{tcp.dport}",
                   f"{count} attempts in 10 s — active credential stuffing")


def detect_icmp_flood(packet):
    """ICMP flood and ping sweep."""
    if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
        return
    ip   = packet[IP]
    icmp = packet[ICMP]
    if icmp.type != 8:   # echo request only
        return
    with lock:
        icmp_tracker[ip.src].append(time.time())
        icmp_tracker[ip.src] = _prune(icmp_tracker[ip.src])
        count = len(icmp_tracker[ip.src])
    if count == 20:
        fire_alert("MEDIUM", "ICMP Flood / Ping Sweep", ip.src, ip.dst,
                   f"{count} ICMP echo requests in 5 s")
    elif count == 100:
        fire_alert("HIGH", "ICMP DoS Flood", ip.src, ip.dst,
                   f"{count} ICMP echo requests in 5 s — potential DoS")


def detect_arp_spoof(packet):
    """ARP spoofing / cache poisoning detection."""
    if not packet.haslayer(ARP):
        return
    arp = packet[ARP]
    if arp.op != 2:   # ARP reply only
        return
    ip, mac = arp.psrc, arp.hwsrc
    with lock:
        if ip in arp_table and arp_table[ip] != mac:
            old_mac = arp_table[ip]
            fire_alert("CRITICAL", "ARP Spoofing / Poisoning", mac, ip,
                       f"IP {ip} changed MAC: {old_mac} → {mac} (MITM attack?)")
        arp_table[ip] = mac


def detect_dns_exfil(packet):
    """DNS exfiltration — oversized query subdomain."""
    if not (packet.haslayer(DNS) and packet.haslayer(UDP)):
        return
    dns = packet[DNS]
    if dns.qr != 0 or not dns.qd:   # only queries
        return
    try:
        qname = dns.qd.qname.decode(errors="replace")
    except Exception:
        return
    if len(qname) > 60:
        src = packet[IP].src if packet.haslayer(IP) else "unknown"
        fire_alert("HIGH", "DNS Exfiltration Attempt", src, "DNS",
                   f"Oversized DNS query ({len(qname)} chars): {qname[:80]}")


def detect_payload_sigs(packet):
    """Match raw payload against known attack signatures."""
    if not (packet.haslayer(IP) and packet.haslayer(Raw)):
        return
    raw = bytes(packet[Raw])
    src = packet[IP].src
    dst = packet[IP].dst
    for pattern, label in PAYLOAD_SIGS:
        if pattern.search(raw):
            preview = raw[:80].decode(errors="replace").replace("\n", "\\n")
            fire_alert("HIGH", f"Signature Match — {label}", src, dst,
                       f"Payload: \"{preview}\"")
            break   # one alert per packet


# ─── Master packet handler ────────────────────────────────────────────────────

def handle_packet(packet):
    stats["packets"] += 1
    detect_port_scan(packet)
    detect_brute_force(packet)
    detect_icmp_flood(packet)
    detect_arp_spoof(packet)
    detect_dns_exfil(packet)
    detect_payload_sigs(packet)


# ─── Stats printer thread ─────────────────────────────────────────────────────

def stats_printer(interval=10):
    while True:
        time.sleep(interval)
        t = datetime.datetime.now().strftime("%H:%M:%S")
        print(
            f"\n{GREY}{'─'*60}{R}\n"
            f"  {BLU}[Stats {t}]{R}  Packets: {stats['packets']}  "
            f"Alerts: {stats['total']}  "
            f"{RED}CRIT:{stats['CRITICAL']}{R}  "
            f"{YEL}HIGH:{stats['HIGH']}{R}  "
            f"{MAG}MED:{stats['MEDIUM']}{R}  "
            f"{CYN}LOW:{stats['LOW']}{R}\n"
            f"{GREY}{'─'*60}{R}"
        )


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha NIDS — Task 4")
    parser.add_argument("-i", "--iface",   default=None,   help="Interface to monitor")
    parser.add_argument("-f", "--filter",  default=None,   help="BPF filter")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Stop after N seconds")
    parser.add_argument("--stats-interval", type=int, default=10, help="Stats print interval (s)")
    args = parser.parse_args()

    print(f"""{BLU}{BOLD}
  ███╗   ██╗██╗██████╗ ███████╗
  ████╗  ██║██║██╔══██╗██╔════╝
  ██╔██╗ ██║██║██║  ██║███████╗
  ██║╚██╗██║██║██║  ██║╚════██║
  ██║ ╚████║██║██████╔╝███████║
  ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
  Network Intrusion Detection System
  CodeAlpha Internship — Task 4{R}
""")
    print(f"  Interface : {YEL}{args.iface or 'auto'}{R}")
    print(f"  Filter    : {YEL}{args.filter or 'all traffic'}{R}")
    print(f"  Log JSON  : {YEL}{LOG_JSON}{R}")
    print(f"  Log TXT   : {YEL}{LOG_TXT}{R}")
    print(f"\n  {GRN}Detecting:{R} Port Scans | Brute Force | ICMP Flood | ARP Spoof | DNS Exfil | Payload Sigs")
    print(f"\n  {GREY}Press Ctrl+C to stop.{R}\n")
    print("─" * 60)

    # Start stats printer
    t = Thread(target=stats_printer, args=(args.stats_interval,), daemon=True)
    t.start()

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handle_packet,
            store=False,
            timeout=args.timeout,
        )
    except PermissionError:
        print(f"\n{RED}[!] Permission denied. Run with sudo.{R}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    print(f"\n{GRN}Capture stopped.{R}")
    print(f"  Total packets : {stats['packets']}")
    print(f"  Total alerts  : {stats['total']}")
    print(f"  Logs saved to : {LOG_JSON}  &  {LOG_TXT}\n")


if __name__ == "__main__":
    main()
