# 🛡️ Task 4: Network Intrusion Detection System
**CodeAlpha Cybersecurity Internship**

## Overview
A Python-based NIDS using **Scapy** that monitors live network traffic, detects 6 attack categories in real time, fires colour-coded terminal alerts, and logs all events to JSON and plain-text files.
An optional **Snort/Suricata rule set** (`codealpha.rules`) provides enterprise-grade signature-based detection for the same attack categories.

---

## Detection Capabilities

| Detection Engine | Attack Type | Trigger |
|---|---|---|
| Port Scan | SYN Scan | 10 SYN/5s from one source |
| Port Scan | NULL / FIN / XMAS Scan | Any packet with evasion flags |
| Brute Force | SSH / FTP / Telnet / HTTP / RDP | 15 connections/10s per service |
| ICMP Flood | Ping Flood / Sweep | 20 ICMP echo requests/5s |
| ARP Spoof | Cache Poisoning / MITM | MAC change for known IP |
| DNS Exfil | Data Exfiltration | DNS query > 60 chars |
| Payload Sigs | SQLi / XSS / Shell / Path Traversal / Code Exec | Regex match on raw payload |

---

## Requirements
```bash
pip install scapy flask
# Linux
sudo apt install libpcap-dev
```

---

## Usage

### Python NIDS (`nids.py`)
```bash
# Capture all traffic (auto interface)
sudo python3 nids.py

# Specific interface
sudo python3 nids.py -i eth0

# With BPF filter
sudo python3 nids.py -i eth0 -f "not arp"

# Stop after 60 seconds, stats every 5s
sudo python3 nids.py -t 60 --stats-interval 5
```

**Arguments:**
| Flag | Description |
|------|-------------|
| `-i / --iface` | Network interface (default: auto) |
| `-f / --filter` | BPF filter string |
| `-t / --timeout` | Stop after N seconds |
| `--stats-interval` | Stats print interval in seconds (default: 10) |

**Output files:**
- `nids_alerts.json` — structured JSON log of all alerts
- `nids_alerts.log` — plain-text log for syslog/SIEM ingestion

---

## Snort/Suricata Rules (`codealpha.rules`)

### Snort 3 setup
```bash
# Install Snort
sudo apt install snort

# Copy rules
sudo cp codealpha.rules /etc/snort/rules/

# Add to /etc/snort/snort.conf:
# include $RULE_PATH/codealpha.rules

# Run
sudo snort -i eth0 -c /etc/snort/snort.conf -A console
```

### Suricata setup
```bash
# Install Suricata
sudo apt install suricata

# Copy rules
sudo cp codealpha.rules /etc/suricata/rules/

# Add to /etc/suricata/suricata.yaml under rule-files:
# - codealpha.rules

# Run
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Rule coverage

| SID | Rule | Classtype |
|-----|------|-----------|
| 1000001 | SYN Scan (15 SYN/2s) | attempted-recon |
| 1000002 | NULL Scan | attempted-recon |
| 1000003 | FIN Scan | attempted-recon |
| 1000004 | XMAS Scan | attempted-recon |
| 1000010–13 | SSH/FTP/Telnet/RDP Brute Force | attempted-admin |
| 1000020–23 | SQLi / XSS / Path Traversal / CMDi | web-application-attack |
| 1000030–31 | ICMP Flood / Ping Sweep | attempted-dos |
| 1000040–41 | DNS Exfil / DNS Amplification | policy-violation / attempted-dos |
| 1000050–52 | Meterpreter C2 / Netcat / PowerShell | trojan-activity |

---

## Testing the NIDS (safe, local-only)

```bash
# Test SYN scan detection (requires nmap)
sudo nmap -sS 127.0.0.1 -p 1-1000 --rate 100

# Test ping flood
ping -f 127.0.0.1

# Test DNS exfil detection
nslookup aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.test.com 127.0.0.1

# Simulate SQL injection payload (safe curl to local server)
curl "http://localhost:5000/search?q=' UNION SELECT * FROM users--"
```

> Run all tests against **localhost / 127.0.0.1 only**. Never test against systems you don't own.

---

## Architecture

```
live traffic
     │
     ▼
  scapy sniff()
     │
     ├─► detect_port_scan()    → SYN/NULL/FIN/XMAS
     ├─► detect_brute_force()  → sliding window per (src, dport)
     ├─► detect_icmp_flood()   → sliding window per src
     ├─► detect_arp_spoof()    → ARP table comparison
     ├─► detect_dns_exfil()    → query length check
     └─► detect_payload_sigs() → regex against Raw layer
              │
              ▼
          fire_alert()
              │
     ┌────────┼────────┐
     ▼        ▼        ▼
  terminal  JSON log  TXT log
```

---

## GitHub Repository Name
```
CodeAlpha_NetworkIDS
```

