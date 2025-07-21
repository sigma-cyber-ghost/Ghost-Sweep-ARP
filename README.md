# 👻 Ghost-Sweep-ARP

> **Sigma Ghost: Black Hat Edition**  
> A ruthless LAN hijacking tool for intercepting credentials, spoofing ARP tables, and extracting MAC-level recon in real-time.

---

## 🔍 Name Dissection

- **Ghost** → Spectral stealth, vanishes after the kill  
- **Sweep** → LAN-wide passive/active recon and ARP disruption  
- **ARP** → Core vector of attack: ARP spoofing for MITM control  

---

## ⚡ Core Capabilities

| Module            | Function                           | Technical Basis                     |
|-------------------|------------------------------------|-------------------------------------|
| 🕸 Phantom Scan     | Passive ARP/ICMP monitoring         | Scapy-based zero-emission sniffing  |
| 🔍 Spectral Sweep   | Active ICMP subnet discovery        | Threaded ping + TTL variation       |
| 👥 Ethereal MITM    | Real-time ARP bidirectional spoofing| Poisoning target ↔ gateway          |
| 🔓 Cred Sniffer     | Extract plaintext login credentials | HTTP POST data sniff via Scapy      |
| 🧬 MAC Profiler     | Dump target & site MAC addresses    | Ethernet layer query via ARP        |
| 🚨 Hijack Detector  | Alerts on hijackable HTTP login     | Regex + site profiling              |

---

## 🚀 Strategic Advantages

✅ **Clarity**  
- Instantly recognized by red teams as ARP-based MITM suite  
- Follows `nmap`/`ettercap`/`bettercap` logic  

✅ **Brand Synergy**  
- Black Hat aesthetics (YouTube-ready visuals)  
- Technical appeal: hooks offensive security pros, demo hunters, SOC testers  

✅ **Modular Evolution**  
- Future upgrade paths: `Ghost-Sweep-DNS`, `Ghost-Sweep-SSL`, `Ghost-Sweep-WiFi`

---

## 🎯 Who's This For?

- 🧠 Red Teamers & Black Hat researchers  
- 💻 Penetration testers in live demos  
- 🛰 SOC analysts testing threat detection  
- 📹 YouTube creators showing raw attack chains  

---

## ⚙️ Installation

```bash
git clone https://github.com/sigma-cyber-ghost/Ghost-Sweep-ARP.git
cd Ghost-Sweep-ARP
sudo apt update && sudo apt install -y python3-pip iptables mitmproxy bettercap
pip3 install scapy scapy-http netifaces colorama psutil requests rich iptables  mitmproxy

```
## 🌐 Connect With Us

[![Telegram](https://img.shields.io/badge/Telegram-Sigma_Ghost-blue?logo=telegram)](https://t.me/Sigma_Cyber_Ghost)  [![YouTube](https://img.shields.io/badge/YouTube-Sigma_Ghost-red?logo=youtube)](https://www.youtube.com/@sigma_ghost_hacking)  [![Instagram](https://img.shields.io/badge/Instagram-Safder_Khan-purple?logo=instagram)](https://www.instagram.com/safderkhan0800_/)  [![Twitter](https://img.shields.io/badge/Twitter-@safderkhan0800_-1DA1F2?logo=twitter)](https://twitter.com/safderkhan0800_)
