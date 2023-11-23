import scapy.all as scapy
import requests
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interval", dest="interval", type=int, default=60, help="Specify interval in seconds for periodic scan")
    parser.add_argument("-l", "--log", dest="log", help="Specify log file name")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc

def get_vendor(mac):
    url = "https://api.macvendors.com/"
    response = requests.get(url + mac)
    return response.content.decode()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        vendor = get_vendor(mac_address)
        client_dict = {"ip": element[1].psrc, "mac": mac_address, "vendor": vendor}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP Address\t\tMAC Address\t\tVendor")
    print("-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + client["vendor"])

def write_to_file(results, filename):
    with open(filename, "a") as file:
        file.write("IP Address\t\tMAC Address\t\tVendor\n")
        file.write("-----------------------------------------\n")
        for client in results:
            file.write(client["ip"] + "\t\t" + client["mac"] + "\t\t" + client["vendor"] + "\n")

options = get_arguments()
interval = options.interval
log_file = options.log

while True:
    local_ip_range = "192.168.0.1/24"  # Substitua pelo intervalo de IPs da sua rede
    scan_result = scan(local_ip_range)
    print_result(scan_result)

    if log_file:
        write_to_file(scan_result, log_file)

    time.sleep(interval)
