import subprocess
import re
import socket
import sys
from threading import Thread
from scapy.layers.inet import TCP, IP
from scapy.all import *


# def get_default_gateway_ipv4():
#     result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
#     output = result.stdout
#     for line in output.split('\n'):
#         if '0.0.0.0' in line and 'UG' in line:
#             parts = line.split()
#             for i, part in enumerate(parts):
#                 if part == '0.0.0.0':
#                     return parts[i+1]
#
#
#
#
# def packet_callback(packet):
#     if packet.haslayer(TCP) and packet[TCP].dport == 443:
#         print("HTTPS packet detected from {}:{} to {}:{}"
#               .format(packet[IP].src, packet[TCP].sport,
#                       packet[IP].dst, packet[TCP].dport))
#
# Set to store unique open ports
open_ports = set()

def packet_callback(packet):
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port not in open_ports:
            open_ports.add(dst_port)
            print("Port {} is open".format(dst_port))

# Start capturing packets in a separate thread


def start_the_scan():
    sniff(prn=packet_callback, store=0)

    # Print open ports
    print("Open ports detected:")
    for port in open_ports:
        print("Port:", port)
        check_ports = threading.Thread(target=return_command, args=("port", port))
        check_ports.run()
#
def alwais_on_packet_callback(packet):
    if TCP in packet:
        dst_port = packet[TCP].dport
        open_ports.add(dst_port)


#
#
if __name__ == "__main__":
    start_the_scan()
    sniff(prn=packet_callback, filter="tcp", store=0)
#
#     # open_ports = []
#     # threads = []
#     # num = 20
#     # for port in range(1, 65535 - num, num):
#     #         scan_thread = Thread(target=scan, args=(port, num)).start()
#     #         threads.append(scan_thread)
#     #
#     # for thread in threads:
#     #     thread.join()


# from scapy.all import *
#
# # Set to store unique open ports
# open_ports = set()
#
# def packet_callback(packet):
#     if TCP in packet:
#         dst_port = packet[TCP].dport
#         open_ports.add(dst_port)

# Start capturing packets
# sniff(prn=packet_callback, store=0)
#
# # Print open ports
# print("Open ports detected:")
# for port in open_ports:
#     print("Port:", port)


# Set to store unique open ports
# open_ports = set()

def packet_callback(packet):
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port not in open_ports:
            open_ports.add(dst_port)
            print("Port {} is open".format(dst_port))

# Start capturing packets in a separate thread
# sniff(prn=packet_callback, store=0, iface="eth0", store_pcap=False, timeout=10)

# Print open ports
# print("Open ports detected:")
# for port in open_ports:
#     print("Port:", port)
