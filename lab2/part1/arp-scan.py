import socket
from scapy.all import *
import network_util as nutil
from threading import Thread

res = []

def arp_scan(ipv4):
    global res
    # print("scanning : " +  ipv4)

    arp_request = ARP(pdst=ipv4)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
        
    # send request
    answerList = srp(arp_request_broadcast, timeout=1, verbose=False)
    
    # parse response
    for answer in answerList[0]:
        res.append(answer[1].psrc + " | " + answer[1].hwsrc)

def arp_scan_ips(ip_addrs):
    global res
    res = []

    print("Scanning " + str(len(ip_addrs)) + " IPs...")
    
    for ip in ip_addrs:
        thread = Thread(target = arp_scan, args = (ip,))
        thread.start()
    
    thread.join()
    print("Found " + str(len(res)) + " active IPs")
    for r in res:
        print(r)

def arp_scan_network(subnet, mask):
    print("ARP Scan")
    print("Scanning network " + subnet + " with mask " + mask)
    arp_scan_ips(nutil.get_ips_in_subnet(subnet, mask))


def main():
    iface = "eth0"
    ip = nutil.get_ip(iface)
    mask = nutil.get_mask(iface)
    subnet = nutil.get_subnet(ip, mask)
    arp_scan_network(subnet, mask)

if __name__ == "__main__":
    main()