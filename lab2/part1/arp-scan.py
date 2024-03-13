import socket
from scapy.all import *
import network_util as nutil
from threading import Thread

res = []

def arp_scan(ipv4):
    global res
    print("scanning : " +  ipv4)

    arp_request = ARP(pdst=ipv4)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
        
    # send request
    answerList = srp(arp_request_broadcast, timeout=1, verbose=False)
    
    # parse response
    for answer in answerList[0]:
        res.append(answer[1].psrc + " | " + answer[1].hwsrc)

def arp_scan_ips(ip_addrs):
    for ip in ip_addrs:
        thread = Thread(target = arp_scan, args = (ip,))
        thread.start()
    
    thread.join()
    for r in res:
        print(r)

def arp_scan_network(subnet, mask):
    mask_split = list(  map( int, mask.split('.') ))
    subnet_split = list(map(int, subnet.split('.')))
    
    ip_addrs = []
    for i in range(256 - mask_split[0]):
        for j in range(256 - mask_split[1]):
            for k in range(256 - mask_split[2]):
                for l in range(256 - mask_split[3]):
                    ip_addrs.append(str(subnet_split[0] + i) + "." + str(subnet_split[1] + j) + "." + str(subnet_split[2] + k) + "." + str(subnet_split[3] + l))


    ip_addrs.pop() # remove broadcast address
    ip_addrs.pop(0) # remove network address
    arp_scan_ips(ip_addrs)


def main():
    iface = "eth0"
    ip = nutil.get_ip(iface)
    mask = nutil.get_mask(iface)
    subnet = nutil.get_subnet(ip, mask)
    arp_scan_network(subnet, mask)

if __name__ == "__main__":
    main()