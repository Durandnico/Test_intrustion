import socket
from scapy.all import *
import network_util as nutil
from threading import Thread

res = []

def icmp_ping(ipv4):
    global res

    print("ping : " +  ipv4)

    icmp_ping = IP(dst=ipv4)/ICMP()
        
    # send request
    answer = sr1(icmp_ping, timeout=1, verbose=False)
    
    # parse response
    if answer:
        res.append(ipv4)
    
def icmp_scan_ips(ip_addrs):
    res = []

    for ip in ip_addrs:
        thread = Thread(target = icmp_ping, args = (ip,))
        thread.start()
    
    thread.join()
    for r in res:
        print(r)
    
        
def icmp_scan_network(subnet, mask):
    icmp_scan_ips(nutil.get_ips_in_subnet(subnet, mask))


def main():
    iface = "eth0"
    ip = nutil.get_ip(iface)
    mask = nutil.get_mask(iface)
    subnet = nutil.get_subnet(ip, mask)
    icmp_scan_network(subnet, mask)

if __name__ == "__main__":
    main()