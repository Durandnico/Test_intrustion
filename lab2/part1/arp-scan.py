import socket
from scapy.all import *
import network_util as nutil

def arp_scan(ip_addrs):

    for ip in ip_addrs:
        print("Scanning " + ip)

        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # send request
        answerList = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
        
        # parse response
        for answer in answerList[0]:
            print(answer[1].psrc + " " + answer[1].hwsrc)



def main():
    iface = "wlp0s20f3"
    ip = nutil.get_ip(iface)
    mask = nutil.get_mask(iface)
    subnet = nutil.get_subnet(ip, mask)
    print(subnet)

    mask_split = map( int, mask.split('.') )
    subnet_split = map(int, subnet.split('.'))
    
    # calculate number of hosts
    num_hosts = 1
    for i in range(4):
        num_hosts *= 256 - int(mask_split[i])
    num_hosts -= 2 # subtract network and broadcast addresses


    ip_addrs = []
    for i in range(1, 255):
        ip_addrs.append(subnet + "." + str(i))

    ip_addrs.pop(0) # remove network address
    ip_addrs.pop() # remove broadcast address
    arp_scan(ip_addrs)

if __name__ == "__main__":
    main()