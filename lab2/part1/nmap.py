import socket
from scapy.all import *
import network_util as nutil
from threading import Thread

res = []

def full_tcp_scan_port(ipv4, port):
    tcp_scan = IP(dst=ipv4)/TCP(dport=port, flags="S")
        
    # send request
    answer = sr1(tcp_scan, timeout=1, verbose=False)
    
    # parse response
    if answer and answer[TCP].flags == "SA":
        print(ipv4 + " | " + str(port) + " | " + "OPEN")
        
        # send ACK 
        tcp_ack = IP(dst=ipv4)/TCP(dport=port, flags="A", ack=answer[TCP].seq + 1, seq=0)
        send(tcp_ack, verbose=False)

        res.append((str(port) + "/tcp", "OPEN"))

        # send RST to close the connection
        send(IP(dst=ipv4)/TCP(dport=port, flags="R"), verbose=False)
        

    else:
        res.append((str(port) + "/tcp", "CLOSED"))



def syn_scan_port(ipv4, port):
    syn_scan = IP(dst=ipv4)/TCP(dport=port, flags="S")
        
    # send request
    answer = sr1(syn_scan, timeout=1, verbose=False)
    
    # parse response
    if answer and answer[TCP].flags == "SA":
        res.append((str(port) + "/tcp", "OPEN"))
        send(IP(dst=ipv4)/TCP(dport=port, flags="R"), verbose=False) # send RST to close the connection

    elif answer and answer[TCP].flags == "RA":
        # print(ipv4 + " | " + str(port) + " | " + "CLOSED")
        res.append((str(port) + "/tcp", "CLOSED"))

    else:
        # print(ipv4 + " | " + str(port) + " | " + "FILTERED")
        res.append((str(port) + "/tcp", "FILTERED"))




def fin_scan_port(ipv4, port):
    fin_scan = IP(dst=ipv4)/TCP(dport=port, flags="F")
        
    # send request
    answer = sr1(fin_scan, timeout=1, verbose=False)
    
    # parse response
    # print(answer.show())
    if not answer:
        # print(ipv4 + " | " + str(port) + " | " + "OPEN")
        res.append((str(port) + "/tcp", "OPEN|FILTERED"))
    elif answer.haslayer(TCP) and answer[TCP].flags == "RA":
        # print(ipv4 + " | " + str(portz) + " | " + "CLOSED")
        res.append((str(port) + "/tcp", "CLOSED"))
    else:
        print(ipv4 + " | " + str(port) + " | " + "FILTERED")
        res.append((str(port) + "/tcp", "FILTERED"))




def ack_scan_port(ipv4, port):
    ack_scan = IP(dst=ipv4)/TCP(dport=port, flags="A")
        
    # send request
    answer = sr1(ack_scan, timeout=1, verbose=False)
    
    # parse response
    if answer and answer[TCP].flags == "R":
        # print(ipv4 + " | " + str(port) + " | " + "UNFILTERED")
        res.append((str(port) + "/tcp", "UNFILTERED"))

    
    else:
        # print(ipv4 + " | " + str(port) + " | " + "FILTERED")
        res.append((str(port) + "/tcp", "FILTERED"))




def udp_scan_port(ipv4, port):
    # print("scanning : " +  ipv4 + " " + str(port))

    udp_scan = IP(dst=ipv4)/UDP(dport=port)
        
    # send request
    answer = sr1(udp_scan, timeout=2, verbose=False)
        
    # parse response
    if not answer:
        # print(ipv4 + " | " + str(port) + " | " + "OPEN|FILTERED")
        res.append((str(port) + "/udp", "OPEN|FILTERED"))

    
    else:
        if answer.haslayer(ICMP):
            if int(answer[ICMP].type) == 3:
                if int(answer[ICMP].code) == 3:
                    # print(ipv4 + " | " + str(port) + " | " + "CLOSED")
                    res.append((str(port) + "/udp", "CLOSED"))
                
                elif int(answer[ICMP].code) in [1,2,9,10,13]:
                    # print(ipv4 + " | " + str(port) + " | " + "FILTERED")
                    res.append((str(port) + "/udp", "FILTERED"))
            
            if answer.haslayer(UDP):
                # print(ipv4 + " | " + str(port) + " | " + "OPEN")
                res.append((str(port) + "/udp", "OPEN"))
            # print(ipv4 + " | " + str(port) + " | " + "CLOSED")
        else:
            print("ERROR UNKNOWN")


def scan_ports(ipv4, ports, scan_fct):
    global res
    res = []

    print("Scan " + "SYN" if scan_fct == syn_scan_port else "FULL TCP" if scan_fct == full_tcp_scan_port else "FIN" if scan_fct == fin_scan_port else "ACK" if scan_fct == ack_scan_port else "UDP")
    print("Scanning " + ipv4 + " ports...")

    for port in ports:
        thread = Thread(target = scan_fct, args = (ipv4, port))
        thread.start()
    
    thread.join()

def print_res(filter = ["OPEN" , "CLOSED", "FILTERED", "UNFILTERED", "OPEN|FILTERED"], ipv4 = None):
    
    print("scan report for " +  ipv4 )
    print("port scans : " + str(len(res)))
    count = 0

    res.sort(key=lambda x: int(x[0].split("/")[0]))

    for r in res:
        if r[1] in filter:
            print(r[0] + "   \t" + r[1])
            count += 1

    print("not shown : " + str(len(res) - count) + " ports")


def main():
    iface = "eth0"
    ip = nutil.get_ip(iface)
    mask = nutil.get_mask(iface)
    subnet = nutil.get_subnet(ip, mask)
    # ports 1 to 1024 and 8070 to 8100
    ports = list(range(1, 1025)) + list(range(8070, 8101))
    # scan_ports("192.168.50.2", range(1, 1024), full_tcp_scan_port)
    # print("====================================")
    # scan_ports("192.168.50.2", range(1, 1024), syn_scan_port)
    # print("====================================")
    # scan_ports("192.168.50.2", range(1, 1024), fin_scan_port)
    # print("====================================")
    # scan_ports("192.168.50.2", range(1, 1024), ack_scan_port)
    # print("====================================")
    # scan_ports("192.168.50.2", range(1, 1024), udp_scan_port)
    
    # print_res(["OPEN", "UNFILTERED", "OPEN|FILTERED"], "192.168.50.2")
    

if __name__ == "__main__":
    main()