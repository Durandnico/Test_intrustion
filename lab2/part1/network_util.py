import socket
import struct
import fcntl

def get_mask(iface = "eth0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s, 35099, struct.pack('256s', iface[:15]))[20:24])

def get_ip(iface = "eth0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s, 0x8915, struct.pack('256s', iface[:15]))[20:24])

def get_subnet(ip, mask):
    ip = ip.split('.')
    mask = mask.split('.')
    subnet = []
    for i in range(4):
        subnet.append(str(int(ip[i]) & int(mask[i])))
    return '.'.join(subnet)


def get_ips_in_subnet(subnet, mask):
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
    return ip_addrs


def main():
    iface = "wlp0s20f3"
    print (get_ip(iface))
    print (get_mask(iface))
    print (get_subnet(get_ip(iface), get_mask(iface)))

if __name__ == "__main__":
    main()