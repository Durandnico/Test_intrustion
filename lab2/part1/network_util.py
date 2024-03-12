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

def main():
    iface = "wlp0s20f3"
    print (get_ip(iface))
    print (get_mask(iface))
    print (get_subnet(get_ip(iface), get_mask(iface)))

if __name__ == "__main__":
    main()