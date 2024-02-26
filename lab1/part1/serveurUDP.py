import socket

SERVER_ADDRESS = '192.168.50.25'
SERVER_PORT = 7230

def server_udp(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    s.bind((address, port))

    print('Server is listening at {}:{} via udp'.format(address, port))
    # wait for a message from the client
    while True:
        data, client_address = s.recvfrom(1024)
        print('received {!r} from {}'.format(data, client_address))

        #if data contain the word 'reply' send it back to the client
        if 'reply with' in data:
            data_split = data.split(':')
            response = data_split[1][:4]

            print('sending response : ', response)
            s.sendto(response, client_address)
            
    

if __name__ == '__main__':
    server_udp(SERVER_ADDRESS, SERVER_PORT)