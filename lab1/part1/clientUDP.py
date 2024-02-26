import socket

SERVER_ADDRESS = '192.168.50.20'
SERVER_PORT = 7230

def UDP_client(address, port):
    
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Connect to the server
    s.connect((address, port))
    
    #send message to the server
    s.sendall('GTI723')

    while True:
        # wait for response from server
        data = s.recv(1024)
        if not data:
            print('no data !!!!!!!!!')
            break
        print(data)
    
    # close the socket
    s.close()

    print('connection closed')


if __name__ == "__main__":
    UDP_client(SERVER_ADDRESS, SERVER_PORT) 