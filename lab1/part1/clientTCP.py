import socket
import sys

# constants
SERVER_ADDRESS = '192.168.50.20'
SERVER_PORT = 723
GET_CONFIG_MESSAGE = 'GET_FILE'
CONFIG_FILE_NAME = 'config.txt'
GET_APP_MESSAGE = 'GET_APP'
APP_NAME = 'app'


def connect_to_server(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((address, port))

    return s

def TCP_client(address, port):
    s = connect_to_server(address, port)
    #wait to get all the server messages and print them
    while True:
        # wait for response from server
        data = s.recv(1024)
        if not data:
            break

        print(data)
    
    # close the socket
    s.close()

    print('connection closed')


def get_configuration_file():
    # Create a socket
    s = connect_to_server(SERVER_ADDRESS, SERVER_PORT)

    # send message to server
    s.sendall(GET_CONFIG_MESSAGE)

    # skip the 4 helping messages
    for i in range(4):
        data = s.recv(2048)
        if not data:
            break
        print(data)

    #write the file to the disk
    with open(CONFIG_FILE_NAME, 'w') as f:
        while True:
            data = s.recv(2048)
            if not data:
                break
            f.write(data)
        

def get_app():
    # Create a socket
    s = connect_to_server(SERVER_ADDRESS, SERVER_PORT)

    # send message to server
    s.sendall(GET_APP_MESSAGE)
    
    # skip the 4 helping messages
    for i in range(4):
        data = s.recv(2048)
        if not data:
            break
        print(data)
        
    with open(APP_NAME, 'w') as f:
        while True:
            data = s.recv(2048)
            if not data:
                break
            f.write(data)
    
    # close the socket
    s.close()

    print('connection closed')



    
if __name__ == '__main__':
    # TCP_client(SERVER_ADDRESS, SERVER_PORT)
    get_configuration_file(SERVER_ADDRESS, GET_CONFIG_MESSAGE)
    # get_app()