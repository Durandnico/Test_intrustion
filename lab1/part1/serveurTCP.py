import socket

SERVER_ADDRESS = '192.168.50.25'
SERVER_PORT = 723



def server_tcp(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((address, port))
 
    s.listen(10)
    print('listening on port %s ...' % port)
    while True:
        # wait for a connection
        connection, client_address = s.accept()
        try:
            print('connection from', client_address)
            # receive the data in small chunks and print it
            while True:
                data = connection.recv(1024)
                print('received "%s"' % data)

                if data:
                    response = ''
                    #if data contain the word 'reply' send it back to the client
                    if 'reply with' in data:
                        data_split = data.split(':')
                        response = data_split[1][:4]

                    print('sending response : ', response)
                    connection.sendall(response)
                    
                else:
                    print('no more data from', client_address)
                    break
        finally:
            # clean up the connection
            connection.close()

    





if __name__ == '__main__':
    server_tcp(SERVER_ADDRESS, SERVER_PORT)