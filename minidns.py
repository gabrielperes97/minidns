 #!/bin/python

import socket
import messages

#TODO: Colocar isso como parametro passado no terminal
BIND_IP = "0.0.0.0"
BIND_PORT = 53
#ROOT_SERVER = "192.36.148.17"
ROOT_SERVER = "8.8.8.8"
ROOT_PORT = 53

#TODO: Transformar em um thread
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, BIND_PORT))

root_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


try:
    while True:
        data, addr_client = sock.recvfrom(512)
        req = messages.DnsMessage.from_bytes(data)
        print ("Received from ", addr_client, " this: \n", req)
        print("Consultando à ", ROOT_SERVER)
        root_sock.sendto(data, (ROOT_SERVER, ROOT_PORT))
        data, addr = root_sock.recvfrom(512)
        print ("Received from ", addr, " this: \n", data)
        res = messages.DnsMessage.from_bytes(data)
        print("Enviando resposta")
        sock.sendto(res.to_bytes(), addr_client)

except Exception as e:
    raise
finally:
    sock.close()
