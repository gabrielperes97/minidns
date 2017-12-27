 #!/bin/python

import socket
import messages

#TODO: Colocar isso como parametro passado no terminal
BIND_IP = "0.0.0.0"
BIND_PORT = 53

#TODO: Transformar em um thread
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, BIND_PORT))

try:
    while True:
        data, addr = sock.recvfrom(1024)
        req = messages.Request.from_bytes(data)
        print ("Received from ", addr, " this: \n", req)
except Exception as e:
    raise
finally:
    sock.close()
