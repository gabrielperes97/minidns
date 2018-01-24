#!/usr/bin/env python

import socket
import messages
import sys
import os

PORT = 53


#uso:
#raw_queries.py <url> <type> <server>
#Exemplos:
#raw_queries.py google.com.br A 127.0.0.1
#raw_queries.py ig.com.br A ROOT
#raw_queries.py kabum@escola.com aluno 127.0.0.1

req = messages.DnsMessage()
req.add_query(messages.Query(sys.argv[1], sys.argv[2]))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server = sys.argv[3]
if (sys.argv[3] == "ROOT"):
    server = "192.36.148.17"

sock.sendto(req.to_bytes(), (server, PORT))

data, addr = sock.recvfrom(512)
res = messages.DnsMessage.from_bytes(data)
print("Received: \n"+str(res))
