import socket
import messages
import sys
import os

PORT = 53

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
