 #!/bin/python

import socket
import messages
import _thread

#TODO: Colocar isso como parametro passado no terminal
BIND_IP = "0.0.0.0"
BIND_PORT = 53
ROOT_SERVER = "192.36.148.17"
#ROOT_SERVER = "8.8.8.8"
ROOT_PORT = 53

def task(data, addr_client, sock):
    query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = messages.DnsMessage.from_bytes(data)
        print ("Resolving for ", addr_client, " this: \n", req)

        res = recursive_query(req, ROOT_SERVER, query_sock)

        print("Enviando resposta: "+str(res))
        sock.sendto(res.to_bytes(), addr_client)
    except Exception as e:
        raise
    finally:
        query_sock.close()

def recursive_query(query, server, query_sock):
    query_sock.sendto(query.to_bytes(), (server, ROOT_PORT))

    data, addr = query_sock.recvfrom(512)
    res = messages.DnsMessage.from_bytes(data)
    if (len(res.answers) == 0):
        for s in res.additionals:
            if(s.type == "A"):
                print("Resolving "+res.authorities[0].name+" by "+s.addr)
                result = recursive_query(query, s.addr, query_sock)
                print(result)
                if (result is not None):
                    return result
    else:
        return res
    return res



sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, BIND_PORT))

try:
    while True:
        data, addr_client = sock.recvfrom(512)
        _thread.start_new_thread(task, (data, addr_client, sock))
except Exception as e:
    raise
finally:
    sock.close()
