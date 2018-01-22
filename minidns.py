#!/usr/bin/env python

import socket
from messages import *
import _thread

#TODO: Colocar isso como parametro passado no terminal
BIND_IP = "0.0.0.0"
BIND_PORT = 53
ROOT_SERVER = "192.36.148.17"
#ROOT_SERVER = "8.8.8.8"
ROOT_PORT = 53

"""
Teste interessantes:
CNAME = cloud9.co
Resolver autoridade recursivamente = ig.com.br
Testar ṕr requisições AAAA
"""

def task(data, addr_client, sock):
    query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = DnsMessage.from_bytes(data)
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
    res = DnsMessage.from_bytes(data)
    #Quando tiver alguma resposta
    if (len(res.answers) > 0):
        anws = []
        for a in res.answers:
            if (a.type == "CNAME"):
                c_query = DnsMessage(queries=[])
                c_query.add_query(Query(a.addr, "A"))
                result = recursive_query(c_query, ROOT_SERVER, query_sock)
                if result is not None:
                    anws += result.answers
            else:
                anws.append(a)
        res.answers = anws
        return res
    else:
        if len(res.authorities) > 0:
            #Quando não tiver uma resposta mas tiver o ip de alguma authority
            if len(res.additionals) > 0:
                for s in res.additionals:
                    if(s.type == "A"):
                        print("Resolving "+res.authorities[0].name+" by "+s.addr)
                        result = recursive_query(query, s.addr, query_sock)
                        print(result)
                        if (result is not None):
                            return result

            #Quando não tiver o Ip de uma authority e ter que resolvê-lo na mão
            else:
                if (len(res.authorities) == 1 and res.authorities[0].type == "SOA"):
                    return res
                for a in res.authorities:
                    print("Resolving a Name server "+a.name+" by "+a.name_server)
                    server_query = DnsMessage(queries=[])
                    server_query.add_query(Query(a.name_server, "A"))
                    new_server = recursive_query(server_query, ROOT_SERVER, query_sock)
                    if new_server is not None and len(new_server.answers) > 0:
                        print("Name server "+a.name+" is at "+new_server.answers[0].addr)
                        return recursive_query(query, new_server.answers[0].addr, query_sock)
    return None

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((BIND_IP, BIND_PORT))

print("Servidor iniciado na porta "+str(BIND_PORT))
try:
    while True:
        data, addr_client = sock.recvfrom(512)
        _thread.start_new_thread(task, (data, addr_client, sock))
except Exception as e:
    raise
finally:
    sock.close()
