def resolve_pointer(bytes, offset):
    #Dado em binário
    bin = "{0:16b}".format(int.from_bytes(bytes[offset:offset+2], byteorder='big'))
    if (bin[0:2] == "11"): #é um ponteiro
        bin = "00"+bin[2:]
        return int(bin, 2), True
    else:
        return offset, False

def decode_int(bytes, offset, length):
    return int.from_bytes(bytes[offset:offset+length], byteorder='big'), length


def decode_url(bytes, offset):
    url = []
    i = offset
    tam = 0
    while(int(bytes[i]) != 0):
        k, is_pointer = resolve_pointer(bytes, i)
        if (is_pointer):
            tam += 2
            url += (decode_url(bytes, k)[0]).split(".")
            tam -= 1 #Gambiarra pra alinhar com o zero do final quando não tem ponteiro
            break
        else:
            length = int(bytes[k])
            url.append(bytes[k+1:k+1+length].decode("utf-8"))
            i += 1+length
            tam += length+1
    url = ".".join(url)
    tam += 1
    return url, tam

def decode_class(bytes, offset):
    clas, off = decode_int(bytes, offset, 2)
    if (clas in DnsMessage.classes):
        clas = DnsMessage.classes[clas]
    else:
        raise Exception("clas "+str(clas) + " not mapped")
    return clas, off

def decode_type(bytes, offset):
    typ, off = decode_int(bytes, offset, 2)
    if (typ in DnsMessage.types):
        typ = DnsMessage.types[typ]
    else:
        raise Exception("type "+str(typ) + " not mapped")
    return typ, off

def decode_addr(bytes, offset, length):
    addr = []
    i = offset
    if (length == 4):
        for k in range(length):
            addr.append(str(decode_int(bytes, i, 1)[0]))
            i += 1
        addr = ".".join(addr)
    elif (length == 16):
        k = 0
        while (k < length):
            addr.append(bytes[offset+k:offset+k+2].hex())
            k += 2
        addr = ":".join(addr)
    else:
        raise Exception("Cannot decode address with length "+str(lenght))

    return addr, length

def encode_pointer(offset):
    bin = "{0:{fill}16b}".format(offset, fill="0")
    bin = "11"+bin[2:]
    return encode_int(int(bin, 2),2)

def encode_int(i, length):
    return i.to_bytes(length, byteorder='big')

def encode_url(url):
    b = bytes(0)
    for s in url.split("."):
        b += encode_int(len(s), 1)
        b += s.encode("utf-8")
    b += encode_int(0, 1)
    return b

def encode_class(clas):
    b = bytes(0)
    if (clas in DnsMessage.classes_r):
        b += encode_int(DnsMessage.classes_r[clas], 2)
    else:
        raise Exception("Class "+str(clas) + " not mapped")
    return b

def encode_type(typ):
    b = bytes(0)
    if (typ in DnsMessage.types_r):
        b += encode_int(DnsMessage.types_r[typ], 2)
    else:
        raise Exception("type "+str(typ) + " not mapped")
    return b

def encode_addr(addr):
    b = bytes(0)
    length=0

    addr_l = addr.split(".")
    if (len(addr_l) == 4):
        length = 4
        for p in addr_l:
            b += int(p).to_bytes(1, byteorder='big')
    else:
        addr_l = addr.split(":")
        if (len(addr_l) == 8):
            length = 16
            for p in addr_l:
                b += bytes.fromhex(p)
        else:
            raise Exception("Unknown separator on " + addr)
    return b, length


class DnsMessage(object):
    """docstring for Request."""
    classes = {1:"IN"}
    classes_r = dict()
    for key, item in classes.items():
        classes_r[item] = key
    types = {1:"A", 2:"NS", 28:"AAAA"}
    types_r = dict()
    for key, item in types.items():
        types_r[item] = key

    def __init__(self, transaction_id, flags=256, queries=[], answers=[], authorities=[], additionals=[]):
        super(DnsMessage, self).__init__()
        self.transaction_id = transaction_id
        self.flags = flags

        self.queries = queries

        self.answers = answers

        self.authorities = authorities

        self.additionals = additionals


    @staticmethod
    def from_bytes(bytes):
        transaction_id, off = decode_int(bytes, 0, 2)
        flags, off = decode_int(bytes, 2, 2)
        questions, off = decode_int(bytes, 4, 2)
        answer_rrs, off = decode_int(bytes, 6, 2)
        authority_rrs, off = decode_int(bytes, 8, 2)
        additional_rrs, off = decode_int(bytes, 10, 2)
        queries, off = Query.from_bytes(bytes, 12, questions)
        i = 12 + off
        answers, off = Answer.from_bytes(bytes, i, answer_rrs)
        i += off
        authorities, off = Authority.from_bytes(bytes, i, authority_rrs)
        i += off
        additionals, off = Additional.from_bytes(bytes, i, additional_rrs)
        i += off
        return DnsMessage(transaction_id, flags, queries, answers, authorities, additionals)


    def to_bytes(self):
        urls = dict()
        data = bytes(0)
        data += encode_int(self.transaction_id,2)
        data += encode_int(self.flags,2)
        data += encode_int(len(self.queries),2)
        data += encode_int(len(self.answers),2)
        data += encode_int(len(self.authorities),2)
        data += encode_int(len(self.additionals),2)
        i = 12

        for q in self.queries:
            b = q.to_bytes()
            urls[q.url] = i
            i += len(b)
            data += b

        for a in self.answers:
            data += a.to_bytes(urls.get(a.url))

        for a in self.authorities:
            data += a.to_bytes()

        for a in self.additionals:
            data += a.to_bytes()
        return data

    def __repr__(self):
        s = ""
        s += "transaction_id = " + str(self.transaction_id) + "\n"
        s += "flags = " + str(self.flags) + "\n"
        s += "questions = " + str(len(self.queries)) + "\n"
        s += "answer_rrs = " + str(len(self.answers)) + "\n"
        s += "authority_rrs = " + str(len(self.authorities)) + "\n"
        s += "additional_rrs = " + str(len(self.additionals)) + "\n"
        for q in self.queries:
            s += str(q)
        for a in self.answers:
            s += str(a)
        for a in self.authorities:
            s += str(a)
        for a in self.additionals:
            s += str(a)

        return s

class Query(object):

    def __init__(self, url, typ, clas):
        self.url = url
        self.type = typ
        self.clas = clas

    def get_hierarchy(self):
        return self.url.split(".")

    @staticmethod
    def from_bytes(bytes, offset, questions):
        queries = []
        i = offset
        for j in range(0,questions):
            url, off = decode_url(bytes, i)
            i += off
            typ, off = decode_type(bytes, i)
            i += off
            clas, off = decode_class(bytes, i)
            i += off
            queries.append(Query(url, typ, clas))
        return queries, i-offset

    def to_bytes(self):
        b = bytes(0)
        b += encode_url(self.url)
        b += encode_type(self.type)
        b += encode_class(self.clas)
        return b

    def __repr__(self):
        s = ""
        s += "Query: " + self.url
        s += " " + str(self.type)
        s += " " + str(self.clas)
        s += "\n"
        return s

class Answer(object):
    """docstring for Answer."""
    def __init__(self, url, typ, clas, ttl, addr):
        super(Answer, self).__init__()
        self.url = url
        self.type = typ
        self.clas = clas
        self.ttl = ttl
        self.addr = addr

    @staticmethod
    def from_bytes(bytes, offset, n_answers):
        answers = []
        i = offset
        for j in range(n_answers):
            url, off = decode_url(bytes, i)
            i += off

            typ, off = decode_type(bytes, i)
            i += off

            clas, off = decode_class(bytes, i)
            i += off

            ttl, off = decode_int(bytes, i, 4)
            i += off

            addr_len, off = decode_int(bytes, i, 2)
            i += off

            addr, off = decode_addr(bytes, i, addr_len)
            i += off

            answers.append(Answer(url, typ, clas, ttl, addr))

        return answers, i-offset

    def to_bytes(self, url_location=None):
        b = bytes(0)
        if (url_location is not None):
            b += encode_pointer(url_location)
        else:
            b += encode_url(self.url)
        b += encode_type(self.type)
        b += encode_class(self.clas)
        b += encode_int(self.ttl, 4)
        addr, addr_len = encode_addr(self.addr)
        b += encode_int(addr_len, 2)
        b += addr
        return b

    def __repr__(self):
        s = ""
        s += "Answer: " + self.url
        s += " " + str(self.type)
        s += " " + str(self.clas)
        s += ": " + str(self.addr)
        s += "\n"
        return s

class Authority(object):
    """docstring for authorities."""
    def __init__(self, name, typ, clas, ttl, name_server):
        super(Authority, self).__init__()
        self.name = name
        self.type = typ
        self.clas = clas
        self.ttl = ttl
        self.name_server = name_server

    @staticmethod
    def from_bytes(bytes, offset, n_authorities):
        authorities = []
        i = offset
        for j in range(n_authorities):
            name, off = decode_url(bytes, i)
            i += off

            typ, off = decode_type(bytes, i)
            i += off

            clas, off = decode_class(bytes, i)
            i += off

            ttl, off = decode_int(bytes, i, 4)
            i += off

            lenght, off = decode_int(bytes, i, 2) #not used
            i += off

            name_server, off = decode_url(bytes, i)
            i += off
            authorities.append(Authority(name, typ, clas, ttl, name_server))
        return authorities, i-offset

    def to_bytes(self, url_location=None):
        b = bytes(0)
        b += encode_url(self.name)
        b += encode_type(self.type)
        b += encode_class(self.clas)
        b += encode_int(self.ttl, 4)
        b += encode_int(len(self.name_server)+2, 2) #Tam do NS
        b += encode_url(self.name_server)
        return b

    def __repr__(self):
        s = ""
        s += "Authority: " + self.name
        s += " " + str(self.type)
        s += " " + str(self.clas)
        s += ": " + str(self.name_server) + "\n"
        return s

class Additional(object):
    """docstring for Additional."""
    def __init__(self, name, typ, clas, ttl, addr):
        super(Additional, self).__init__()
        self.name = name
        self.type = typ
        self.clas = clas
        self.ttl = ttl
        self.addr = addr

    @staticmethod
    def from_bytes(bytes, offset, n_additionals):
        additionals = []
        i = offset
        for j in range(n_additionals):
            name, off = decode_url(bytes, i)
            i += off

            typ, off = decode_type(bytes, i)
            i += off

            clas, off = decode_class(bytes, i)
            i += off

            ttl, off = decode_int(bytes, i, 4)
            i += off

            lenght, off = decode_int(bytes, i, 2) #not used
            i += off

            addr, off = decode_addr(bytes, i, lenght)
            i += off
            additionals.append(Additional(name, typ, clas, ttl, addr))
        return additionals, i-offset

    def to_bytes(self, url_location=None):
        b = bytes(0)
        b += encode_url(self.name)
        b += encode_type(self.type)
        b += encode_class(self.clas)
        b += encode_int(self.ttl, 4)
        addr, addr_len = encode_addr(self.addr)
        b += encode_int(addr_len, 2)
        b += addr
        return b

    def __repr__(self):
        s = ""
        s += "Additional: " + self.name
        s += " " + str(self.type)
        s += " " + str(self.clas)
        s += ": " + str(self.addr) + "\n"
        return s
