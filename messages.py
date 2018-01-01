def resolve_pointer(bytes, offset):
    #Dado em binário
    bin = "{0:b}".format(int.from_bytes(bytes[offset:offset+2], byteorder='big'))
    if (bin[0:2] == "11"): #é um ponteiro
        bin = "00"+bin[2:]
        return int(bin, 2), True
    else:
        return offset, False

def decode_int(bytes, offset, length):
    return int.from_bytes(bytes[offset:offset+length], byteorder='big'), length

def decode_url(bytes, offset):
    i, is_pointer = resolve_pointer(bytes, offset)
    tam = 0

    url = []
    while (int(bytes[i]) != 0):
        k = i + int(bytes[i])+1
        url.append(bytes[i+1:k].decode("utf-8"))
        tam += k-i
        i = k
    url = ".".join(url)
    tam += 1
    return url, 2 if is_pointer else tam

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
    for k in range(length):
        addr.append(str(decode_int(bytes, i, 1)[0]))
        i += 1
    separator = ""
    if (length == 4):
        separator = "."
    else:
        separator = ":"
    addr = separator.join(addr)
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

    addr_l = addr.split(".")
    if (addr_l == 1):
        addr_l = addr.split(":")
        if(addr_l == 1):
            raise Exception("Unknown separator on " + addr)
    for p in addr_l:
        b += int(p).to_bytes(1, byteorder='big')
    return b, len(addr_l)


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
        self.authority_rrs = len(authorities)

        self.additionals = additionals
        self.additional_rrs = len(additionals)


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
        return DnsMessage(transaction_id, flags, queries, answers)


    def to_bytes(self):
        urls = dict()
        data = bytes(0)
        data += encode_int(self.transaction_id,2)
        data += encode_int(self.flags,2)
        data += encode_int(len(self.queries),2)
        data += encode_int(len(self.answers),2)
        data += encode_int(self.authority_rrs,2)
        data += encode_int(self.additional_rrs,2)
        i = 12
        for q in self.queries:
            b = q.to_bytes()
            urls[q.url] = i
            i += len(b)
            data += b
        for a in self.answers:
            data += a.to_bytes(urls.get(a.url))
        return data

    def __repr__(self):
        s = ""
        s += "transaction_id = " + str(self.transaction_id) + "\n"
        s += "flags = " + str(self.flags) + "\n"
        s += "questions = " + str(len(self.queries)) + "\n"
        s += "answer_rrs = " + str(len(self.answers)) + "\n"
        s += "authority_rrs = " + str(self.authority_rrs) + "\n"
        s += "additional_rrs = " + str(self.additional_rrs) + "\n"
        for q in self.queries:
            s += str(q)
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

class CompressionTable(object):
    """docstring for CompressionTable."""
    def __init__(self, arg):
        super(CompressionTable, self).__init__()
        self.arg = arg
