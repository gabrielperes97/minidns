
def verify_pointer(bytes, offset):
    return "{0:b}".format(int.from_bytes(bytes[offset:offset+2], byteorder='big'))[0:2]=="11"

def resolve_pointer(bytes, offset):
    #Dado em binário
    bin = "{0:b}".format(int.from_bytes(bytes[offset:offset+2], byteorder='big'))
    if (bin[0:2] == "11"): #é um ponteiro
        bin[0] = "0"
        bin[1] = "0"
        return int(bin, 2), True
    else:
        return offset, False

def decode_int(bytes, offset, length):
    i, is_pointer = resolve_pointer(bytes, offset)
    return int.from_bytes(bytes[i:i+length], byteorder='big'), 2 if is_pointer else length

def decode_url(bytes, offset):
    i, is_pointer = resolve_pointer(bytes, offset)
    tam = 0

    url = []
    while (int(bytes[i]) != 0):
        k = i + int(bytes[i])+1
        url.append(bytes[i+1:k].decode("utf-8"))
        i = k
        tam += 1
    url = ".".join(url)
    tam += 1
    return url, 2 if is_pointer else tam

def decode_class(bytes, offset):
    clas = int.from_bytes(bytes[i:i+2], byteorder='big')
    if (clas in DnsMessage.classes):
        clas = DnsMessage.classes[clas]
    else:
        raise Exception("clas "+str(clas) + " not mapped")
    return clas, 2

def decode_type(bytes, offset):
    typ = int.from_bytes(bytes[i:i+2], byteorder='big')
    if (typ in DnsMessage.types):
        typ = DnsMessage.types[typ]
    else:
        raise Exception("type "+str(typ) + " not mapped")
    return typ, 2


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
        self.questions = len(queries)

        self.answers = answers
        self.answer_rrs = len(answers)

        self.authorities = authorities
        self.authority_rrs = len(authorities)

        self.additionals = additionals
        self.additional_rrs = len(additionals)


    @staticmethod
    def from_bytes(bytes):
        transaction_id = int.from_bytes(bytes[0:2], byteorder='big')
        flags = int.from_bytes(bytes[2:4], byteorder='big')
        questions = int.from_bytes(bytes[4:6], byteorder='big')
        answer_rrs = int.from_bytes(bytes[6:8], byteorder='big')
        authority_rrs = int.from_bytes(bytes[8:10], byteorder='big')
        additional_rrs = int.from_bytes(bytes[10:12], byteorder='big')
        queries, piece = Query.from_bytes(bytes[12:], questions)
        answers, pieces = Answer.from_bytes(piece, answer_rrs)
        return DnsMessage(transaction_id, flags, queries, answers)


    def to_bytes(self):
        data = bytes(0)
        data += self.transaction_id.to_bytes(2, byteorder='big')
        data += self.flags.to_bytes(2, byteorder='big')
        data += self.questions.to_bytes(2, byteorder='big')
        data += self.answer_rrs.to_bytes(2, byteorder='big')
        data += self.authority_rrs.to_bytes(2, byteorder='big')
        data += self.additional_rrs.to_bytes(2, byteorder='big')
        for q in self.queries:
            data += q.to_bytes()
        for a in self.answers:
            data += a.to_bytes()
        return data

    def __repr__(self):
        s = ""
        s += "transaction_id = " + str(self.transaction_id) + "\n"
        s += "flags = " + str(self.flags) + "\n"
        s += "questions = " + str(self.questions) + "\n"
        s += "answer_rrs = " + str(self.answer_rrs) + "\n"
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
    def from_bytes(bytes, questions):
        queries = []
        i = 0
        for j in range(0,questions):
            url = []
            while (int(bytes[i]) != 0):
                k = i + int(bytes[i])+1
                url.append(bytes[i+1:k].decode("utf-8"))
                i = k
            url = ".".join(url)
            i += 1
            typ = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (typ in DnsMessage.types):
                typ = DnsMessage.types[typ]
            else:
                raise Exception("type "+str(typ) + " not mapped")
            i += 2
            clas = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (clas in DnsMessage.classes):
                clas = DnsMessage.classes[clas]
            else:
                raise Exception("clas "+str(clas) + " not mapped")
            i += 2
            queries.append(Query(url, typ, clas))
        return queries, bytes[i+1:]

    def to_bytes(self):
        b = bytes(0)
        for s in self.url.split("."):
            b += len(s).to_bytes(1, byteorder='big')
            b += s.encode("utf-8")
        b += (0).to_bytes(1, byteorder='big')

        if (self.type in DnsMessage.types_r):
            b += DnsMessage.types_r[self.type].to_bytes(2, byteorder='big')
        else:
            raise Exception("type "+str(self.type) + " not mapped")
        if (self.clas in DnsMessage.classes_r):
            b += DnsMessage.classes_r[self.clas].to_bytes(2, byteorder='big')
        else:
            raise Exception("class "+str(self.clas) + " not mapped")
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
    def from_bytes(bytes, n_answers):
        answers = []
        i = 0
        for i in range(n_answers):
            url = []
            while (int(bytes[i]) != 0):
                k = i + int(bytes[i])+1
                url.append(bytes[i+1:k].decode("utf-8"))
                i = k
            url = ".".join(url)
            i += 1
            typ = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (typ in DnsMessage.types):
                typ = DnsMessage.types[typ]
            else:
                raise Exception("type "+str(typ) + " not mapped")
            i += 2
            clas = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (clas in DnsMessage.classes):
                clas = DnsMessage.classes[clas]
            else:
                raise Exception("clas "+str(clas) + " not mapped")
            i += 2

            ttl = int.from_bytes(bytes[i:i+4], byteorder='big')
            i += 4

            addr_len = int.from_bytes(bytes[i:i+2], byteorder='big')
            i += 2

            addr = []
            for i in range(addr_len):
                addr.append(str(int.from_bytes(bytes[i:i+1], byteorder='big')))
                i += 1
            addr = ".".join(addr)

            answers.append(Answer(url, typ, clas, ttl, addr))

        return answers, bytes[i:]

        def to_bytes(self):
            b = bytes(0)
            for s in self.url.split("."):
                b += len(s).to_bytes(1, byteorder='big')
                b += s.encode("utf-8")
            b += (0).to_bytes(1, byteorder='big')

            if (self.type in DnsMessage.types_r):
                b += DnsMessage.types_r[self.type].to_bytes(2, byteorder='big')
            else:
                raise Exception("type "+str(self.type) + " not mapped")
            if (self.clas in DnsMessage.classes_r):
                b += DnsMessage.classes_r[self.clas].to_bytes(2, byteorder='big')
            else:
                raise Exception("class "+str(self.clas) + " not mapped")
            b += self.ttl.to_bytes(4, byteorder='big')

            if (len(addr = self.addr.split(".")) > 1):
                pass
            elif (len(addr = self.addr.split(":")) > 1):
                pass
            else:
                raise Exception("Unknown separator on " + self.addr)

            for p in addr:
                b += p.to_bytes(2, byteorder='big')

            return b
