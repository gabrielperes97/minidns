class Request(object):
    """docstring for Request."""

    def __init__(self, transaction_id, flags=256, questions=0, answer_rrs=0, authority_rrs=0, additional_rrs=0, queries={}):
        super(Request, self).__init__()
        self.transaction_id = transaction_id
        self.flags = flags
        self.questions = questions
        self.answer_rrs = answer_rrs
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs
        self.queries = queries

    @staticmethod
    def from_bytes(bytes):
        transaction_id = int.from_bytes(bytes[0:2], byteorder='big')
        flags = int.from_bytes(bytes[2:4], byteorder='big')
        questions = int.from_bytes(bytes[4:6], byteorder='big')
        answer_rrs = int.from_bytes(bytes[6:8], byteorder='big')
        authority_rrs = int.from_bytes(bytes[8:10], byteorder='big')
        additional_rrs = int.from_bytes(bytes[10:12], byteorder='big')
        queries = Query.from_bytes(bytes[12:], questions)

        return Request(transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs, queries)


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


class Response(object):
    """docstring for Response."""
    def __init__(self, arg):
        super(Response, self).__init__()
        self.arg = arg

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
            url = ""
            while (int(bytes[i]) != 0):
                k = i + int(bytes[i])+1
                url += bytes[i+1:k].decode("utf-8") + "."
                i = k

            url = url[0:-1] #Tira o ultimo ponto
            i += 1
            typ = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (typ == 1):
                typ = "A"
            else:
                raise Exception("type "+str(typ) + " not mapped")
            i += 2
            clas = int.from_bytes(bytes[i:i+2], byteorder='big')
            if (clas == 1):
                clas = "IN"
            else:
                raise Exception("clas "+str(clas) + " not mapped")
            i += 2
            queries.append(Query(url, typ, clas))
        return queries

    def to_bytes(self):
        b = bytes(0)
        for s in self.url.split("."):
            b += len(s).to_bytes(1, byteorder='big')
            b += s.encode("utf-8")
        b += (0).to_bytes(1, byteorder='big')
        if self.type == "A":
            b += (1).to_bytes(2, byteorder='big')
        else:
            raise Exception("type "+str(typ) + " not mapped")
        if (self.clas == "IN"):
            b += (1).to_bytes(2, byteorder='big')
        else:
            raise Exception("type "+str(typ) + " not mapped")
        return b

    def __repr__(self):
        s = ""
        s += "Query: " + self.url
        s += " " + str(self.type)
        s += " " + str(self.clas)
        return s
