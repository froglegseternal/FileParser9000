import weakref

def objectPairs(res):
    dic = {}
    for i in res:
        if i[0] in dic and isinstance(dic[i[0]],list):
            dic[i[0]] = dic[i[0]] + [i[1]]
        elif i[0]in dic:
            dic[i[0]] = [dic[i[0]]] + [i[1]]
        else:
            dic[i[0]] = i[1]
    return dic

def unpackByteSequence(seq):
    if len(seq) == 0:
        return seq
    if isinstance(seq, list):
        tmp = []
        for i in seq:
            tmp.append(unpackByteSequence(i))
        return tmp

    splitter = seq.split(":")
    
    splatter = b''
    for i in splitter:
        splatter += int(i,16).to_bytes()
    return splatter

class PacketDiss():
    def __init__(self, data):
        self.data = data
        self.expertnumber = 0
        self.wsgroup = {}
        self.wsmessage = {}
        self.wssevlevel = {}
        self.wsbase = {}
    def __str__(self):
        builder = "-"*45+self.typ + "-"*45+"\n"
        return builder
    def doProcessExpert(self, key, value, number = 0):
        match key[11:]: #_ws.expert.X
            case "group":
                self.wsgroup[number] = int(value)
            case "message":
                self.wsmessage[number] = value
                #print(f"_ws.expert.message",value)
            case "severity":
                self.wssevlevel[number] = int(value)
            case "":
                self.wsbase[number] = value
            case _:
                raise Exception(f"Unknown wireshark expert key {key} with value {value}")
    def doProcessMalformed(self, key, value):
        match key[14:] : #_ws.malformed.X
            case _:
                raise Exception(f"Unknown wireshark malformed packet key {key} with value {value}")
    def doCheck(self):
        pass

def keyParser(key):
    if ":" in key:
        print(key)
        key = key.split(":")[0]
        print(key)
    if "[" in key:
        print(key)
        key = key.split("[")[0]
        print(key)
    return key

class DataFrame(PacketDiss):
    trees = ['_ws.expert','Timestamps']
    hexints = {}
    ints = hexints
    byteseqs = {}
    framerefs = {}
    ipv6_addrs = {}
    strs = {}
    keyvals = {"ber.bitstring.padding":("ber_bitstring_padding","uint8"), #Padding
            }
    def __init_subclass__(cls, keyvals={}, **kwargs):
        cls.keyvals = cls.__bases__[0].keyvals.copy()
        cls.keyvals.update(keyvals)
        if len(cls.keyvals) > 1:
            for i in cls.__bases__[1:]:
                cls.keyvals.update(i.keyvals)
        super().__init_subclass__(**kwargs)
    

    def __init__(self, data, frame):
        super().__init__(data)
        self.framenum = int(frame)
        self.keyvals = self.keyvals.copy()
        s1 = set(self.keyvals.keys())
        s2 = set(data.keys())
        if not set(data.keys()) <= set(self.keyvals.keys()):
            try:
                for i in s2-s1:
                    test = keyParser(i)
                    if test != i:
                        self.data[test] = self.data[i]
                        del self.data[i]
                    s2 = set(data.keys())
                assert len(s2-s1) == 0
            except:
                print(s2-s1)
                raise Exception(f"Unimplemented key values in class {type(self)}")
        for i in self.keyvals:
            if i in data:
                if "uint" in self.keyvals[i][1]:
                    self.assignValue(self.keyvals[i][0], self.getInt(data[i],i,self.keyvals),self.keyvals, i)
                elif "int" in self.keyvals[i][1]:
                    self.assignValue(self.keyvals[i][0], self.getInt(data[i], i, self.keyvals,signed=True),self.keyvals, i)
                elif "tree" == self.keyvals[i][1]:
                    self.doTreeBetter(data[i], self.keyvals[i][0], i)
                elif "byteseq" == self.keyvals[i][1]:
                    if self.keyvals[i][0] not in self.__dict__:
                        self.__dict__[self.keyvals[i][0]] = unpackByteSequence(data[i])
                    else:
                        if not isinstance(self.__dict__[self.keyvals[i][0]],list):
                            self.__dict__[self.keyvals[i][0]] = [self.__dict__[self.keyvals[i][0]]]
                        self.__dict__[self.keyvals[i][0]].append(unpackByteSequence(data[i]))
                    self.__dict__[self.keyvals[i][0]] = unpackByteSequence(data[i])
                elif self.keyvals[i][1] in ["str","datetime","MAC","IPV4"]:
                    self.assignValue(self.keyvals[i][0], self.getStr(data[i],i),self.keyvals,i)
                elif "bool" == self.keyvals[i][1]:
                    self.__dict__[self.keyvals[i][0]] = bool(int(data[i]))
                elif "Specialtree" == self.keyvals[i]:
                    self.doTree(data[i], i)
                elif "subtype" == self.keyvals[i][1]:
                    if self.keyvals[i][0] not in self.__dict__:
                        self.__dict__[self.keyvals[i][0]] = self.keyvals[i][2](data[i])
                    else:
                        if not isinstance(self.__dict__[self.keyvals[i][0]],list):
                            self.__dict__[self.keyvals[i][0]] = [self.__dict__[self.keyvals[i][0]]]
                        self.__dict__[self.keyvals[i][0]].append(self.keyvals[i][2](data[i]))
                else:
                    raise Exception("Unimplemented keyval type "+self.keyvals[i][1])
        for i in self.ints:
            self.keyvals.update({i: (self.ints[i],"int")})
            if i in data:
                self.assignValue(self.ints[i], self.getInt(data[i],i),self.ints, i)
        for i in self.trees:
            self.keyvals.update({i: "Specialtree"})
            if i in data:
                self.doTree(data[i], i)
        for i in self.byteseqs:
            self.keyvals.update({i: (self.byteseqs[i],"byteseq")})
            if i in data:
                self.__dict__[self.byteseqs[i]] = unpackByteSequence(data[i])
        for i in self.ipv6_addrs:
            self.keyvals.update({i: (self.ipv6_addrs[i], "ipv6_addr")})
            if i in data:    
                self.__dict__[self.ipv6_addrs[i]] = data[i]
        for i in self.strs:
            self.keyvals.update({i: (self.strs[i], "str")})
            if i in data:
                self.assignValue(self.strs[i], self.getStr(data[i],i),self.strs, i)
    def doTree(self, tree, treename):
        raise Exception(f"This should never be called. A tree of name {treename} made its way to the base DataFrame class. The type of this object is "+self.typ)

    def doTreeBetter(self, tree, keytree, treename):
        for i in tree:
            if i not in keytree:
                print("Unknown key in tree", treename, "with key", i)
            elif "uint" in keytree[i][1]:
                self.assignValue(keytree[i][0], self.getInt(tree[i],i,keytree),keytree, i)
            elif "int" in keytree[i][1]:
                self.assignValue(keytree[i][0], self.getInt(tree[i],i,keytree,signed=True),keytree, i)
            elif "tree" == keytree[i][1]:
                self.doTreeBetter(tree[i], keytree[i][0], i)
            elif "byteseq" == keytree[i][1]:
                self.__dict__[keytree[i][0]] = unpackByteSequence(tree[i])
            elif "str" == keytree[i][1]:
                self.assignValue(keytree[i][0], self.getStr(tree[i],i),keytree,i)
            elif "bool" == keytree[i][1]:
                self.__dict__[keytree[i][0]] = bool(int(tree[i]))
            elif "Specialtree" == keytree[i]:
                self.doTree(tree, treename)
            elif "subtype" == keytree[i][1]:
                    if keytree[i][0] not in self.__dict__:
                        if not isinstance(tree[i], list):
                            self.__dict__[keytree[i][0]] = keytree[i][2](tree[i])
                        else:
                            self.__dict__[keytree[i][0]] = [keytree[i][2](x) for x in tree[i]]
                    else:
                        if not isinstance(self.__dict__[keytree[i][0]],list):
                            self.__dict__[keytree[i][0]] = [self.__dict__[keytree[i][0]]]
                        self.__dict__[keytree[i][0]].append(keytree[i][2](tree[i]))

            else:
                raise Exception("Unimplemented")

    def getInt(self, integer, parent=None, keytree=None, signed=False):
        if (isinstance(integer, int) or isinstance(integer, str)) and signed:
            if "0x" in integer:
                return int.from_bytes(bytes.fromhex(integer[2:]), signed=True)
            else:
                return int(integer)
        if isinstance(integer, int) or isinstance(integer, str):
            if "x" in integer:
                return int(integer, 16)
            else:
                return int(integer)
        elif isinstance(integer, dict):
            if keytree is None:
                for i in self.data[parent]:
                    if i in self.ints[parent] or (parent in self.keyvals and i in self.keyvals[parent] and "uint" in self.keyvals[i]):
                        self.__dict__[self.ints[parent][i]] = self.getInt(self.data[parent][i])
                    elif i not in self.ints[parent] and (parent not in self.strs or i not in self.strs[parent]) and (parent not in self.keyvals or i not in self.keyvals[parent]):
                        raise Exception("unknown key in class "+self.typ+" with key value "+str(i)+ " in tree "+str(parent))
            else:
                for i in self.data[parent]:
                    if i in keytree:
                        self.__dict__[keytree[i][0]] = self.getInt(self.data[parent][i])
                    else:
                        raise Exception("Unknown key in class "+self.typ+" with key value "+str(i)+" in tree "+str(parent))
            return None
        elif isinstance(integer, list):
            tmp = integer
            for i in range(len(tmp)):
                tmp[i] = self.getInt(tmp[i])
            return tmp
        else:
            print(integer)
            print(type(integer))
            raise Exception("Invalid type exception")
    def getStr(self, string, parent=None):
        if isinstance(string, str):
            return string
        elif isinstance(string, dict):
            for i in self.data[parent]:
                if i in self.strs[parent]:
                    self.__dict__[self.strs[parent][i]] = self.getStr(self.data[parent][i])
                elif i not in self.strs[parent] and (parent not in self.ints or i not in self.ints[parent]) and (parent not in self.keyvals or i not in self.keyvals[parent]):
                    print("unknown key in class",self.typ,"with key value",i,"in tree", parent)
            return None
        elif isinstance(string, list):
            return string
        else:
            raise Exception("InvalidTypeException")
    def assignValue(self, parent, result, dictionary, key):
        if result is not None and parent not in self.__dict__:
            self.__dict__[parent] = result
        elif parent in self.__dict__:
            raise Exception("Unimplemented")
        else:
            pass
    def __str__(self):
        builder = super().__str__()
        return builder

    @classmethod
    def initialKeyvalCreation(cls, dicky):
        cls.keyvals = cls.__bases__[0].keyvals.copy()
        cls.keyvals.update(dicky)
        if len(cls.keyvals) > 1:
            for i in cls.__bases__[1:]:
                cls.keyvals.update(i.keyvals)

class DataSubtype(DataFrame):
    def __init__(self, data, frame=-1):
        super().__init__(data, frame)

tmp = {"dns.cname":("cname","str"), #CNAME
                    "dns.mx.mail_exchange":("mxme","str"), #Mail Exchange
                    "dns.ptr.domain_name":("ptr_dom_name","str"), #Domain Name (Character string)
                    "dns.srv.name":("srvname","str"), #Name
                    "dns.srv.proto":("srvproto","str"), #Protocol
                    "dns.srv.service":("srvservice","str"), #Service
                    "dns.srv.target":("srvtarget", "str"), #Target
                    "nbns.name": ("name","str"), #Name
                    "dns.count.labels":("labelcount","uint16"), #Label Count
                    "dns.mx.preference":("mxpref","uint16"), #Preference
                    "dns.srv.port":("srvport","uint16"), #Port
                    "dns.srv.priority":("srvprior","uint16"), #Priority
                    "dns.srv.weight":("srvweight","uint16"), #Weight
                    "nbns.class":("clas","uint16"), #Class
                    "nbns.type":("type","uint16"), #Type
                   } 
class DNSRecord(DataFrame, keyvals=tmp):
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.doTree(value, key)
    def doTree(self, tree, treename=None):
        for i in tree:
            if i in self.keyvals:
                continue
            match i:
                case 'dns.a': #Address (IPv4 address)
                    self.addr = tree[i]
                case 'dns.aaaa': #AAAA Address (IPv6 address)
                    self.aaaa = tree[i]
                case _:
                    print("Unknown DNSRecord key", i)

class DNSQuery(DNSRecord):
    keyvals = DNSRecord.keyvals.copy()
    keyvals.update({"dns.qry.class":("clas","uint16"), #Class
                    "dns.qry.name.len":("name_len", "uint16"), #Name Length
                    "dns.qry.type":("typ", "uint16"), #Type
                    "dns.qry.name":("name", "str"), #Name
                    "dns.qry.qu":("qu","bool"), #"QU" question
                    })
    def doTree(self, tree, treename):
       super().doTree({x: tree[x] for x in tree if "dns.qry." not in x})
       for i in {x: tree[x] for x in tree if "dns.qry." in x}:
           if i in self.keyvals:
               continue
           match i[8:]:
               case _:
                   print("Unknown DNSQuery key", i)

class DNSAnswer(DNSRecord):
    keyvals = DNSRecord.keyvals.copy()
    keyvals.update({"dns.resp.cache_flush":("cache_flush","bool"), #Cache flush
                    "dns.resp.z.do":("zdo","bool"), #DO bit
                    "dns.resp.ttl":("ttl","uint32"), #Time to live
                    "dns.resp.class":("clas","uint16"), #Class
                    "dns.resp.len":("resp_len","uint16"), #Data Length
                    "dns.resp.type":("typ","uint16"), #Type
                    "dns.resp.z":("z","uint16"), #Z
                    "dns.resp.z.reserved":("zreserv","uint16"), #Reserved
                    "dns.resp.edns0_version":("ednsver","uint8"), #EDNS0 version
                    "dns.resp.ext_rcode":("extrcode","uint8"), #Higher bits in extended RCODE
                    "dns.resp.name":("name","str"), #Name
                    "dns.resp.z_tree":"Specialtree",
                    })
    def doTree(self, tree, treename=None):
        super().doTree({x: tree[x] for x in tree if "dns.resp." not in x})
        for i in {x: tree[x] for x in tree if "dns.resp." in x}:
            if i in self.keyvals:
                continue
            match i[9:]:
                case _:
                    print("Unknown DNSAnswer key", i)

class DNSAddRecord(DNSAnswer):
    def doTree(self, tree, treename):
        super().doTree({x: tree[x] for x in tree if "dns.rr." not in x})
        for i in {x: tree[x] for x in tree if "dns.rr." in x}:
            match i[7:]:
                case 'udp_payload_size': #UDP payload size (uint16)
                    self.ups = int(tree[i])
                case _:
                    raise Exception(f"Unknown DNSAddRecord key {i}")

class DNSAuth(DNSAnswer):
    keyvals = DNSAnswer.keyvals.copy()
    keyvals.update({"dns.soa.expire_limit":("explimit","uint32"), #Expire limit
                    "dns.soa.minimum_ttl":("minttl","uint32"), #Minimum TTL
                    "dns.soa.refresh_interval":("refint","uint32"), #Refresh Interval
                    "dns.soa.retry_interval":("retint","uint32"), #Retry interval
                    "dns.soa.serial_number":("serial","uint32"), #Serial Number
                    "dns.soa.mname":("mname","str"), #Primary name server
                    "dns.soa.rname":("rname","str"), #Responsible Authority's mailbox
                    })
    def doTree(self, tree, treename):
        super().doTree({x: tree[x] for x in tree if "dns.soa." not in x})
        for i in {x: tree[x] for x in tree if "dns.soa." in x}:
            match i[8:]:
                case _:
                    raise Exception(f"Unknown DNSAuth key "+i)

   
class Data(DataFrame):
    def __init__(self, data, frame=-1):
        super().__init__(data, frame)
        #if self.framenum != -1: print(f"Frame number: {self.framenum}")
        for i in self.data:
            match i:
                case 'data.data': #Data
                    self.realdata = unpackByteSequence(self.data[i])
                case 'data.len': #???
                    self.len = self.data[i]
                case _:
                    pass
                    #print("Unknown data key ",i)

class gss_api(): #GSS-API Generic Security Service Application Program Interface
    def __init__(self, data):
        self.data = data
        for i in data:
            if i[0:12] == 'spnego.krb5.': #spnego.krb5.X
                if 'krb5' not in self.__dict__:
                    self.krb5 = krb5()
                self.krb5[i] = data[i]
            else:
                match i:
                    case 'gss-api.OID': #OID
                        self.oid = data[i]
                    case _:
                        print("Unknown GSS_API key: ",i)
    def doTree(self, tree, treename):
        print("Unknown behavior for gss_api")

class Malformed(DataFrame):
    def doMoarInit(self):
        for i in self.data:
            match i:
                case _:
                    print("Unknown wireshark malformed packet key", i)
    def doTree(self, tree, treename):
        if treename == "_ws.expert":
            self.expertnumber += 1
            for i in tree:
                if "_ws.expert" in i:
                    self.doProcessExpert(i, tree[i], self.expertnumber)
                else:
                    match i:
                        case "_ws.malformed.reassembly": #Reassembly error (Label)
                            self.reassemblyError = True
                        case _:
                            print("unknown key in Malformed packet _ws.expert tree with name", i, "and value", tree[i])
        else:
            print("Unknown tree in Malformed packet with treename", treename)



class MIME(DataSubtype):
    def __init__(self, data, packet=-1):
        super().__init__(data, packet)
        self.headers = []
        for i in self.data:
            match i[15:]: #mime_multipart.X
                case 'boundary': #Boundary
                    self.bound = self.data[i]
                case 'first_boundary': #First boundary
                    self.firstBound = self.data[i]
                case 'last_boundary': #Last boundary
                    self.lastBound = self.data[i]
                case 'part':
                    if isinstance(self.data[i], list):
                        self.partdata = []
                        for j in self.data[i]:
                            if j.encode() != b'':
                                self.partdata += [j]
                                print(j.encode())
                    elif self.data[i].encode() != b'':
                            self.partdata = self.data[i]
                            print(self.data[i].encode())
                case 'part_tree':
                    self.doTree(self.data[i],'part_tree')
                    if 'media' in self.__dict__: self.doMedia(self.media)
                case 'preamble':
                    self.data['mime_multipart.preamble'] = unpackByteSequence(self.data[i])
                case 'type':
                    self.type = self.data[i]
                    if self.type == "multipart/encrypted":
                        self.encrypted = True
                    elif self.type == 'multipart/mixed':
                        self.mixed_content = True
                    else:
                        print(self.type)
                case _:
                    if i == "The multipart dissector could not decrypt the message.":
                        self.undecryptable = True
                        self.doTree(self.data[i], 'The multipart dissector could not decrypt the message.')
                    else:
                        print(f"Unknown MIME key {i}")

    def __str__(self):
        builder = ""
        builder += f"\nContent type(s): {self.header['contenttype']}"
        builder += f"\nTransfer Encoding: {self.header['transferencoding']}"
        builder += f"\nContent Disposition: {self.header['contentdisp']}"
        builder += f"\nContent ID: {self.header['contentid']}"
        builder += f"\nMedia: {self.media}"
        return builder

    def doTree(self, tree, treename):
        self.headers.append(tree) #Very temporary solution
        """for i in tree.keys():
            if i[0:22] == "mime_multipart.header.":
                match i[22:]:
                    case "content-disposition":
                        self.header['contentdisp'] = tree[i]
                    case "content-id":
                        self.header['contentid'] = tree[i]
                    case "content-transfer-encoding":
                        self.header['transferencoding'] = tree[i]
                    case "content-type":
                        self.header['contenttype'] = tree[i]
                    case 'sectoken-length':
                        self.header['sectokenlen'] = tree[i]
                    case _:
                        print(f"Unknown MIME {treename} header key {i}")
            elif i == 'gss-api': #gss-api ???
                if 'gss_api' not in self.__dict__:
                    self.gss_api = gss_api(tree[i])
                else:
                    self.gss_api.doTree(tree[i], 'gss-api')
            else:
                match i:
                    case '_ws.expert': #???
                        self.expertnumber+=1
                        for j in tree[i]:
                            if "_ws.expert" in j:
                                self.doProcessExpert(j, tree[i][j], self.expertnumber)
                            else:
                                match j:
                                    case 'mime_multipart.decryption_not_possible':
                                        self.undecryptable = True
                                    case _:
                                         print(f"Unknown MIME tree key in wireshark expert subtree {j}")
                    case 'data': #???
                        self.partdata = Data(tree[i])
                    case 'media': #???
                        self.media = tree[i]
                    case _:
                        print(f"Unknown MIME {treename} key {i}")"""
    def doMedia(self, media):
        for i in media.keys():
            match i:
                case 'media.type':
                    temp = unpackByteSequence(media[i])
                    temp = temp.decode().replace("\r\n","")
                    if self.header['transferencoding'] == 'base64':
                        import base64
                        temp = base64.b64decode(temp)
                    self.media = temp
                case _:
                    print(f"Unknown media key {i}")


class krb5():
    def __init__(self):
        self.blobs = []
    def __setitem__(self, key, val):
        if key[0:12] == 'spnego.krb5.': #spnego.krb5.X
            match key[12:]:
                case 'blob': #krb5_blob
                    self.blobs.append(krbblob(val))
                case 'blob_tree': #???
                    self.blobs.append(krbblob(val, parent='spnego.krb5.blob_tree'))
                case _:
                    print(f"Unknown spnego (krb5) key {key} in krb5 obj with value {val}")
        else:
            print(f"Unknown krb5 subobject {key} with value {val}")

class krbblob():
    def __init__(self, value, parent=None):
        self.spnego = {}
        self.ap_rep = ap_rep()
        self.ap_request = ap_req()
        if parent is None:
            self.data = unpackByteSequence(value)
            self.parent = None
        else:
            self.parent = parent
            self.doTree(value, parent)
    def __setitem__(self, key, val):
        if key[0:12] == 'spnego.krb5.': #spnego.krb5.X
            match key[12:]:
                case 'acceptor_subkey': #AcceptorSubkey
                    self.spnego['acc_subk'] = bool(val)
                case 'cfx_flags': #krb5_cfx_flags
                    self.spnego['cfx_flags'] = int(val,16)
                case 'cfx_flags_tree': #krb5_cfx_flags_tree
                    self.doTree(val, 'spnego.krb5.cfx_flags_tree')
                case 'cfx_ec': #krb5_cfx_ec
                    self.spnego['cfx_ec'] = int(val, 16)
                case 'cfx_rrc': #krb5_cfx_rrc
                    self.spnego['cfx_rrc'] = int(val, 16)
                case 'cfx_seq': #krb5_cfx_seq
                    self.spnego['cfx_seq'] = int(val, 16)
                case 'filler': #krb5_filler
                    self.spnego['filler'] = unpackByteSequence(val)
                case 'sealed': #Sealed
                    self.spnego['sealed'] = bool(val)
                case 'send_by_acceptor': #SendByAcceptor
                    self.spnego['sendbyacc'] = bool(val)
                case 'sgn_cksum': #krb5_sgn_cksum
                    self.spnego['sgn_cksum'] = unpackByteSequence(val)
                case 'tok_id': #krb5_tok_id
                    self.spnego['tok_id'] = int(val,16)
                case _:
                    print(f"Unknown spnego (krb5) key {key} in subtree {treename}")
        elif key[0:9] == 'kerberos.': #kerberos.X
            match key[9:]:
                case 'ap_rep_element':
                    self.doTree(val, 'ap_rep_element')
                case 'ap_req_element':
                    self.doTree(val, 'ap_req_element')
                case 'msg_type': #msg-type
                    self.ap_rep = int(val, 16)
                case 'pvno': #pvno
                    self.ap_rep['pvno'] = int(val, 16)
                case _:
                    print(f"Unknown kerberos (krbblob) key {key} with value {val}")
        else:
            match key:
                case 'kerberos':
                    self.doTree(val, 'kerberos')
                case _:
                    print(f"Unknown krbblob subobject {key} with value {val}")

    def doTree(self, tree, treename):
        if treename == 'spnego.krb5.cfx_flags_tree':
            for i in tree:
                if 'spnego.krb5' not in i:
                    print('unknown key for spnego.krb5', i)
        elif treename == 'ap_rep_element':
            for i in tree:
                if i in self.ap_rep:
                    print('Repeat key for ap_rep_element', i)
                    self.ap_rep[i] = tree[i]
            return
        elif treename == 'ap_req_element':
            for i in tree:
                if i in self.ap_request:
                    self.ap_request[i] = tree[i]
        for i in tree:
            self[i] = tree[i]

tmp = {"kerberos.name_type":("name_type","int32"), #name-type
                    "kerberos.sname_string":("string","uint32"), #sname-string
                    "kerberos.sname_string_tree":({
                        "kerberos.SNameString":("name","str"), #SNameString
                        }, "tree"), #???
                    }
class sname(DataSubtype, keyvals=tmp):
    pass
elements = {"kerberos.sname_element":("elements","subtype",sname)} 


tmp = {"kerberos.cipher":("cipher","byteseq"), #cipher
                    "kerberos.etype":("etype","int32"), #etype
                    "kerberos.kvno":("kvno","uint32"), #kvno
                    "kerberos.realm":("realm","str"), #realm
                    "kerberos.crealm":("crealm","str"), #crealm
                    "kerberos.pvno":("pvno","uint32"), #pvno
                    "kerberos.msg_type":("msg_type","int32"), #msg-type
                    "kerberos.nonce":("nonce","uint32"), #nonce
                    "kerberos.rtime":("rtime","datetime"), #rtime
                    "kerberos.till":("till","datetime"), #till
                    }
class krb_subtype(DataSubtype, keyvals=tmp):
    pass 

#########################

class authenticator(krb_subtype):
    def __init__(self, data):
        super().__init__(data)
        print(self.data)

elements.update({"kerberos.authenticator_element":("elements","subtype",authenticator)})

##########################

class encData(krb_subtype):
    pass
elements.update({"kerberos.enc_part_element":("elements","subtype",encData)})


#####################
tmp = {"kerberos.tkt_vno":("tkt_vno","uint32"), #tkt-vno
                    }
tmp.update(elements)

class ticket(krb_subtype, keyvals=tmp):
    def __init__(self, data):
        super().__init__(data)

elements.update({"kerberos.ticket_element":("elements","subtype",ticket)})

#####################

tmp = {"kerberos.ap_options":("ap_opt","byteseq"), #ap-options
       "kerberos.ap_options_tree":({},"tree"), #???
       }
tmp.update(elements)
class ap_req(krb_subtype, keyvals=tmp):
    pass
elements.update({"kerberos.ap_req_element":("elements","subtype",ap_req)})

#######################

class ap_rep(krb_subtype):
    pass


########################

tmp = {"kerberos.padata_type":("type","int32"), #padata-type
        "kerberos.padata_type_tree":({
        "kerberos.padata_value":("value","byteseq"), #padata-value
        "kerberos.padata_value_tree":({
            "kerberos.ap_req_element":("elements","subtype",ap_req), #???
            "kerberos.cipher":("cipher","byteseq"), #cipher
                "kerberos.etype":("etype","int32"), #etype
                "kerberos.include_pac":("inc_pac","bool"), #include-pac
                }, "tree"), #???
            },"tree"), #???
        }
tmp.update(elements)
class padata(krb_subtype, keyvals=tmp):
    pass

######################

tmp = {"kerberos.cname_string":("string","uint32"), #cname-string
        "kerberos.cname_string_tree":({
            "kerberos.CNameString":("namestring","str"), #CNameString
        },"tree"), #???
        "kerberos.name_type":("name_type","int32"), #name-type
        }
tmp.update(elements)

class cname(krb_subtype, keyvals=tmp):
    def __init__(self, data):
        super().__init__(data)

elements.update({"kerberos.cname_element":("elements","subtype",cname)})

##################



tmp = {"kerberos.padata":("padata","uint32"), #padata
        "kerberos.padata_tree":({
            "kerberos.PA_DATA_element":("padata_s","subtype",padata), #PA-DATA
            },"tree"),
                    }
tmp.update(elements)
class as_rep(krb_subtype, keyvals=tmp):
    pass

tmp = {"kerberos.kdc-req-body.etype":("etype","uint32"), #etype
        "kerberos.kdc-req-body.etype_tree":({
            "kerberos.ENCTYPE":("enctype","int32"), #ENCTYPE
            },"tree"), #???
        "kerberos.kdc_options":("kdc_opt_base","byteseq"), #kdc-options
        "kerberos.kdc_options_tree":({
            "kerberos.KDCOptions.allow.postdate":("KDC_ALLOW_POSTDATE", "bool"), #allow-postdate
            "kerberos.KDCOptions.allow_postdate":("KDC_ALLOW_POSTDATE", "bool"), #Allow Postdate
        },"tree"), #???
                    "kerberos.kdc_req_body":({},"tree"), #KDC_REQ_BODY
                    "kerberos.cname_element":("cname","subtype",cname), #cname
                    "kerberos.sname_element":("elements","subtype",sname), #sname
                    }
class req_body(krb_subtype, keyvals=tmp):
    def __init__(self, data):
        super().__init__(data)
        if "kerberos.kdc_options_tree" in self.data:
            if "kerberos.KDCOptions.allow.postdate" in self.data["kerberos.kdc_options_tree"] and "kerberos.KDCOptions.allow_postdate" in self.data["kerberos.kdc_options_tree"]:
                raise Exception("Check your assumptions, one of 'em's wrong.")

tmp = {"kerberos.padata":("padata","uint32"), #padata
        "kerberos.padata_tree":({
            "kerberos.PA_DATA_element":("padata_s","subtype",padata), #PA-DATA
                        },"tree"),
        "kerberos.req_body_element":("elements","subtype",req_body), #req-body
        }
class as_req(krb_subtype, keyvals=tmp):
    pass

tmp = {"kerberos.e_data":("e_data","byteseq"), #e-data
                    "kerberos.e_data_tree":({
                        "kerberos.PA_DATA_element":("padata_s","subtype",padata), #PA-DATA
                        },"tree"), #???
                    "kerberos.error_code":("error_code","int32"), #error-code
                    "kerberos.msg_type":("msg_type","int32"), #msg-type
                    "kerberos.susec":("susec","int32"), #susec
                    "kerberos.realm":("realm","str"), #realm
                    "kerberos.stime":("stime","datetime"), #stime
                    "kerberos.sname_element":("elements","subtype",sname), #sname
                    }
class krb_error(krb_subtype, keyvals=tmp):
    pass

tmp = {"kerberos.msg_type":("msg_type","int32"), #msg-type
                   "kerberos.crealm":("crealm","str"), #crealm
                    "kerberos.cname_element":("cname","subtype",cname), #cname
                    "kerberos.ticket_element":("ticket","subtype",ticket), #ticket
                    "kerberos.enc_part_element":("enc_part","subtype",encData), #enc-part
                    }
class tgs_rep(krb_subtype, keyvals=tmp):
    def __str__(self):
        builder = '-'*20 +"tgs_rep"+"-"*20+"\n"
        builder += "PVNO: "+str(self.pvno)+"\n"
        builder += "msg-type: "+str(self.msg_type)+"\n"
        builder += "crealm: "+str(self.crealm)+"\n"
        builder += "cname_element: "+str(self.cname)+"\n"
        builder += "ticket_element: "+str(self.ticket)+"\n"
        builder += "enc_part_element: "+str(self.enc_part)+"\n"
        return builder

tmp = {"kerberos.padata":("padata","uint32"), #padata
                    "kerberos.msg_type":("msg_type","int32"), #msg-type
                    "kerberos.padata_tree":({
                        "kerberos.PA_DATA_element":("padata_s","subtype",padata), #PA-DATA
                        },"tree"),
                    "kerberos.req_body_element":("elements","subtype",req_body),
                    }
class tgs_req(krb_subtype, keyvals=tmp):
    def __str__(self):
        builder = '-'*20 +"tgs_rep"+"-"*20+"\n"
        builder += "PVNO: "+str(self.pvno)+"\n"
        builder += "msg-type: "+str(self.msg_type)+"\n"
        builder += "padata: "+str(self.padata)+"\n"
        builder += "padata_s: "+str(self.padata_s)+"\n"
        if isinstance(self.elements, list):
            for i in self.elements:
                builder += "Element: "+str(i)+"\n"
        else:
            builder += "Element: "+str(self.elements)+"\n"
        return builder


tmp = {"kerberos.as_rep_element":("elements","subtype",as_rep), #as-rep
                    "kerberos.as_req_element":("elements","subtype",as_req), #as-req
                    "kerberos.krb_error_element":("elements","subtype",krb_error), #???
                    "kerberos.req_body_element":("elements","subtype",req_body), #req-body
                    "kerberos.tgs_rep_element":("elements","subtype",tgs_rep), #tgs-rep
                    "kerberos.tgs_req_element":("elements","subtype",tgs_req), #tgs-req
                    'Record Mark':({
                        "kerberos.rm.length":("reclen","uint32"), #Record Length
                        "kerberos.rm.reserved":("res","bool"), #Reserved
                        }, "tree"), #???
                    }
class krbpacket(DataFrame, keyvals=tmp):
    typ = "kerberos"
    def __init__(self, data, packet):
        self.elements = ['']
        self.marks = []
        super().__init__(data, packet)
    def __str__(self):
        builder = '-'*45 + "KERBEROS" + "-"*45 + "\n"
        builder += "Record Mark: Length of "+str(self.reclen)+", Reserved? "+str(self.res)+"\n"
        for i in self.elements:
            builder += str(i) + "\n"
        return builder
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    if "Record Mark" in i:
                        self.marks.append(self.data[i])
                    else:
                        raise Exception("Unknown kerberos frame key "+ i)
    def doTree(self, tree, treename):
        raise Exception("Unimplemented")
