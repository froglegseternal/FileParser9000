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
                print(f"Unknown wireshark expert key {key} with value {value}")
    def doProcessMalformed(self, key, value):
        match key[14:] : #_ws.malformed.X
            case _:
                print(f"Unknown wireshark malformed packet key {key} with value {value}")
    def doCheck(self):
        pass

class DataFrame(PacketDiss):
    trees = ['_ws.expert','Timestamps']
    hexints = {}
    ints = hexints
    byteseqs = {}
    framerefs = {}
    ipv6_addrs = {}
    strs = {}
    keyvals = {}
    def __init__(self, data, frame):
        super().__init__(data)
        self.framenum = int(frame)
        self.keyvals = self.keyvals.copy()
        for i in self.keyvals:
            if i in data:
                if "uint" in self.keyvals[i][1]:
                    self.assignValue(self.keyvals[i][0], self.getInt(data[i],i,self.keyvals),self.keyvals, i)
                elif "tree" == self.keyvals[i][1]:
                    self.doTreeBetter(data[i], self.keyvals[i][0], i)
                elif "byteseq" == self.keyvals[i][1]:
                    self.__dict__[self.keyvals[i][0]] = unpackByteSequence(data[i])
                elif "str" == self.keyvals[i][1]:
                    self.assignValue(self.keyvals[i][0], self.getStr(data[i],i),self.keyvals,i)
                elif "bool" == self.keyvals[i][1]:
                    self.__dict__[self.keyvals[i][0]] = bool(int(data[i]))
                else:
                    raise Exception("Unimplemented keyval type "+self.keyvals[i][1])
        for i in self.ints:
            self.keyvals.update({i: (self.ints[i],"int")})
            if i in data:
                self.assignValue(self.ints[i], self.getInt(data[i],i),self.ints, i)
        for i in self.trees:
            self.keyvals.update({i: (i,"tree")})
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
            elif "tree" == keytree[i][1]:
                self.doTreeBetter(tree[i], keytree[i][0], i)
            elif "byteseq" == keytree[i][1]:
                self.__dict__[keytree[i][0]] = unpackByteSequence(tree[i])
            elif "str" == keytree[i][1]:
                self.assignValue(keytree[i][0], self.getStr(tree[i],i),keytree,i)
            elif "bool" == keytree[i][1]:
                self.__dict__[keytree[i][0]] = bool(int(tree[i]))
            elif "Specialtree" == keytree[i][1]:
                self.doTree(tree, treename)
            else:
                raise Exception("Unimplemented")

    def getInt(self, integer, parent=None, keytree=None):
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
        if result is not None:
            self.__dict__[parent] = result
        else:
            pass

class DNSRecord(DataFrame):
    keyvals = DataFrame.keyvals.copy()
    keyvals.update({"dns.ptr.domain_name":("ptr_dom_name","str"), #Domain Name (Character strig)
                   })
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
                case 'dns.count.labels': #Label Count (uint16)
                    self.labelcount = int(tree[i])
                case 'dns.cname': #CNAME (Character string)
                    self.cname = tree[i]
                case 'dns.mx.mail_exchange': #Mail Exchange (Character string)
                    self.mxme = tree[i]
                case 'dns.mx.preference': #Preference (uint16)
                    self.mxpref = int(tree[i])
                case 'dns.srv.name': #Name (Character string)
                    self.srvname = tree[i]
                case 'dns.srv.port': #Port (uint16)
                    self.srvport = int(tree[i])
                case 'dns.srv.priority': #Priority (uint16)
                    self.srvprior = int(tree[i])
                case 'dns.srv.proto': #Protocol (Character string)
                    self.srvproto = tree[i]
                case 'dns.srv.service': #Service (Character string)
                    self.srvservice = tree[i]
                case 'dns.srv.target': #Target (Character string)
                    self.srvtarget = tree[i]
                case 'dns.srv.weight': #Weight (uint16)
                    self.srvweight = int(tree[i])
                case 'nbns.class': #Class (uint16)
                    self.clas = self.getInt(tree[i])
                case 'nbns.name': #Name (Character string)
                    self.name = tree[i]
                case 'nbns.type': #Ttype (uint16)
                    self.type = self.getInt(tree[i])
                case _:
                    print("Unknown DNSRecord key", i)

class DNSQuery(DNSRecord):
    def doTree(self, tree, treename):
       super().doTree({x: tree[x] for x in tree if "dns.qry." not in x})
       for i in {x: tree[x] for x in tree if "dns.qry." in x}:
           match i[8:]:
               case 'class': #Class (uint16)
                   self.clas = int(tree[i],16)
               case 'name': #Name (Character string)
                   self.name = tree[i]
               case 'name.len': #Name Length (uint16)
                   self.name_len = int(tree[i])
               case 'qu': #"QU" question (Boolean)
                   self.qu = bool(int(tree[i]))
               case 'type': #Type (uint16)
                    self.typ = int(tree[i])
               case _:
                   print("Unknown DNSQuery key", i)

class DNSAnswer(DNSRecord):
    keyvals = DNSRecord.keyvals.copy()
    keyvals.update({"dns.resp.cache_flush":("cache_flush","bool"), #Cache flush
                    })
    def doTree(self, tree, treename=None):
        super().doTree({x: tree[x] for x in tree if "dns.resp." not in x})
        for i in {x: tree[x] for x in tree if "dns.resp." in x}:
            if i in self.keyvals:
                continue
            match i[9:]:
                case 'class': #Class (uint16)
                    self.clas = int(tree[i],16)
                case 'edns0_version': #EDNS0 version (uint8)
                    self.ednsver = int(tree[i])
                case 'ext_rcode': #Higher bits in extended RCODE (uint8)
                    self.extrcode = int(tree[i],16)
                case 'len': #Data Length (uint16)
                    self.resp_len = int(tree[i])
                case 'name': #Name (Character string)
                    self.name = tree[i]
                case 'ttl': #Time to live (uint32)
                    self.ttl = int(tree[i])
                case 'type': #Type (uint16)
                    self.typ = int(tree[i])
                case 'z': #Z (uint16)
                    self.z = int(tree[i],16)
                case 'z_tree': #???
                    self.doTree(tree[i],i)
                case 'z.do': #DO bit (Boolean)
                    self.zdo = bool(int(tree[i]))
                case 'z.reserved': #Reserved (uint16)
                    self.zreser = int(tree[i],16)
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
                    print("Unknown DNSAddRecord key", i)

class DNSAuth(DNSAnswer):
    def doTree(self, tree, treename):
        super().doTree({x: tree[x] for x in tree if "dns.soa." not in x})
        for i in {x: tree[x] for x in tree if "dns.soa." in x}:
            match i[8:]:
                case 'expire_limit': #Expire limit (uint32)
                    self.explimit = int(tree[i])
                case 'minimum_ttl': #Minimum TTL (uint32)
                    self.minttl = int(tree[i])
                case 'mname': #Primary name server (Character string)
                    self.mname = tree[i]
                case 'refresh_interval': #Refresh Interval (uint32)
                    self.refint = int(tree[i])
                case 'retry_interval': #Retry interval (uint32)
                    self.retint = int(tree[i])
                case 'rname': #Responsible Authority's Mailbox (Character string)
                    self.rname = tree[i]
                case 'serial_number': #Serial Number (uint32)
                    self.serial = int(tree[i])
                case _:
                    print("Unknown DNSAuth key", i)

   
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



class MIME(DataFrame):
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

class ap_req(dict):
    def __init__(self):
        pass

class ap_rep(dict):
    def __init__(self):
        pass
