import util

class HTTP(util.DataFrame):
    typ = "HTTP"
    def __init__(self, data, frame):
        self.parts = []
        self.doProc1_0 = False
        self.doProc1_1 = False
        super().__init__(data, frame)
    def doMoarInit(self, data=None):
        if data == None:
            data = self.data
        self.content_length_tree = {}
        self.private = {}
        self.headers = {}
        if isinstance(data, list):
            for i in data:
                self.parts.append(HTTP(i, self.framenum))
        else:
            for i in data.keys():
                if i[0:5] == 'http.': #http.X
                    match i[5:]:
                        case 'accept': #Accept
                            self.headers['Accept'] = self.data[i]
                            if '*/*' != self.data[i]: print(f'Accept: {self.data[i]}')
                        case 'accept_encoding': #Accept Encoding
                            self.headers['Accept-Encoding'] = self.data[i]
                            print(f'Accept-Encoding: {self.data[i]}')
                        case 'accept_language': #Accept-Language
                            self.headers['Accept-Language'] = self.data[i]
                            print(f'Accept-Language: {self.data[i]}')
                        case 'authorization': #Authorization
                            self.headers['Authorization'] = self.data[i]
                            print(f'Authorization: {self.data[i]}')
                        case 'authorization_tree': #???
                            self.doTree(self.data[i], 'authorization_tree')
                        case 'cache_control': #Cache-Control
                            self.headers['Cache-Control'] = self.data[i]
                            print(f"Cache-Control: {self.data[i]}")
                        case 'connection': #Connection
                            self.headers['Connection'] = self.data[i]
                            print(f"Connection: {self.data[i]}")
                        case 'content_encoding': #Content-Encoding
                            self.headers['Content-Encoding'] = self.data[i]
                            print(f"Content-Encoding: {self.data[i]}")
                            if 'SLDC' in self.data[i]: print("\tFor more information see http://rfc.nop.hu/ecma/ECMA-321.PDF")
                        case 'content_length_header': #Content-Length
                            self.headers['Content-Length'] = self.data[i]
                        case 'content_length_header_tree':
                            tmp = self.data[i]
                            for j in tmp.keys():
                                match j:
                                    case 'http.content_length': #Content-Length
                                        self.content_length_tree['content_length'] = tmp[j]
                                        print(f"\tContent-Length {tmp[j]}")
                                    case _:
                                        print(f"Unknown http-content-length-tree key {j}")
                        case 'content_type': #Content-Type
                            self.headers['Content-Type'] = self.data[i]
                        case 'date': #Date
                            self.headers['Date'] = self.data[i]
                        case 'file_data': #File Data
                            self.private['filedata'] = self.data[i]
                            self.body = self.data[i]
                            print('\tThere is file data present.')
                        case 'host': #Host
                            self.headers['Host'] = self.data[i]
                        case 'last_modified': #Last-Modified
                            self.headers['Last-Modified'] = self.data[i]
                        case 'location': #Location
                            self.headers['Location'] = self.data[i]
                        case 'next_request_in': #Next request in frame X
                            self.private['next_req'] = int(self.data[i])
                        case 'next_response_in': #Next response in frame X
                            self.private['next_resp'] = int(self.data[i])
                        case 'prev_request_in': #Previous request in frame X
                            self.private['prev_req'] = int(self.data[i])
                        case 'prev_response_in': #Previous response in frame X
                            self.private['prev_resp'] = int(self.data[i])
                        case 'request': #Request
                            if int(self.data[i]) == 1:
                                self.type = 'Request'
                            print(f'\tRequest: {self.data[i]}')
                        case 'request.full_uri': #Full request URI
                            self.private['full_req_uri'] = self.data[i]
                            print(f'\tFull Request URI: {self.data[i]}')
                        case 'request.line': #Request line
                            if isinstance(self.data[i], list):
                                self.private['req_line'] = self.data[i][0]
                                for j in range(1, len(self.data[i])):
                                    self.private['req_line'] += "\t"+self.data[i][j]
                            else:
                                self.private['req_line'] = self.data[i]
                            print(f'\tRequest line: \n\t{self.private["req_line"].encode().decode()}')
                        case 'request_in': #Request in frame X
                            self.private['req_in'] = int(self.data[i])
                        case 'request_number': #Request number X
                            self.private['reqnum'] = int(self.data[i])
                        case 'response': #Response
                            if int(self.data[i]) == 1:
                                self.type = 'Response'
                            print(f'\tResponse: {self.data[i]}')
                        case 'response.line': #Response line
                            if isinstance(self.data[i], list):
                                self.private['resp_line'] = self.data[i][0]
                                for j in range(1, len(self.data[i])):
                                    self.private['resp_line'] += "\t"+self.data[i][j]
                            else:
                                self.private['resp_line'] = self.data[i]
                            print(f'\tResponse line: \n\t{self.private["resp_line"].encode().decode()}')
                        case 'response_for.uri': #Request URI
                            self.private['requri'] = self.data[i]
                            print(f'\tResponse for request URI: {self.data[i]}')
                        case 'response_in': #Response in frame X
                            self.private['resp_in'] = int(self.data[i])
                        case 'response_number': #Response number X
                            self.private['respnum'] = int(self.data[i])
                        case 'server': #Server
                            self.headers['Server'] = self.data[i]
                        case 'time': #Time since request (Time offset)
                            self.private['time_since'] = self.data[i]
                        case 'transfer_encoding': #Transfer-Encoding (Character string)
                            self.headers['Transfer-Encoding'] = self.data[i]
                        case 'user_agent': #User-Agent
                            self.headers['User-Agent'] = self.data[i]
                        case 'www_authenticate': #WWW-Authenticate
                            self.headers['WWW-Authenticate'] = self.data[i]
                        case 'www_authenticate_tree': #???
                            self.doTree(self.data[i], 'www_authenticate_tree')
                        case _:
                            print(f"Unknown http private key {i} with value {self.data[i]}")
                else:
                    if "HTTP/1.0" in i:
                        self.doProc1_0 = True
                        self.lineone = i
                    elif "HTTP/1.1" in i:
                        self.doProc1_1 = True
                        self.lineone = i
                    elif i == r'\r\n':
                        pass
                    elif "body" in i:
                        self.doTree(self.data[i], i, "body")
                    else:
                        print(f"Unknown http public key {i.encode()} with value {self.data[i]}")
    def __str__(self):
        if self.parts != []:
            ret = " "*40+"Frame number: "+str(self.framenum)+" "*40+"\n"
            for i in self.parts:
                ret += str(i)
            return ret
        ret = " "*40+self.typ+" "*40+"\n"
        if self.doProc1_0: ret += self.doProc10()
        if self.doProc1_1: ret += self.doProc11()
        return ret
    def doTree(self, tree, treename, treetype=None):
        if treetype == "body":
            for i in tree:
                match i:
                    case '_ws.expert':
                        pass
                    case 'data':
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown http body tree key", i)
        elif treename == "www_authenticate_tree" or treename == "authorization_tree":
            for i in tree:
                match i:
                    case 'gss-api':
                        if 'gss_api' not in self.__dict__:
                            self.gss_api = util.gss_api(tree[i])
                    case _:
                        print(f"Unknown HTTP key {i} in tree {treename}")
        elif treename == "data":
            for i in tree:
                match i:
                    case 'data.data':
                        self.body = util.unpackByteSequence(tree[i])
                    case 'data.len':
                        self.bodylen = int(tree[i])
                    case _:
                        print("Unknown http data tree key", i)
        else:
            print("Unknown HTTP treename",treename)
    def doProc10(self): #https://datatracker.ietf.org/doc/html/rfc1945
        builder = '-'*40+"HTTP/1.0" + "-"*40
        builder += self.lineone.replace(r'\r\n','') + "\n"
        builder += "\t"*6+"General Header\n"
        if "Date" in self.headers:
            builder += f"Date: {self.headers['Date']}\n"
        if self.type == 'Response':
            builder += "\t"*6+"Response Header\n"
            if "Location" in self.headers:
                builder += "Location:"+self.headers['Location']+"\n"
            if "Server" in self.headers:
                builder += "Server:"+self.headers['Server']+"\n"
            if "WWW-Authenticate" in self.headers and not isinstance(self.headers['WWW-Authenticate'], list):
                builder += "WWW-Authenticate:"+self.headers['WWW-Authenticate']+"\n"
            elif "WWW-Authenticate" in self.headers:
                for i in self.headers["WWW-Authenticate"]:
                    builder += "WWW-Authenticate:"+i+"\n"
        builder+="\t"*6+"Entity Header\n"
        if "Content-Encoding" in self.headers:
            builder+='Content-Encoding:'+self.headers['Content-Encoding']+"\n"
        if "Content-Length" in self.headers:
            builder+="Content-Length:"+self.headers['Content-Length']+"\n"
        if self.content_length_tree != {}:
            builder += str(self.content_length_tree)
        if "Content-Type" in self.headers:
            builder += "Content-Type:"+self.headers['Content-Type']+"\n"
        if 'Last-Modified' in self.headers:
            builder+="Last-Modified:"+self.headers['Content-Type']+"\n"
        builder += "\n"
        if "body" in self.__dict__:
            builder += self.body
        return builder

    def doProc11(self): # https://datatracker.ietf.org/doc/html/rfc9112
        builder = '-'*40+"HTTP/1.1"+'-'*40+"\n"
        builder+=self.lineone.replace(r'\r\n','')+"\n"
        if "Host" in self.headers:
            builder+="Host:"+self.headers['Host']+"\n"
        builder += "\n"
        if "Accept" in self.headers: #https://www.iana.org/assignments/http-fields/http-fields.xhtml
            builder+="Accept:"+self.headers['Accept']+"\n"
        if "Accept-Encoding" in self.headers:
            builder+="Accept-Encoding:"+self.headers['Accept-Encoding']+"\n"
        if 'Accept-Language' in self.headers:
            builder+="Accept-Language:"+self.headers['Accept-Language']+"\n"
        if 'Authorization' in self.headers:
            builder+='Authorization:'+self.headers['Authorization']+"\n"
        if 'Cache-Control' in self.headers:
            builder+='Cache-Control:'+self.headers['Cache-Control']+"\n"
        if 'Connection' in self.headers:
            builder+='Connection:'+self.headers['Connection']+"\n"
        if 'Content-Encoding' in self.headers:
            builder+='Content-Encoding:'+self.headers['Content-Encoding']+"\n"
        if "Content-Length" in self.headers:
            builder+="Content-Length:"+self.headers['Content-Length']+"\n"
        if self.content_length_tree != {}:
            builder+=str(self.content_length_tree)+"\n"
        if "Content-Type" in self.headers:
            builder+="Content-Type:"+self.headers['Content-Type']+"\n"
        if 'Date' in self.headers:
            builder+='Date:'+self.headers['Date']+"\n"
        if 'Last-Modified' in self.headers:
            builder+='Last-Modified:'+self.headers['Last-Modified']+"\n"
        if 'Location' in self.headers:
            builder+='Location:'+self.headers['Location']+"\n"
        if 'Server' in self.headers:
            builder+='Server:'+self.headers['Server']+"\n"
        if 'User-Agent' in self.headers:
            builder+='User-Agent:'+self.headers['User-Agent']+"\n"
        if "WWW-Authenticate" in self.headers and not isinstance(self.headers['WWW-Authenticate'], list):
                builder += "WWW-Authenticate:"+self.headers['WWW-Authenticate']+"\n"
        elif "WWW-Authenticate" in self.headers:
            for i in self.headers["WWW-Authenticate"]:
                builder += "WWW-Authenticate:"+i+"\n"
        builder+='\n'
        if 'body' in self.__dict__:
            builder += str(self.body)
        return builder


class SSDP(HTTP): #Simple Service Discovery Protocol
    def __init__(self, data, frame):
        super().__init__(data, frame)
        self.type = "SSDP"
    def doMoarInit(self):
        super().doMoarInit({x: self.data[x] for x in self.data if "ssdp" not in x})
        for i in {x: self.data[x] for x in self.data if "ssdp" in x}:
            match i:
                case _:
                    print("Unknown SSDP Key",i)

class ICMP(util.DataFrame): #Internet Control Message Protocol (https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
    typ = 'ICMP'
    trees = util.DataFrame.__dict__['trees']
    ints = util.DataFrame.__dict__['ints'].copy()
    ints.update({"icmp.checksum": "check", #Checksum (uint16)
                 "icmp.checksum.status":"checkstat", #Checksum Status (uint8)
                 "icmp.code": "code", #Code (uint8)
                 "icmp.ident":"ident", #Identifier (BE) (uint16)
                 "icmp.ident_le":"ident_le", #Identifier (LE) (uint16)
                 "icmp.seq": "seq", #Sequence Number (BE) (uint16)
                 "icmp.seq_le":"seq_le", #Sequence Number (LE) (uint16)
                 "icmp.type":"type" #Type (uint8)
                    })
    byteseqs = util.DataFrame.__dict__['byteseqs'].copy()
    byteseqs.update({})
    def __init__(self, data, frame):
        self.options = {}
        super().__init__(data, frame)
    def doMoarInit(self, data=None):
        if data==None and self.typ=='ICMP':
            data = self.data
        for i in data:
            if i in self.ints or i in self.byteseqs or i in self.trees:
                continue
            if i[0:5] == 'icmp.':
                match i[5:]:
                    case 'data_time': #Timestamp from icmp data (Date and time)
                        self.datatime = data[i]
                    case 'data_time_relative': #Timestamp from icmp data (relative) (Time offset)
                        self.datatimerel = data[i]
                    case 'resp_in': #Response frame in frame X (Frame number)
                        self.respinref = int(data[i])
                    case 'resp_to': #Request frame in frame X (Frame number)
                        self.resptoref = int(data[i])
                    case 'resptime': #Response time (Floating point (double-precision))
                        self.resptime = float(data[i])
                    case _:
                        print("Unknown", self.typ, "key", i)
            else:
                match i:
                    case 'data':
                        self.data = util.Data(data[i])
                    case _:
                        print("Unknown", self.typ, "key", i, "with data value", data[i])
    def __str__(self):
        builder = '-'*40+self.typ+40*'-'+'\n'
        builder += "Type: "+self.getType()+" | Code: "+self.getCode()+" | Checksum: "+str(self.check)+" (Status: "+str(self.checkstat)+")\n"
        return builder

    def getType(self):
        tmp = {0:"Echo Reply",
               3: "Destination Unreachable",
               4: "Source Quench",
               5: "Redirect Message",
               8: "Echo Request",
               9: "Router Advertisement",
               10: "Router Solicitation",
               11: "Time Exceeded",
               12: "Parameter Problem: Bad IP header",
               13: "Timestamp",
               14: "Timestamp Reply",
               15: "Information Request",
               16: "Information Reply",
               17: "Address Mask Request",
               18: "Address Mask Reply",
               30: "Traceroute",
               42: "Extended Echo Request",
               43: "Extended Echo Reply"}
        return tmp[self.type]

    codes = {0: {0: "Expectedd Value"},

            8: {0: "Expected Value"}
            }
    def getCode(self):
        return self.codes[self.type][self.code]

class ICMPV6(ICMP): #Internet Control Message Protocol v6
    typ = "ICMPv6"
    trees = ICMP.__dict__['trees'] + ["icmpv6.mldr.mar", #Multicast Address Record (Label)
                                      "icmpv6.opt" #???
                                      ]
    ints = ICMP.__dict__['ints'].copy()
    ints.update({"icmpv6.checksum": "check", #Checksum (uint16)
                 "icmpv6.checksum.status":"checkstat", #Checksum Status (uint8)
                 "icmpv6.code":"code", #Code (uint8)
                 "icmpv6.mldr.nb_mcast_records":"mldr_number", #Number of Multicast Address Records (uint16)
                 "icmpv6.type":"type" #Type (uint8)
                 })
    byteseqs = ICMP.__dict__['byteseqs'].copy()
    byteseqs.update({"icmpv6.reserved":"reserved" #Reserved (Byte sequence)
                     })
    def __init__(self, data, frame):
        self.mars = []
        super().__init__(data, frame)
    def doMoarInit(self):
        build = {x: self.data[x] for x in self.data if 'icmpv6' not in x}
        for i in {x: self.data[x] for x in self.data if 'icmpv6' in x}:
            if i in self.trees or i in self.ints or i in self.byteseqs:
                continue
            else:
                match i:
                    case _:
                        raise Exception("Unknown ICMPv6 key"+ i)
        super().doMoarInit(build)
    def getType(self):
        tmp = {1: "Error: Destination Unreachable",
               2: "Error: Packet too big",
               3: "Error: Time exceeded",
               4: "Error: Parameter problem",
               100: "Error: Private experimentation",
               101: "Error: Private experimentation",
               127: "Error: Reserved for expansion of ICMPv6 error messages",
               128: "Informational: Echo Request",
               129: "Informational: Echo Reply",
               130: "Informational: Multicast Listener Query (MLD)", #https://en.wikipedia.org/wiki/Multicast_Listener_Discovery
               131: "Informational: Multicast Listener Report (MLD)",
               132: "Informational: Multicast Listener Done (MLD)",
               133: "Informational: Router Solicitation (NDP)", #https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
               134: "Informational: Router Advertisement (NDP)",
               135: "Informational: Neighbor Solicitation (NDP)",
               136: "Informational: Neighbor Advertisement (NDP)",
               137: "Informational: Redirect Message (NDP)",
               138: "Informational: Router Renumbering",
               139: "Informational: ICMP Node Information Query",
               140: "Informational: ICMP Node Information Response",
               141: "Informational: Inverse Neighbor Discovery Solicitation Message",
               142: "Informational: Inverse Neighbor Discovery Advertisement Message",
               143: "Informational: Multicast Listener Discovery (MLDv2) reports"} #There are more that's just all I think are needed for now. See more at https://en.wikipedia.org/wiki/ICMPv6.
        return tmp[self.type]

    def doTree(self, tree, treename):
        if treename == 'icmpv6.mldr.mar':
            self.mars.append({})
            for i in tree:
                match i:
                    case 'icmpv6.mldr.mar.aux_data_len': #Aux Data Len (uint8)
                        self.mars[-1]['aux_data_len'] = int(tree[i])
                    case 'icmpv6.mldr.mar.multicast_address': #Multicast Address (IPv6 address)
                        self.mars[-1]['multicast_address'] = tree[i]
                    case 'icmpv6.mldr.mar.nb_sources': #Number of Sources (uint16)
                        self.mars[-1]['nb_sources'] = int(tree[i])
                    case 'icmpv6.mldr.mar.record_type': #Record Type (uint8)
                        self.mars[-1]['record_type'] = int(tree[i])
                    case _:
                        print("Unknown key in icmpv6.mldr.mar tree", i)
        elif treename == 'icmpv6.opt':
            option_type = tree['icmpv6.opt.type']
            self.options[option_type] = {}
            for i in tree:
                match i:
                    case 'icmpv6.opt.length': #Length (uint8)
                        self.options[option_type]['length'] = int(tree[i])
                    case 'icmpv6.opt.linkaddr': #Link-layer address (Byte sequence)
                        self.options[option_type]['linkaddr'] = util.unpackByteSequence(tree[i])
                    case 'icmpv6.opt.src_linkaddr': #Source Link-layer address (Byte sequence)
                        self.options[option_type]['src_linkaddr'] = util.unpackByteSequence(tree[i])
                    case 'icmpv6.opt.type': #Type (uint8)
                        self.options[option_type]['type'] = int(tree[i])
                    case _:
                        print("Unknown key in icmpv6.opt tree", i)
        else:
            print("Unknown ICMPv6 tree", treename)
    codes = {1: {0: "no route to destination",
                 1: "communication with destination administratively prohibited"},
            133: {0: "Expected Code"},
             143: {0: "Expected Code"}
            }#There are more. again. see https://en.wikipedia.org/wiki/ICMPv6
    def getCode(self):
        return self.codes[self.type][self.code]
class IGMP(util.DataFrame): #Internet Group Management Protocol
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"igmp.checksum":("check","uint16"),   #Checksum (uint16)
                    "igmp.type":("igmp_type","uint8"), #Type (uint8)
                    "igmp.reserved":("reserved","byteseq"), #Reserved
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        self.recs = {}
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            if i[0:5] == 'igmp.':
                match i[5:]:
                    case 'checksum.status': #Checksum Status (uint8)
                        self.checkstat = int(self.data[i])
                    case 'num_grp_recs': #Num Group Records (uint16)
                        self.numgrprecs = int(self.data[i])
                    case 'version': #IGMP Version
                        self.ver = int(self.data[i])
                    case _:
                        print("Unknown IGMP key",i)
            else:
                if "Group Record" in i:
                    self.doTree(self.data[i], i, "Group Record")
                else:
                    match i:
                        case _:
                            print("Unknown IGMP key", i,"with value",self.data[i])
    
    def doTree(self, tree, treename, treetype=None):
        if treetype == "Group Record":
            self.recs[treename] = {}
            for i in tree:
                match i:
                    case 'igmp.aux_data_len': #Aux Data Len
                        self.recs[treename]['aux_data_len'] = int(tree[i])
                    case 'igmp.maddr': #Multicast Address
                        self.recs[treename]['maddr'] = tree[i]
                    case 'igmp.num_src': #Num Src
                        self.recs[treename]['num_src'] = int(tree[i])
                    case 'igmp.record_type': #Record Type
                        self.recs[treename]['record_type'] = int(tree[i])
                    case _:
                        print("Unknown IGMP key in Group Record tree", i)

    def __str__(self): # https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
        builder = '-'*40+'IGMP'+40*'-'+'\n'
        builder += "Type: "+self.getType() + " | Checksum: "+str(self.check)+" (Status: "+str(self.checkstat)+")\n"
        builder += str(self.recs)+"\n"
        builder += "Group Records:\n"
        if self.numgrprecs > 0:
            for i in self.recs:
                builder += "\t"+i+"\n"
        return builder

    def getType(self):
        types = {0x11: "Membership Query",
                 0x12: "IGMPv1 Membership Report",
                 0x16: "IGMPv2 Membership Report",
                 0x17: "Leave Group",
                 0x22: "IGMPv3 Membership Report"}
        return types[self.igmp_type]

