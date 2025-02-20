import util

class DHCP(util.DataFrame): #https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
    ints = util.DataFrame.__dict__['ints'].copy()
    ints.update({"dhcp.flags":"flags_bootp", #Bootp flags
                    "dhcp.hw.type":"hwtype", #Hardware type
                    "dhcp.id":"id" #Transaction ID
                    })
    trees = util.DataFrame.__dict__['trees'] + ["dhcp.flags_tree","dhcp.option.type_tree"]
    def __init__(self, data, frame):
        self.flags = {}
        self.hw = {}
        self.ip = {}
        self.opt = {'type_tree':[]}
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            if 'dhcp.flags' == i[0:10]:
                match i:
                    case _:
                        print(f"Unknown dhcp flag key {i}")
            elif 'dhcp.hw.' == i[0:8]:
                match i[8:]:
                    case 'addr_padding':
                        self.hw['addr_padding'] = util.unpackByteSequence(self.data[i]) #Client hardware address padding
                    case 'len':
                        self.hw['len'] = int(self.data[i]) #Hardware address length
                    case 'mac_addr':
                        self.hw['mac_addr'] = self.data[i] #Client MAC Address
                    case _:
                        print(f"Unknown dhcp hardware key {i}")
            elif 'dhcp.ip.' == i[0:8]:
                match i[8:]:
                    case 'client':
                        self.ip['client'] = self.data[i] #Client IP Address
                    case 'relay':
                        self.ip['relay'] = self.data[i] #Relay agent IP Address
                    case 'server':
                        self.ip['server'] = self.data[i] #Next server IP Adress
                    case 'your':
                        self.ip['your'] = self.data[i] #Your (client) IP Address
                    case _:
                        print(f"Unknown IP DHCP key {i}")
            elif 'dhcp.option.' == i[0:12]:
                match i[12:]:
                    case 'padding':
                        self.opt['padding'] = util.unpackByteSequence(self.data[i]) #Padding
                    case 'type':
                        if isinstance(self.data[i], list):
                            self.opt['type'] = self.data[i]
                        else:
                            self.opt['type'] = int(self.data[i]) #"Option"???? unknown
                            if self.opt['type'] != 0:
                                print(self.opt['type'])
                    case _:
                        print(f"Unknown Option DHCP key {i}")
            elif 'dhcp.' == i[0:5]:
                match i[5:]:
                    case 'cookie': #Magic cookie
                        self.cookie = self.data[i]
                    case 'file': #Boot file name
                        self.file = self.data[i]
                        if self.file:
                            print("Boot file name:",self.file)
                    case 'hops': #Hops
                        self.hops = int(self.data[i])
                    case 'secs': #Seconds elapsed
                        self.secs = int(self.data[i])
                    case 'server': #Server host name
                        self.server = self.data[i]
                        if self.server: print("Server:",self.server)
                    case 'type': #Message type
                        self.type = int(self.data[i])
                    case _:
                        print("Unknown generic/other DHCP key",i)
            else:
                match i:
                    case _:
                        print(f"Unknown generic/other DHCP key {i}")
        if isinstance(self.opt['type'], list):
            self.doOptProcessing()

    def doOptProcessing(self):
        self.final_options = []
        for i in range(len(self.opt['type'])):
            self.final_options.append((self.getInt(self.opt['type'][i]),self.opt['type_tree'][i]))

    op_type_dict  = {0: "Pad (0)",
                     1: "Subnet mask (1)",
                     2: "Time offset (2)",
                     3: "Router (3)",
                     4: "Time server (4)",
                     5: "Name server (5)",
                     6: "Domain name server (6)",
                     7: "Log server (7)",
                     8: "Cookie server (8)",
                     9: "LPR Server (9)",
                     10: "Impress server (10)",
                     11: "Resource location server (11)",
                     12: "Host name (12)",
                     13: "Boot file size (13)",
                     14: "Merit dump file (14)",
                     15: "Domain name (15)",
                     16: "Swap server (16)",
                     17: "Root path (17)",
                     18: "Extensions path (18)",
                     50: "Requested IP address (50)",
                     51: "IP address lease time (51)",
                     52: "Option overload (52)",
                     53: "DHCP Message Type (53)",
                     54: "Server identifier (54)",
                     55: "Parameter Request list (55)",
                     56: "Message (56)",
                     57: "Maximum DHCP message size (57)",
                     58: "Renewal (T1) time value (58)",
                     59: "Rebinding (T2) time value (59)",
                     60: "Vendor class identifier (60)",
                     61: "Client identifier (61)",
                     66: "TFTP server name (66)",
                     67: "Bootfile name (67)"}
    def __str__(self):
        builder = "-"*40+"DHCP"+"-"*40+"\n"
        if 'framenum' in self.__dict__:
            builder += f'Frame Number {self.framenum}\n'
        builder += "DHCP Message type: "+self.getMsgType()+"\n"
        builder += "Hardware type: "+self.getHWType()+" | Hardware Address Length: "+str(self.hw['len'])+" | Hops: "+str(self.hops)+"\n"
        builder += "Transaction ID: "+hex(self.id)+"\n"
        builder += "Seconds elapsed: "+str(self.secs)+" | Flags: "+str(self.flags)+"\n"
        builder += "Bootp flag: "+str(self.flags_bootp)+"\n"
        builder += "Client IP Address: "+self.ip['client']+'\n'
        builder += "Your IP Address: "+self.ip['your']+'\n'
        builder += 'Server IP Address: '+self.ip['server']+'\n'
        builder += 'Gateway IP Address: '+self.ip['relay']+'\n'
        builder += 'Client Hardware Address: ' + self.hw['mac_addr']+'\n'
        builder += "Magic Cookie: "+self.cookie+"\n"
        builder += "DHCP Options: \n"
        if 'final_options' in self.__dict__:
            for i in self.final_options:
                builder += "\nOption Type - "+self.op_type_dict[i[0]]+":"+"\n"+"\t"+str(i[1])
        return builder

    def getMsgType(self):
        match self.type:
            case 1:
                return "Boot Request"
            case 2:
                return "Boot Reply"
            case _:
                raise Exception(f"Invalid DHCP Message Type {self.type}")

    def getHWType(self):
        match self.hwtype:
            case 1:
                return "Ethernet"
            case _:
                raise Exception(f"Invalid DHCP Hardware Type {self.hwtype}")

    def doTree(self, tree, treename):
        if treename == 'dhcp.flags_tree':
            for i in tree:
                if i[0:11] == 'dhcp.flags.':
                    match i[11:]:
                        case 'bc': #Broadcast flag
                            self.flags['bc'] = bool(int(tree[i]))
                        case 'reserved': #Reserved flags
                            self.flags['reserved'] = int(tree[i],16)
                        case _:
                            print("Unknown key in",treename,"tree",i)
                else:
                    match i:
                        case _:
                            print("Unknown key in dhcp.flags_tree tree", i)
        elif treename == 'dhcp.option.type_tree':
            for i in tree:
                if isinstance(tree, list):
                    self.opt['type_tree'].append(i) #Very temporary solution
                elif i[0:12] == 'dhcp.option.':
                    match i[12:]:
                        case 'end': #Option End
                            self.opt['end'] = int(tree[i])
                        case _:
                            print("Unknown key in",treename,"tree",i)
                else:
                    match i:
                        case _:
                            print(f"Unknown key in {treename} tree", i)
        else:
            print("Unknown DHCP tree", treename)

class DNS(util.DataFrame): #https://en.wikipedia.org/wiki/Domain_Name_System
    typ = "DNS"
    trees = util.DataFrame.__dict__['trees'] + ['dns.id_tree']
    ints = util.DataFrame.__dict__['hexints'].copy()
    ints.update({'dns.count.add_rr':"add_rr_count", #Additional RRs (uint16)
                 'dns.count.answers':'answers_count', #Answer RRs (uint16)
                 'dns.count.auth_rr':'auth_rr_count',#Authority RRs (uint16)
                 'dns.count.queries':'queries_count',#Questions (uint16)
        "dns.flags": "flags_base", #Flags (uint16)
                    "dns.id": "id" #Transaction ID (uint16)
                    })
    def __init__(self, data, frame):
        self.additional_records = []
        self.answers = []
        self.auth_servers = []
        self.queries = []
        self.private = {'flags':{}}
        super().__init__(data, frame)
    def doMoarInit(self, data=None):
        if data == None:
            data = self.data
        for i in data.keys():
            if i in self.ints or i in self.trees:
                continue
            if 'dns.' == i[0:4]:
                if ".count." == i[3:10]: #dns.count.X
                    match i[10:]:   #dns.count.X
                        case _:
                            print(f"Unknown private (count) DNS key {i}")
                elif '.flags' == i[3:9]: #dns.flagsX
                    match i[9:]:
                        case '_tree':
                            tmp = data[i]
                            for j in tmp.keys():
                                match j[10:]: #dns.flags.X
                                    case 'authenticated': #Answer Authenticated / Authentic Data (boolean)
                                        self.private["flags"]["AD"] = bool(int(tmp[j]))
                                    case 'authoritative': #Authoritative (boolean)
                                        self.private["flags"]["AA"] = bool(int(tmp[j]))
                                    case 'checkdisable': #Non-authenticated data / Checking disabled (boolean)
                                        self.private["flags"]["CD"] = bool(int(tmp[j]))
                                    case 'conflict': #Conflict (boolean)
                                        self.private["flags"]["C"] = bool(int(tmp[j]))
                                    case 'opcode': #Opcode (uint16)
                                        self.private['flags']['OPCODE'] = int(tmp[j])
                                        if int(tmp[j]) == 0:
                                            self.private['flags']['OPCODE'] = 'QUERY'
                                        elif int(tmp[j]) == 1:
                                            self.private['flags']['OPCODE'] = 'IQUERY'
                                        elif int(tmp[j]) == 2:
                                            self.private['flags']['OPCODE'] = 'STATUS'
                                        else:
                                            raise Exception("Invalid DNS Opcode flag")
                                    case 'rcode': #Reply code (uint16)
                                        self.private['flags']['RCODE'] = self.getRcode(int(tmp[j]))
                                    case 'recavail': #Recursion available (boolean)
                                        self.private["flags"]['RA'] = bool(int(tmp[j]))
                                    case 'recdesired': #Recursion desired (boolean)
                                        self.private['flags']['RD'] = bool(int(tmp[j]))
                                    case 'response': #Response (boolean)
                                        self.private["flags"]["QR"] = not bool(int(tmp[j]))
                                        if not self.private['flags']['QR']:
                                            self.type = 'Response'
                                        else:
                                            self.type = 'Query'
                                    case 'tentative': #Tentative (boolean)
                                        self.private["flags"]["T"] = bool(int(tmp[j]))
                                    case 'truncated': #Truncated (boolean)
                                        self.private["flags"]["TC"] = bool(int(tmp[j]))
                                    case 'z': #reserved bit (boolean)
                                        self.private["flags"]["Z"] = bool(int(tmp[j]))
                                        if self.private['flags']['Z']:
                                            raise Exception(f"DNS Error: Non-zero value in the zero flag bit. {self.private['flags']['Z']}")
                                    case _:
                                        print(f"Unknown private (flags) DNS key in tree {j}")
                        case _:
                            print(f"Unknown private (flags) DNS key {i}")
                else:
                    match i[4:]: #dns.X
                        case 'response_in': #Response in X (Frame Number)
                            self.private['resp_in'] = int(data[i])
                        case 'response_to': #Request in X (Frame Number)
                            self.private["req_in"] = int(data[i])
                        case 'retransmission': #Retransmission (Boolean)
                            self.private['retrans'] = bool(int(data[i]))
                        case 'retransmit_request': #DNS query retransmission (Label)
                            self.private['retrans_req'] = data[i]
                            print(data[i])
                        case 'retransmit_request_in': #Retransmitted request. Original request in X (Frame Number)
                            self.private['orig_req'] = int(data[i])
                        case 'retransmit_response_in': #Retransmitted response. Original response in X (Frame Number)
                            self.private['orig_resp'] = int(data[i])
                        case 'time': #Time (Time offset)
                            self.private['time'] = data[i]
                        case 'unsolicited': #Unsolicited (Boolean)
                            self.private['unsol'] = bool(int(data[i]))
                        case _:
                            print(f"Unknown private DNS key {i}")
            else:
                match i:
                    case 'Additional records':
                        self.addrecords = data[i]
                        for j in self.addrecords.keys():
                            tmp = util.DNSAddRecord(j, self.addrecords[j])
                            self.additional_records.append(tmp)
                    case 'Answers':
                        self.answerin = data[i]
                        for j in self.answerin.keys():
                            tmp = util.DNSAnswer(j, self.answerin[j])
                            self.answers.append(tmp)
                    case 'Authoritative nameservers':
                        self.asi = data[i] #auth servers in
                        for j in self.asi.keys():
                            tmp = util.DNSAuth(j, self.asi[j])
                    case 'Queries':
                        self.queriesin = data[i]
                        for j in self.queriesin.keys():
                            tmp = util.DNSQuery(j, self.queriesin[j])
                            self.queries.append(tmp)
                    case _:
                        print(f"Unknown DNS key {i}")
    def __str__(self):
        builder = "-"*70 + self.typ + "-" * 70 + "\n"
        builder += "-"*35+"Header"+"-"*35+"\n"
        if "id" in self.__dict__:
            builder += f"Transaction ID: {self.id}\t"
        builder += "| Q/R: " + self.type
        builder += " | Opcode: "+self.private['flags']['OPCODE']
        if self.typ == "LLMNR": builder += " | C: "
        if self.typ == "LLMNR" and self.private['flags']['C']: builder += "Y"
        elif self.typ == "LLMNR": builder += "N"
        builder += " | AA?: " #Authoritative for this domain?
        if self.type == 'Response' and self.private['flags']['AA']: builder+= "Y  "
        elif self.type == 'Response': builder += "N  "
        else: builder += "N/A"
        builder += " | TC?: " #Trucated?
        if self.private['flags']['TC']: builder += "Y"
        else: builder += "N"
        if self.typ == "LLMNR": builder += " | T: "
        if self.typ == "LLMNR" and self.private['flags']['T']: builder += "Y"
        elif self.typ == "LLMNR": builder += "N"
        builder += " | RD?: " #Recursion Desired?
        if self.typ != "LLMNR" and self.private['flags']['RD']: builder += "  Y"
        elif self.typ != "LLMNR": builder += "  N"
        else: builder += "N/A"
        builder += " | RA?: " #Recursion Available?
        if self.typ == 'Response' and self.private['flags']['RA']: builder += "Y  "
        elif self.typ == 'Response': builder += "N  "
        else: builder += 'N/A'
        builder += " | AD?: " #Authentic Data?
        if self.typ == 'Response' and self.private['flags']['authen']: builder += "Y  "
        elif self.typ == 'Response': builder += "N  "
        else: builder += "N/A"
        builder += " | CD?: " #Checking Disabled?
        if self.typ == 'Query' and self.private['flags']['checkdis']: builder += "Y  "
        elif self.typ == 'Query': builder += 'N  '
        else: builder += 'N/A'
        if self.typ == 'Response': builder += " | RCODE: " + self.private['flags']['rcode'] + "\n"
        else: builder += " | RCODE: N/A\n"
        builder += "Number of Questions: " + str(self.queries_count) + " | Number of Answers: " + str(self.answers_count)
        builder += " | Number of Authority Resource Records: " + str(self.auth_rr_count) + " | Number of Additional Resource Records: " + str(self.add_rr_count) + "\n"
        builder += "-"*35+"End of Header"+"-"*35+"\n"
        builder += "\n\n\n\n"
        return builder

    def getRcode(self, code):
        match code:
            case 0:
                return 'NOERROR'
            case 1:
                return 'FORMERR' #Format error
            case 2:
                return 'SERVFAIL'
            case 3:
                return 'NXDOMAIN'
            case _:
                raise Exception('Unknown DNS Response Code')
    def doTree(self, tree, treename):
        if treename == "dns.id_tree":
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.expertnumber += 1
                        for j in tree[i]:
                            if "_ws.expert" in j:
                                self.doProcessExpert(j, tree[i][j])
                            elif 'dns.retransmit_request' == j:#DNS query retransmission (Label)
                                self.private['retrans_req'] = tree[i][j]
                            elif 'dns.retransmit_response' == j: #DNS response retransmission (Label)
                                self.private['retrans_res'] = tree[i][j]
                            else:
                                print(f"Unknown DNS ID tree key in wireshark expert subtree {j}")
                    case _:
                        print(f"Unknown DNS ID tree key {i}")
        elif treename == self.typ.lower()+".flags_tree":
            for j in tree:
                match j.partition(".")[2].partition(".")[2]: #dns.flags.X
                    case 'authenticated': #Answer Authenticated / Authentic Data (boolean)
                        self.private["flags"]["AD"] = bool(int(tree[j]))
                    case 'authoritative': #Authoritative (boolean)
                        self.private["flags"]["AA"] = bool(int(tree[j]))
                    case 'broadcast': #Broadcast (boolean)
                        self.private['flags']['BC'] = bool(int(tree[j]))
                    case 'checkdisable': #Non-authenticated data / Checking disabled (boolean)
                        self.private["flags"]["CD"] = bool(int(tree[j]))
                    case 'conflict': #Conflict (boolean)
                        self.private["flags"]["C"] = bool(int(tree[j]))
                    case 'opcode': #Opcode (uint16)
                        self.private['flags']['OPCODE'] = int(tree[j])
                        if int(tree[j]) == 0:
                            self.private['flags']['OPCODE'] = 'QUERY'
                        elif int(tree[j]) == 1:
                            self.private['flags']['OPCODE'] = 'IQUERY'
                        elif int(tree[j]) == 2:
                            self.private['flags']['OPCODE'] = 'STATUS'
                        else:
                            raise Exception("Invalid DNS Opcode flag")
                    case 'rcode': #Reply code (uint16)
                        self.private['flags']['RCODE'] = self.getRcode(int(tree[j]))
                    case 'recavail': #Recursion available (boolean)
                        self.private["flags"]['RA'] = bool(int(tree[j]))
                    case 'recdesired': #Recursion desired (boolean)
                        self.private['flags']['RD'] = bool(int(tree[j]))
                    case 'response': #Response (boolean)
                        self.private["flags"]["QR"] = not bool(int(tree[j]))
                        if not self.private['flags']['QR']:
                            self.type = 'Response'
                        else:
                            self.type = 'Query'
                    case 'tentative': #Tentative (boolean)
                        self.private["flags"]["T"] = bool(int(tree[j]))
                    case 'truncated': #Truncated (boolean)
                        self.private["flags"]["TC"] = bool(int(tree[j]))
                    case 'z': #reserved bit (boolean)
                        self.private["flags"]["Z"] = bool(int(tree[j]))
                        if self.private['flags']['Z']:
                            raise Exception(f"DNS Error: Non-zero value in the zero flag bit. {self.private['flags']['Z']}")
                    case _:
                        print(f"Unknown private (flags) DNS key in tree {j}")

        else: print("Unknown DNS tree", treename)

class LLMNR(DNS): #Link-Local Multicast Name Resolution
    typ = "LLMNR"
    def doMoarInit(self):
        super().doMoarInit({x: self.data[x] for x in self.data if 'llmnr' not in x})
        for i in {x: self.data[x] for x in self.data if 'llmnr' in x}:
            match i:
                case _:
                    print("Unknown LLMNR key", i)

class MDNS(DNS):
    typ = "mDNS"
    def doMoarInit(self):
        super().doMoarInit()

class NBNS(DNS): #NetBIOS Name Service
    typ = "NBNS"
    ints = DNS.ints.copy()
    ints.update({"nbns.flags":"base_flags", #Flags (uint16)
                "nbns.id":"id", #Transaction ID (uint16)
                'nbns.count.add_rr':"add_rr_count", #Additional RRs (uint16)
                 'nbns.count.answers':'answers_count', #Answer RRs (uint16)
                 'nbns.count.auth_rr':'auth_rr_count',#Authority RRs (uint16)
                 'nbns.count.queries':'queries_count',#Questions (uint16)
                 })
    trees = DNS.trees + ["nbns.flags_tree"]
    def doMoarInit(self):
        super().doMoarInit()
        for i in self.data:
            if i in self.ints or i in self.trees or i == "Queries":
                continue
            match i:
                case _:
                    print("Unknown NBNS key", i)

