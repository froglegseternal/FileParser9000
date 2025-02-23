import json
import argparse
import util 
import warnings

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--file', help='Path to the input file', required=True)
    parser.add_argument('-v', '--verbose', help="Whether to print requested information verbosely", action="store_true")
    parser.add_argument('--debug', help='Whether to print debug information', action='store_true')

    parser.add_argument('--data', help='Whether to print extraneous data information', action='store_true')
    parser.add_argument('--dhcp', help='Whether to print DHCP information', action='store_true')
    parser.add_argument('--dns', help='Whether to print DNS information', action='store_true')
    parser.add_argument('--quic', help='Whether to print GQUIC information', action='store_true')
    parser.add_argument('--http', help='Whether to print the http data', action='store_true')
    parser.add_argument('--icmp', help='Whether to print ICMP information', action='store_true')
    parser.add_argument('--igmp', help='Whether to print IGMP information', action='store_true')
    parser.add_argument('--imf', help='Whether to print IMF information', action='store_true')
    parser.add_argument('--lldp', help='Whether to print LLDP information', action='store_true')
    parser.add_argument('--llmnr', help='Whether to print LLMNR information', action='store_true')
    parser.add_argument('--mdns', help='Whether to print MDNS information', action='store_true')
    parser.add_argument('-ad', '--activedirectory', help='Whether to print Active-Directory related information', action='store_true')
    parser.add_argument('--smtp', help='Whether to print SMTP information', action='store_true')
    parser.add_argument('--ssdp', help='Whether to print SSDP information', action='store_true')
    parser.add_argument('--xml', help='Whether to print XML information', action='store_true')

    parser.add_argument('--arp', help='Whether to print ARP information', action='store_true')
    parser.add_argument('--ethernet', help='Whether to print ethernet information', action="store_true")
    parser.add_argument('--frame', help='Whether to print frame metadata', action='store_true')
    parser.add_argument('--ipdata', help='Whether to print IP Data information', action='store_true')
    parser.add_argument('--kerb', help="Whether to print kerberos information", action="store_true")
    parser.add_argument('--tcp', help='Whether to print TCP information', action='store_true')
    parser.add_argument('--tls', help='Whether to print TLS information', action='store_true')
    parser.add_argument('--udp', help='Whether to print UDP information', action='store_true')

    parser.add_argument('--checks', help='Whether to attempt to validate every field is a correct value', action='store_true')
    parser.add_argument('--ctf', help='Whether to attempt to solve the current CTF problem', action='store_true')
    args = parser.parse_args()

if __name__ != "__main__":

    import sys

    sys.path.append("/home/froglegs/Documents/git/")

    import pcap_processor

    args = pcap_processor.args

if args.tcp or args.tls or args.udp or args.quic:
    import transportlayer

if args.arp or args.lldp:
    import linklayer

if args.dhcp or args.dns or args.llmnr or args.mdns:
    import resolution

if args.http or args.icmp or args.igmp or args.ssdp:
    import internet

if args.activedirectory:
    import activedirectory as ad
    import resolution

class Ethernet(util.DataFrame):
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"eth.padding":("padding","byteseq"), #Padding
                    "eth.trailer":("trail","byteseq"), #Trailer
                    "eth.fcs.status":("FCSstat","uint8"), #FCS Status
                    "eth.type":("type","uint16"), #Type
                    "eth.fcs":("framecheck","uint32"), #Frame check sequence
                     })
    trees = util.DataFrame.trees + ["eth.trailer_tree", #???
                                    ]
    def __init__(self, data, frame):
        super().__init__(data, frame)
        self.dst = {}
        self.src = {}
        self.private = {}
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            if "eth." == i[0:4]:
                match i[4:]:
                    case 'dst':
                        self.dst['root'] = self.data[i] #Destination (MAC address)
                    case 'dst_tree':
                        tmp = self.data[i]
                        self.make_tree('dst_tree',tmp)
                    case 'src':
                        self.src['root'] = self.data[i] #Source (MAC address)
                    case 'src_tree':
                        tmp = self.data[i]
                        self.make_tree('src_tree', tmp)
                    case _:
                        print(f"Unknown private Ethernet key {i[4:]}")
            else:
                print("Unknown public Ethernet key {i}")
    def make_tree(self, tree, data):
        dic = {'src_tree': self.src, 'dst_tree': self.dst}
        spot = dic[tree]
        for i in data.keys():
            if ('eth.src.' in i and tree != 'src_tree') or ('eth.dst.' in i and tree!= 'dst_tree'):
                warnings.warn("unexpected behavior. code change needed.")
            match i:
                case 'eth.addr': #Address
                    spot['addr'] = data[i]
                case 'eth.addr.oui': #Address OUI
                    spot['addr_oui'] = data[i]
                case 'eth.addr.oui_resolved': #Address OUI (resolved)
                    spot['addr_oui_resolved'] = data[i]
                case 'eth.addr_resolved': #Address (resolved)
                    spot['addr_resolved'] = data[i]
                case 'eth.ig': #IG bit
                    spot['ig_base_bit'] = data[i]
                case 'eth.lg': #LG bit
                    spot['lg_base_bit'] = data[i]
                case _:
                    match i[8:]:
                        case 'resolved': #Source/Destination (resolved)
                            spot['resolved'] = data[i]
                        case 'ig': #IG bit
                            spot['ig_bit'] = data[i]
                        case 'lg': #LG bit
                            spot['lg_bit'] = data[i]
                        case 'oui': #OUI
                            spot['oui'] = data[i]
                        case 'oui_resolved': #OUI (resolved)
                            spot['oui_resolved'] = data[i]
                        case _:
                            print(f'Unknown private Ethernet {tree} key {i}')
    def doTree(self, tree, treename):
        if treename == "_ws.expert":
            self.expertnumber += 1
            for i in tree:
                if "_ws.expert" in i:
                    self.doProcessExpert(i, tree[i], self.expertnumber)
                else:
                    match i:
                        case 'eth.padding_bad':
                            self.badpad = True
                        case _:
                            print("Unknown _ws.expert tree key", i)
        elif treename == "eth.trailer_tree":
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown trailer_tree key", i)
        else:
            raise Exception("Unimplemented")
    def __str__(self):
        builder = "-"*45 + "Ethernet"+"-"*45+"\n"
        builder += "Destination MAC Address: "+str(self.dst['root'])
        builder += " | Source MAC Address: "+str(self.src['root'])
        builder += "\nEtherType/Length: "+self.getEtherType()+"\n"
        if "framecheck" in self.__dict__:
            builder += "Frame check sequence: "+str(self.framecheck)
            builder += " (Status: "+str(self.FCSstat)+")"+"\n"
        return builder

    eth_types = {0x800: "IPv4",
                 0x806: "ARP",
                 0x86dd: "IPv6"}
    def getEtherType(self): # https://en.wikipedia.org/wiki/EtherType
        if self.type <= 1500:
            return "Length ("+str(self.type)+")"
        if self.type < 1536:
            raise Exception("Invalid EtherType")
        try: return self.eth_types[self.type]
        except: 
            print(hex(self.type))
            raise Exception("Unimplemented EtherType")

class Frame(util.PacketDiss):
    def __init__(self, data):
        super().__init__(data)
        self.private = {}
        self.number = self.data['frame.number']
    def doMoarInit(self):
        for i in self.data:
            if i[0:6] == 'frame.':
                if i[5:20] == '.coloring_rule.': #frame.coloring_rule.X
                    if 'coloring_rule' not in self.private.keys():
                        self.private['coloring_rule'] = {}
                    match i[20:]:
                        case 'name': #Coloring Rule Name
                            self.private['coloring_rule']['name'] = self.data[i]
                        case 'string': #Coloring Rule String
                            self.private['coloring_rule']['string'] = self.data[i]
                        case _:
                            print(f"Unknown private (coloring_rule) frame key {i[20:]}")
                elif i[5:10] == '.time': #frame.timeX
                    if 'times' not in self.__dict__.keys():
                        self.times = {}
                    match i[10:]:
                        case '': #Arrival time
                            self.times['arrival'] = self.data[i]
                        case '_delta': #Time delta from previous captured frame
                            self.times['delta'] = self.data[i]
                        case '_delta_displayed': #Time delta from previous captured frame
                            self.times['delta_displayed'] = self.data[i]
                        case '_epoch': #Epoch Arrival Time
                            self.times['epoch'] = self.data[i]
                        case '_relative': #Time since reference or first frame
                            self.times['rel'] = self.data[i]
                        case _:
                            print(f"Unknown private (time) frame key {i[10:]}")
                else:
                    match i[6:]: #frame.X
                        case 'cap_len': #Frame length stored into the capture file
                            self.private['cap_len'] = self.data[i]
                        case 'encap_type': #Encapsulation type
                            self.private['encap_type'] = self.data[i]
                        case 'ignored': #Frame is ignored
                            self.private['ignored'] = self.data[i]
                        case 'interface_id': #Interface id
                            self.private['intid'] = int(self.data[i])
                        case 'interface_id_tree': #???
                            self.doTree(self.data[i], i)
                        case 'len': #Frame length on the wire
                            self.private['len'] = self.data[i]
                        case 'marked': #Frame is marked
                            self.private['marked'] = self.data[i]
                        case 'number': #Frame Number
                            self.number = self.data[i]
                            print(f'Frame number: {self.data[i]}')
                        case 'offset_shift': #Time shift for this packet
                            self.private['offset_shift'] = self.data[i]
                        case 'protocols': #Protocols in frame
                            self.private['protos'] = self.data[i]
                            print(f'Protocols in frame: {self.data[i]}')
                        case 'section_number': #Section number
                            self.private['sectnum'] = int(self.data[i])
                        case _:
                            print(f"Unknown private frame key {i[6:]}")
            else:
                print(f"Unknown frame public key {i}")
    def doTree(self, tree, treename):
        if treename == 'frame.interface_id_tree':
            for i in tree:
                match i:
                    case 'frame.interface_description':
                        self.private['frameintdesc'] = tree[i]
                    case 'frame.interface_name':
                        self.private['frameintname'] = tree[i]
                    case _:
                        print("Unknown frame.interface_id_tree key",i)
        else:
            print("Unknown frame tree name",treename)

class IMF(util.DataFrame): #Internet Message Format
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"imf.content.type":("contenttype","str"), #Content-Type
                    "imf.date":("date","str"), #Date
                    "imf.from":("fro","str"), #From
                    "imf.message_id":("id","str"), #Message-ID
                    "imf.mime_version":("mime_ver","str"), #MIME-Version
                    "imf.subject":("subj","str"), #Subject
                    "imf.to":("to","str"), #To
                    "imf.user_agent":("useragent","str"), #User-Agent
                 })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        self.private = {}
        self.fros = {}
        self.tos = {}
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            if i[0:4] == "imf.":
                match i[4:]: #imf.X
                    case "content.type_tree":
                        self.doTree(self.data[i], i)
                    case 'from_tree': #???
                        self.doTree(self.data[i], i)
                    case 'to_tree': #???
                        self.doTree(self.data[i], i)
                    case _:
                        print(f"Unknown IMF private key {i[4:]}")
            else:
                match i:
                    case "mime_multipart":
                        self.contents = util.MIME(self.data[i])
                    case _:
                        print(f"Unknown IMF public key {i}")
    def doTree(self, tree, treename, treetype="No Type"):
        if treename == 'imf.content.type_tree':
            for i in tree:
                if i[0:17] == 'imf.content.type.':
                    match i[17:]:
                        case 'parameters': #Parameters
                            self.contenttype_param = tree[i]
                        case 'type': #Type
                            self.contenttype_type = tree[i]
                        case _:
                            print("Unknown key in imf.content_type_tree", i)
                else:
                    match i:
                        case _:
                            print("Unknown key in imf.content_type_tree", i)
        elif treename == 'imf.from_tree': #???
            for i in tree:
                if i[0:21] == 'imf.mailbox_list.item':
                    match i[21:]:
                        case '': #Item
                            self.doTree(tree['imf.mailbox_list.item_tree'], tree[i], treetype='From')
                        case '_tree':
                            pass
                        case _:
                            print("Unknown key in imf.from_tree", i)
                else:
                    match i:
                        case _:
                            print("Unknown key in imf.from_tree", i,"with value",tree[i])
        elif treename == 'imf.to_tree':
            for i in tree:
                if i[0:21] == 'imf.address_list.item':
                    match i[21:]:
                        case '': #Item
                            self.doTree(tree['imf.address_list.item_tree'], tree[i], treetype='To')
                        case '_tree':
                            pass
                        case _:
                            print("Unknown key in imf.to_tree", i)
                else:
                    match i:
                        case _:
                            print("Unknown key in imf.to_tree", i)
        elif treetype == 'From':
            self.fros[treename] = {}
            for i in tree:
                match i:
                    case 'imf.address': #Address
                        self.fros[treename]['address'] = tree[i]
                    case _:
                        print("Unknown key in IMF from_tree", i)
        elif treetype == 'To':
            self.tos[treename] = {}
            for i in tree:
                match i:
                    case 'imf.address': #Address
                        self.tos[treename]['address'] = tree[i]
                    case _:
                        print("Unknown key in IMF to_tree", i)
        else:
            print("Unknown IMF tree",treename)
    
    def __str__(self):#https://datatracker.ietf.org/doc/html/rfc5322
        builder = '-'*40+"IMF"+'-'*40+"\n"
        builder += "Date: "+self.date+"\n\n"
        builder += "From: "+self.fro+"\n"
        builder += str(self.fros)+"\n\n"
        builder += "To: "+self.to+"\n"
        builder += str(self.tos)+"\n\n"
        if "id" in self.__dict__:
            builder += "Message-ID: "+self.id+"\n\n"
        builder+= "Subject: "+self.subj+"\n"
        return builder

class IpV4(util.DataFrame):
    typ = "IpV4"
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"ip.checksum":("check","uint16"), #Header Checksum (uint16)
                    "ip.checksum.status":("checkstat","uint8"), #Header checksum status (uint8)
                    "ip.dsfield":("dsfield","uint8"), #Differentiated Services Field (uint8)
                    "ip.flags":("root_flags","uint8"), #Flags (uint8)
                    "ip.frag_offset":("frag_off","uint16"), #Fragment Offset (uint16)
                    "ip.id":("id","uint16"), #Identification (uint16)
                    "ip.version":("ver","uint8"), #Version (uint8)
                    "ip.hdr_len":("hdr_len","uint8"), #Header Length (uint8)
                    "ip.len":("len","uint16"), #Total Length (uint16)
                    "ip.proto":("proto","uint8"), #Protocol (uint8)
                    "ip.ttl":("ttl","uint8"), #Time to Live (uint8)
                    "ip.dsfield_tree":"Specialtree",
                    "ip.flags_tree":"Specialtree",
                    "ip.ttl_tree":"Specialtree"
                    })
    strs = util.DataFrame.__dict__['strs'].copy()
    strs.update({"ip.dst_host":"dst_host", #Destination Host
                 "ip.host":"host", #Source or Destination Host
                "ip.src_host":"src_host" #Source Host
                 })
    framerefs = util.DataFrame.__dict__['framerefs'].copy()
    def __init__(self, data, frame):
        self.options = []
        super().__init__(data, frame)
    def doMoarInit(self, data=None):
        if self.typ == "IpV4":
            data = self.data
        for i in data:
            if i in self.keyvals:
                continue
            if i not in self.trees and i not in self.ints and i not in self.strs:
                match i[3:]: #ip.X
                    case "addr": #Source or Destination address (IPv4 address)
                        self.addr = data[i]
                    case "dst": #Destination Address (IPv4 address)
                        self.dst = data[i]
                    case 'src': #Source Address (IPv4 address)
                        self.src = data[i]
                    case _:
                        if "Options" in i:
                            self.doTree(data[i],i,"Options")
                        else:
                            raise Exception(f"Unknown IpData ({self.typ}) key {i} with value {data[i]}")
    def doTree(self, tree, treename,treetype=None):
        if treename == 'ip.dsfield_tree':
            for i in tree:
                match i[11:]: #ip.dsfield.X
                    case 'ce': #ECN-CE (uint8)
                        self.ecnce = int(tree[i], 16)
                    case 'dscp': #Differentiated Services Codepoint (uint8)
                        self.dscp = self.getInt(tree[i])
                    case 'ecn': #Explicit Congestion Notification (uint8)
                        self.ecn = int(tree[i], 16)
                    case _:
                        print("Unknown IpData dsfield tree key",i)
        elif treename == 'ip.flags_tree':
            for i in tree:
                match i[9:]: #ip.flags.X
                    case 'df': #Don't fragment (Boolean)
                        self.fragment = bool(int(tree[i]))
                    case 'mf': #More fragments (Boolean)
                        self.morefrag = bool(int(tree[i]))
                    case 'rb': #Reserved bit (Boolean)
                        self.reserbit = bool(int(tree[i]))
                    case 'sf': #Security flag (Boolean)
                        self.secur = bool(int(tree[i]))
                    case _:
                        print("Unknown IpData flags tree key", i)
        elif treename == 'ip.ttl_tree':
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.doTree(tree[i], '_ws.expert')
                    case _:
                        print("Unknown IpData (",self.typ,") ttl tree key", i)
        elif treename == '_ws.expert':
            self.expertnumber += 1
            for i in tree:
                if '_ws.expert' in i:
                    self.doProcessExpert(i, tree[i], self.expertnumber)
                else:
                    match i:
                        case 'ip.ttl.lncb': #Time to Live (Label)
                            self.ttl_lncb = True
                        case 'ip.ttl.too_small': #Time to Live (Label)
                            self.ttl_too_small = True
                        case _:
                            print("Unknown IpData (",self.typ,") _ws.expert tree key", i, "with value", tree[i])
        elif treetype == "Options": #https://en.wikipedia.org/wiki/Internet_Protocol_Options
            self.options.append({"Option":treename})
            for i in tree:
                match i:
                    case 'ip.options.routeralert':
                        self.options[-1]["routeralert"] = tree[i]
                    case 'ip.options.routeralert_tree':
                        self.options[-1]["tree"] = tree[i]
                    case _:
                        raise Exception("Unknown IpData ("+self.typ+") Options tree key "+i+" with value "+str(tree[i])+" in tree "+treename)
        else:
            raise Exception("Unknown tree "+treename+" in IpData version "+self.typ)
    def __str__(self): #https://en.wikipedia.org/wiki/IPv4
        builder = "-"*50 + self.typ +"-"*50 + "\n"
        builder += "Version: "+str(self.ver) + " | Header Length: "+str(self.hdr_len) + " | DSCP: "+self.getDSCPClass()+ " | ECN: "+self.getECN() + " | Total Length: " + str(self.len) + "\n"
        builder += "Identification: "+str(self.id)+" | Flags: "+self.getFlags()+" | Fragment Offset: "+str(self.frag_off)+"\n"
        builder += "Time to Live: "+str(self.ttl) + "\nProtocol: "+self.getProto(self.proto)+ "\nHeader Checksum: "+str(self.check) + " (Status: "+str(self.checkstat)+")"+"\n"
        builder += "Source Address: "+self.src+" | Destination Address: "+self.dst+"\n"
        builder += "\n"
        builder += "Source Host: "+self.src_host+" | Destination Host: "+self.dst_host+"\n\n"
        for i in self.options:
            builder += str(i)+"\n"
        return builder

    def doCheck(self):
        if self.ver != 4 and self.typ == "IpV4":
            raise Exception(f"Invalid IP Version field value {self.ver}, this should be 4.")
        if self.ver != 6 and self.typ == "IpV6":
            raise Exception(f"Invalid IP Version field head value {self.ve}, this should be 6.")
        if self.hdr_len < 20 or self.hdr_len > 60:
            raise Exception(f"Invalid header length value {self.hdr_len}, this should be betwee 5 and 15, inclusive.")
        if self.reserbit and self.typ == "IpV4":
            raise Exception(f"The reserved IpData (ipv6) flag is flipped when it should not be.")

    def getDSCPClass(self): #https://en.wikipedia.org/wiki/Differentiated_services
        match self.dscp:
            case 0:
                return "Standard"
            case 4:
                return "Unknown"
            case 8:
                return "Low-priority data"
            case 16:
                return "Network operations, administration and management (OAM)"
            case 24:
                return "Broadcast video"
            case 32:
                return "Real-time interactive"
            case 40:
                return "Signaling"
            case 48:
                return "Network control"
            case 56:
                return "Reserved for future use"
            case _:
                raise Exception(f"Invalid DSCP value {self.dscp}")
    def getECN(self): # https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        match self.ecn:
            case 0:
                return "Not ECN-Capable Transport, Not-ECT"
            case 1:
                return "ECN Capable Transport, ECT"
            case 2:
                return "ECN Capable Transport, ECT"
            case 3:
                return "Congestion Experience, CE"
            case _:
                raise Exception(f"Invalid ECN value {self.ecn}")
    def getFlags(self):
        builder = "Reserved Bit:"
        if self.reserbit: builder += "Y"
        else: builder += "N"
        builder += ", Don't Fragment:"
        if self.fragment: builder += "Y"
        else: builder += "N"
        builder += ", More Fragments:"
        if self.morefrag: builder += "Y"
        else: builder += "N"
        return builder
    
    protoMap = {0: ("HOPOPT", "IPv6 Hop-by-Hop Option"),
                1: ("ICMP", "Internet Control Message Protocol"),
                2: ("IGMP", "Internet Group Management Protocol"),
                6: ("TCP", "Transmission Control Protocol"),
                17: ("UDP", "User Datagram Protocol"),
                23: ("Trunk-1", "Trunk-1"),
                41: ("IPv6", "IPv6 Encapsulation"),
                58: ("IPv6-ICMP", "ICMP for IPv6"),
                89: ("OSPF", "Open Shortest Path First"),
                132: ("SCTP", "Stream Control Transmission Protocol")
                }
    
    def getProto(self, nmbr=None): # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        if nmbr == None:
            nmbr = self.proto
        try:
            return self.protoMap[nmbr][0]
        except:
            raise Exception(f"Unknown Protocol Number {nmbr}")

    def getFullProtocol(self, nmbr=None):
        if nmbr == None:
            nmbr = self.proto
        try:
            return self.protoMap[nmbr][1]
        except:
            raise Exception(f"Unknown Protocol Number {nmbr}")


class IpV6(IpV4): #Internet Protocol Version 6
    typ = "IpV6"
    keyvals = IpV4.keyvals.copy()
    keyvals.update({"ipv6.tclass":("tclass","uint32"), #Traffic Class (uint32)
                    "ipv6.version":("ver","uint8"), #Version (uint8)
                    "ipv6.flow":("flow","uint24"), #Flow Label (uint24)
                    "ipv6.hlim":("hlim","uint8"), #Hop Limit (uint8)
                    "ipv6.nxt":("nxt","uint8"), #Next Header (uint8)
                    "ipv6.plen":("plen","uint16"), #Payload Length (uint16)
                    "ipv6.hopopts":"Specialtree", #Hop-by-Hop Options
                    "ipv6.tclass_tree":"Specialtree",
        })
    strs = IpV4.__dict__["strs"].copy()
    strs.update({"ipv6.dst_host":"dst_host", #Destination Host
                "ipv6.host":"host", #Source or Destination Host
                "ipv6.src_host":"src_host" #Source Host
                 })
    ipv6_addrs = util.DataFrame.__dict__['ipv6_addrs'].copy()
    ipv6_addrs.update({"ipv6.addr": "addr", #Source or Destination Address (IPv6 Address)
                       "ipv6.dst":"dst", #Destination Address
                        "ipv6.src":"src" #Source Address (IPv6 Address)
                       })
    framerefs = IpV4.__dict__["framerefs"].copy()
    framerefs.update({})
    def __init__(self, data, frame):
        super().__init__(data, frame)
    def doMoarInit(self):
        build = {x: self.data[x] for x in self.data if "ipv6" not in x}
        for i in {x: self.data[x] for x in self.data if "ipv6" in x}:
            if i not in self.ints and i not in self.trees and i not in self.ipv6_addrs and i not in self.strs:
                match i:
                    case 'ipv6.slaac_mac': #SLAAC MAC (Ethernet or other MAC address)
                        self.slaac_mac = self.data[i]
                    case 'ipv6.src_slaac_mac': #Source SLAAC MAC (Ethernet or other MAC address)
                        self.src_slaac_mac = self.data[i]
                    case _:
                        raise Exception(f"Unknown IpData (ipv6) key {i} with value {self.data[i]}")
        super().doMoarInit(build)
        print(self)
        try:
            print(self.hopopts)
        except:
            pass
    def doTree(self, tree, treename):
        try:
            super().doTree(tree, treename)
        except:
            if treename == "ipv6.tclass_tree":
                for i in tree:
                    match i:
                        case 'ipv6.tclass.dscp': #Differentiated Services Codepoint (uint32)
                            self.dscp = int(tree[i], 16)
                        case 'ipv6.tclass.ecn': #Explicit Congestion Notification (uint32)
                            self.ecn = int(tree[i], 16) 
                        case _:
                            print("Unknown ipv6.tclass_tree key",i)
            elif treename == "ipv6.hopopts":
                self.hopopts = HopOptions(tree, self.framenum)
            else:
                print("Unknown Ipv6 tree",treename)
    def __str__(self):
        builder = "-"*50 + self.typ +"-"*50 + "\n"
        builder += " "*20+"Fixed Header"+"\n"
        builder += "Version: "+str(self.ver) + " | Traffic Class - DSCP: "+self.getDSCPClass()+ ", ECN: "+self.getECN() + " | Flow Label: " + str(self.flow) + "\n"
        builder += "Payload Length: "+str(self.plen)+"\nNext Header (Protocol): "+self.getProto()+"\nHop Limit: "+str(self.hlim)+"\n"
        builder += "Source Address: "+self.src+" | Destination Address: "+self.dst+"\n"
        builder += "\n"
        builder += "Source Host: "+self.src_host+" | Destination Host: "+self.dst_host+"\n\n"
        return builder

    def getProto(self, proto=None):
        if proto == None:
            return super().getProto(self.nxt)
        else:
            return super().getProto(proto)
        
    def getFullProtocol(self, proto=None):
        if proto == None:
            return super().getFullProtocol(self.nxt)
        else:
            return super().getProto(proto)

class NTP(util.DataFrame): #Network Time Protocol
    ints = util.DataFrame.__dict__["ints"].copy()
    ints.update({"ntp.flags":"flags", #Flags (uint8)
                 "ntp.rootdelay": "rootdel", #Root Delay (uint32)
                 "ntp.rootdispersion":"rootdisp", #Root Dispersion (uint32)
                 "ntp.stratum":"stratum" #Peer Clock Stratum (uint8)
                    })
    byteseqs = util.DataFrame.__dict__['byteseqs'].copy()
    byteseqs.update({"ntp.refid":"refid" #Reference ID (Byte sequence)
                     })
    trees = util.DataFrame.__dict__['trees'] + ["ntp.flags_tree"]
    def doMoarInit(self):
        for i in self.data:
            if i in self.ints or i in self.trees or i in self.byteseqs:
                continue
            elif i[0:4] == 'ntp.':
                match i[4:]:
                    case 'delta_time': #Delta Time (Time offset)
                        self.time_delt = self.data[i]
                    case 'org': #Origin Timestamp (Date and Time)
                        self.org = self.data[i]
                    case 'ppoll': #Peer Polling Interval (int8) note: SIGNED
                        self.ppoll = int(self.data[i])
                    case 'precision': #Peer Clock Precision (int8) note: SIGNED
                        self.pcp = int(self.data[i])
                    case 'rec': #Receive Timestamp (Date and Time)
                        self.rec = self.data[i]
                    case 'reftime': #Reference Timestamp (Date and Time)
                        self.reftime = self.data[i]
                    case 'request_in': #Request in frame X (Frame number)
                        self.reqref = int(self.data[i])
                    case 'response_in': #Response in frame X (Frame number)
                        self.respref = int(self.data[i])
                    case 'xmt': #Transmit Timestamp (Date and Time)
                        self.xmt = self.data[i]
                    case _:
                        print("Unknown NTP key", i)
            else:
                match i:
                    case _:
                        print("Unknown NTP Key", i)
    def __str__(self):
        builder = "-"*40+"NTP"+"-"*40+"\n"
        return builder

    def doTree(self, tree, treename):
        if treename == 'ntp.flags_tree':
            for i in tree:
                if i[0:10] == 'ntp.flags.':
                    match i[10:]:
                        case 'li': #Leap Indicator
                            self.leap_ind = int(tree[i])
                        case 'mode': #Mode
                            self.mode = int(tree[i])
                        case 'vn': #Version Number
                            self.vn = int(tree[i])
                        case _:
                            print("Unknown key in ntp.flags_tree", i)
                else:
                    match i:
                        case _:
                            print("Unknown key in ntp.flags_tree", i)
        else:
            print("Unknown NTP tree",treename)


class IPV6Extension(IpV6):
    typ = "IPV6Extension"
    ints = {}
    strs = {}
    ipv6_addrs = {}
    trees = []
    framerefs = {}

class HopOptions(IPV6Extension): #https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
    typ = "HopOptions"
    ints = IPV6Extension.__dict__["ints"].copy()
    ints.update({"ipv6.hopopts.len":"len", #Length (uint8)
                 "ipv6.hopopts.len_oct":"len_oct", #???
        "ipv6.hopopts.nxt":"nxt" #Next Header (uint8)
    })
    trees = IPV6Extension.__dict__["trees"] + ["ipv6.opt" #IPv6 Option
                                                ]
    def __init__(self, data, frame):
        self.options = []
        super().__init__(data, frame)
        for i in data:
            if i not in self.ints and i not in self.trees:
                match i:
                    case _:
                        print("Unknown HopOptions Key", i)
    def doTree(self, tree, treename):
        if treename == "ipv6.opt":
            self.options.append({})
            for i in tree:
                match i:
                    case 'ipv6.opt.length': #Length (uint8)
                       self.optlen = self.getInt(tree[i])
                    case 'ipv6.opt.padn': #PadN (byte sequence)
                        if len(tree[i]) > 0:
                            self.optpadn = util.unpackByteSequence(tree[i])
                    case 'ipv6.opt.type':
                        self.options[-1]["type"] = self.getInt(tree[i]) #Type (uint8)
                    case 'ipv6.opt.type_tree':
                        for j in tree[i]:
                            match j:
                                case 'ipv6.opt.type.action': #Action (uint8)
                                    self.options[-1]["action"] = self.getInt(tree[i][j])
                                case 'ipv6.opt.type.change': #May Change (boolean)
                                    self.options[-1]["maychange"] = bool(int(tree[i][j]))
                                case 'ipv6.opt.type.rest': #Low-Order Bits (uint8)
                                    self.options[-1]["rest"] = self.getInt(tree[i][j])
                    case _:
                        print("Unknown key",i,"in ipv6.opt with value",tree[i])
        else:
            print("Unknown HopOptions tree")
    def __str__(self):
        builder = "-"*45 + "HopOptions"+"-"*45+"\n"
        builder += "Next Header: "+self.getFullProtocol(self.nxt)
        builder += " | Header extension length: "+str(self.len)
        builder += " | Options: "+str(self.options)+"\n"
        return builder

class SMTP(util.DataFrame):
    hexints = util.DataFrame.__dict__['hexints'].copy()
    hexints.update({})
    trees = util.DataFrame.__dict__['trees'] + []
    def doMoarInit(self, data, frame):
        print('-'*8+'SMTP'+'-'*8)
        print(f"Frame number {self.framenum}")
        for i in self.data:
            match i:
                case 'smtp.response': #???
                    self.response = self.data['smtp.response']
                case 'smtp.command_line': #Command Line
                    self.command_line = self.data['smtp.command_line']
                case 'smtp.req': #???
                    if self.data['smtp.req'] == '1':
                        self.typ = 'Request'
                case 'smtp.rsp': #???
                    if self.data['smtp.rsp'] == '1':
                        self.typ = 'Response'
                case 'smtp.eom': #???
                    if not self.data['smtp.eom']:
                        self.typ = 'End of Message'
                case 'data-text-lines':
                    self.typ = 'Data'
                    self.datalines = self.data[i]
                    self.datatext = ''
                    for j in self.datalines:
                        self.datatext+=j
                case 'smtp.command_line_tree':
                    tmp = self.data[i]
                    self.doTree(self.data[i], i)
                    if 'command' in self.__dict__.keys() and 'parameter' in self.__dict__.keys():
                        self.fullcommand = self.command + " " + self.parameter
                    else:
                        self.fullcommand = self.command
                case 'smtp.data.fragments': #DATA fragments
                    self.typ = "Fragmented"
                    self.data_fragments = self.data[i]
                case 'smtp.data.reassembled.in': #Reassembled DATA in frame
                    self.data_reassem = int(self.data[i])
                case 'smtp.response_tree': #???
                    self.doTree(i, self.data[i])
                case _:
                    print(f'Unknown SMTP key {i}')
        if 'typ' not in self.__dict__.keys():
            print('Unknown SMTP Type')
    def getFrameRef(self):
        if 'data_reassem' in self.__dict__:
            return self.data_reassem
        else:
            return -1
    def doTree(self, tree, treename):
        if treename == "smtp.command_line_tree":
            for i in tree:
                match i:
                    case 'smtp.req.command':
                        self.command = tree[i]
                    case 'smtp.req.parameter':
                        self.parameter = tree[i]
                    case _:
                        print(f"Unknown SMTP command_line_tree key {i}") 
        else:
            print(f"Unknown SMTP tree {treename}")
    
    def __str__(self):
        builder = "-"*40+"SMTP"+"-"*40+"\n"
        builder += f"Frame Number: {self.framenum}\n"
        builder += f"SMTP Type: {self.typ}\n"
        if 'fullcommand' in self.__dict__:
            builder += self.fullcommand + "\n"
        elif 'command' in self.__dict__:
            builder += self.command + "\n"
        if 'response' in self.__dict__:
            builder += self.response + "\n"
        if self.typ == 'Data':
            for i in self.datatext.split('\\r\\n'):
                builder += i +"\n" 
            builder += f"{self.__dir__()}\n"
        if self.typ == 'Fragmented':
            builder += f"Data Fragments: {self.data_fragments}\n"
            builder += f"{self.__dir__()}\n"
        return builder

class WLAN(util.DataFrame): #https://www.wireshark.org/docs/dfref/w/wlan.html
    ints = util.DataFrame.__dict__['ints'].copy()
    ints.update({"wlan.duration":"duration", #Duration (uint16)
                 "wlan.fc":"fc", #Frame Control Field (uint16)
                 "wlan.fc.type_subtype":"fc_type_subtype", #Type/Subtype (uint16)
                 "wlan.frag":"fragnum", #Fragment number (uint16)
                 "wlan.qos":"qos", #Qos Control (uint16)
                 "wlan.seq":"seqnum" #Sequence number (uint16)
        })
    strs = util.DataFrame.__dict__['strs'].copy()
    strs.update({"wlan.addr_resolved":"addr_resolv", #Hardware Address (resolved)
                 "wlan.bssid_resolved":"bssid_resolv", #BSS Id (resolved)
                 "wlan.da_resolved":"da_resolv", #Destination Address (resolved)
                 "wlan.ra_resolved":"ra_resolv", #Receiver address (resolved)
                 "wlan.sa_resolved":"sa_resolv", #Source Address (resolved)
                 "wlan.staa_resolved":"staa_resolv", #STA address (resolved)
                "wlan.ta_resolved":"ta_resolv" #Transmitter address (resolved)
                 })
    trees = util.DataFrame.__dict__['trees']+['Compressed BlockAck Response','TKIP parameters','wlan.fc_tree','wlan.qos_tree']
    def doMoarInit(self):
        print(hex(self.fc_type_subtype))
        for i in self.data:
            if i not in self.ints and i not in self.trees and i not in self.strs:
                match i:
                    case 'wlan.addr': #Hardware address (Ethernet or other MAC address)
                        self.addr = self.data[i]
                    case 'wlan.bssid': #BSS Id (MAC)
                        self.bssid = self.data[i]
                    case 'wlan.da': #Destination address (MAC)
                        self.da = self.data[i]
                    case 'wlan.ra': #Receiver address (Ethernet or other MAC address)
                        self.ra = self.data[i]
                    case 'wlan.sa': #Source address (MAC)
                        self.sa = self.data[i]
                    case 'wlan.staa': #STA address (MAC)
                        self.staa = self.data[i]
                    case 'wlan.ta': #Transmitter address (MAC)
                        self.ta = self.data[i]
                    case _:
                        raise Exception("Unknown WLAN key "+ i+ " with value "+str(self.data[i]))
    def doTree(self, tree, treename):
        if treename == "wlan.fc_tree":
            for i in tree:
                match i:
                    case _:
                        print("Unknown key",i,"in wlan.fc_tree with value",tree[i])
        else:
            print("Unknown tree in WLAN")
class XML(util.DataFrame):
    trees = util.DataFrame.trees + ['xml.tag_tree']
    def __init__(self, data, frame):
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            match i:
                case 'xml.doctype': #Doctype
                    self.doctype = self.data[i]
                    print("Doctype: ", self.doctype)
                case 'xml.tag': #Tag
                    self.tag = self.data[i]
                    print("Tag: ",self.tag)
                case 'xml.xmlpi.xml': #XMLPI
                    self.xmlpi_xml = self.data[i]
                    print("XMLPI XML: ",self.xmlpi_xml)
                case 'xml.xmlpi.xml_tree': #???
                    self.doTree(self.data[i], i)
                case _:
                    print("Unknown XML key: ",i)
    def doTree(self, tree, treename):
        global args
        if args.xml:
            print(tree)
            raise Exception("Unimplemented")

layers = {
        '_ws.malformed': util.Malformed,
        'arp': None,
        'data': util.Data,
        'data-text-lines': util.Data,
        'dcerpc': None,
        'dhcp': None,
        'dns': None,
        'eth': Ethernet,
        'gquic': None,
        'http': None,
        'icmp': None,
        'icmpv6': None,
        'igmp': None,
        'imf': IMF,
        'ip': IpV4,
        'ipv6': IpV6,
        'kerberos': util.krbpacket,
        'lldp': None,
        'llmnr': None,
        'mdns': None,
        'mime_multipart': util.MIME,
        'nbns': None,
        'nbss': None,
        'ntp': NTP,
        'quic': None,
        'smb': None,
        'smb2': None,
        'smtp': SMTP,
        'ssdp': None,
        'tcp': None,
        'tcp.segments': None,
        'tls': None,
        'udp': None,
        'wlan': WLAN,
        "xml": XML
        }


if args.activedirectory:
    layers['dcerpc'] = ad.DCERPC
    layers['smb2'] = ad.SMB2
    layers['smb'] = ad.SMB
    layers['nbns'] = resolution.NBNS
    layers['nbss'] = ad.NBSS

if args.arp:
    layers['arp'] = linklayer.ARP

if args.dhcp:
    layers['dhcp'] = resolution.DHCP

if args.dns:
    layers['dns'] = resolution.DNS
    layers['nbns'] = resolution.NBNS

if args.quic:
    layers['gquic'] = transportlayer.GQUIC
    layers['quic'] = transportlayer.QUIC

if args.http:
    layers['http'] = internet.HTTP

if args.icmp:
    layers['icmp'] = internet.ICMP
    layers['icmpv6'] = internet.ICMPV6

if args.igmp:
    layers['igmp'] = internet.IGMP

if args.lldp:
    layers['lldp'] = linklayer.LLDP

if args.llmnr:
    layers['llmnr'] = resolution.LLMNR

if args.mdns:
    layers['mdns'] = resolution.MDNS

if args.ssdp:
    layers['ssdp'] = internet.SSDP

if args.tcp:
    layers['tcp'] = transportlayer.TCP
    layers['tcp.segments'] = transportlayer.TCPSegments

if args.tls:
    layers['tls'] = transportlayer.TLS

if args.udp:
    layers['udp'] = transportlayer.UDP
    udp = {}

class PacketUnit():
    def __init__(self, data):
        self.data = data
        self.layers = data['_source']['layers']

        global layers
        global args
        self.frame = Frame(self.layers['frame'])
        if args.frame: self.frame.doMoarInit()
        for i in self.layers.keys():
            if args.frame: print(i)
            if i == 'frame':
                pass
            elif i in layers and layers[i] != None and not isinstance(self.layers[i], list):
                self.__dict__[i] = layers[i](self.layers[i],self.frame.number)
            elif i in layers and layers[i] != None:
                self.__dict__[i] = [layers[i](j,self.frame.number) for j in self.layers[i]]
            elif i in layers:
                pass
            else:
                print(f"Unknown layer: {i}")
            if i == 'arp' and args.arp:
                self.arp.doMoarInit()
                print(self.arp)
            elif i == 'dhcp' and args.dhcp:
                self.dhcp.doMoarInit()
                print(self.dhcp)
            elif i == 'dns' and args.dns:
                self.dns.doMoarInit()
                print(self.dns)
            
            elif i == 'eth' and args.ethernet:
                self.eth.doMoarInit()
                print(self.eth)
            elif i == 'gquic' and args.quic:
                self.gquic.doMoarInit()
                print(self.gquic)
            elif i == 'quic' and args.quic:
                self.quic.doMoarInit()
                print(self.quic)
            elif i == 'http' and args.http:
                self.http.doMoarInit()
                print(self.http)
            elif i == 'icmp' and args.icmp:
                self.icmp.doMoarInit()
                print(self.icmp)
            elif i == 'icmpv6' and args.icmp:
                self.icmpv6.doMoarInit()
                print(self.icmpv6)
            elif i == 'igmp' and args.igmp:
                self.igmp.doMoarInit()
                print(self.igmp)
            elif i == 'imf' and args.imf:
                self.imf.doMoarInit()
                print(self.imf)
            elif i == 'ip' and (args.ipdata or args.udp):
                self.ip.doMoarInit()
                print(self.ip)
            elif i == 'ipv6' and (args.ipdata or args.udp):
                self.ipv6.doMoarInit()
            elif i == 'kerberos' and args.kerb:
                self.kerberos.doMoarInit()
                print(self.kerberos)
            elif i == 'lldp' and args.lldp:
                self.lldp.doMoarInit()
                print(self.lldp)
            elif i == 'llmnr' and args.llmnr:
                self.llmnr.doMoarInit()
                print(self.llmnr)
            elif i == 'mdns' and args.mdns:
                self.mdns.doMoarInit()
                print(self.mdns)
            elif args.activedirectory:
                if i == 'dcerpc':
                    self.dcerpc.doMoarInit()
                    print(self.dcerpc)
                elif i == 'nbns' and not args.dns:
                    self.nbns.doMoarInit()
                    print(self.nbns)
                elif i == 'nbss':
                    self.nbss.doMoarInit()
                    print(self.nbss)
                elif i == 'ntp':
                    self.ntp.doMoarInit()
                    print(self.ntp)
                elif i == 'smb':
                    self.smb.doMoarInit()
                    print(self.smb)
                elif i == 'smb2':
                    self.smb2.doMoarInit()
                    print(self.smb2)
            elif i == 'nbns' and args.dns:
                self.nbns.doMoarInit()
                print(self.nbns)
            elif i == 'ssdp' and args.ssdp:
                self.ssdp.doMoarInit()
                print(self.ssdp)
            elif (i=='tcp' or i == 'tcp.segments') and args.tcp:
                self.__dict__[i].doMoarInit()
                print(self.__dict__[i])
            elif i=='tls' and args.tls:
                if not isinstance(self.tls, list):
                    self.tls.doMoarInit()
                    print(self.tls)
                else:
                    for j in self.tls:
                        j.doMoarInit()
                        print(j)
            elif i == 'udp' and args.udp:
                self.udp.doMoarInit()
                print(self.udp)
                global udp
                if self.udp.strm not in udp:
                    udp[self.udp.strm] = [self.udp]
                else:
                    udp[self.udp.strm] = udp[self.udp.strm] + [self.udp]
            elif i == 'wlan':
                self.wlan.doMoarInit()
                print(self.wlan)
            if args.checks:
                self.__dict__[i].doCheck()


with open(args.file,"r") as f:
    data = f.read()

js = json.loads(data,object_pairs_hook=util.objectPairs)

packets = [None]
#if args.ctf:
#    packets_to_process = []
#    ptp2 = []
for i in js:
    tmp = PacketUnit(i)
    packets.append(tmp)

#   if args.ctf and 'smtp': 
#        if 'imf' in tmp.__dict__:
#            packets_to_process.append(tmp.smtp.framenum)
#            print(tmp.smtp)
#        if 'smtp' in tmp.__dict__ and tmp.smtp.typ == 'Data':
#            print(tmp.smtp)
#            ptp2.append(tmp.smtp.framenum)

#if args.ctf:
#    passwords = []
#    for i in ptp2:
        #print(packets[i].smtp)
#        if 'Password' in packets[i].smtp.__str__():
#            passwords.append(packets[i].smtp.__str__())
#    print(len(packets_to_process), len(passwords))
    #for j in packets_to_process:
    #    print(packets[j].imf.contents)

