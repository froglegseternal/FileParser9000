import util

class ARP(util.DataFrame): #Address Resolution Protocol
    ints = util.DataFrame.__dict__['ints'].copy()
    ints.update({"arp.proto.type":"prototype" #Protocol type
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            if i in self.ints or i in self.trees:
                continue
            match i:
                case 'arp.dst.hw_mac': #Target MAC Address
                    self.target_mac = self.data[i]
                case 'arp.dst.proto_ipv4': #Target IP Address
                    self.targetip = self.data[i]
                case 'arp.hw.size': #Hardware size
                    self.hwsize = int(self.data[i])
                case 'arp.hw.type': #Hardware type
                    self.hwtype = int(self.data[i])
                case 'arp.opcode': #Opcode
                    self.opcode = int(self.data[i])
                case 'arp.proto.size': #Protocol size
                    self.protosize = int(self.data[i])
                case 'arp.src.hw_mac': #Sender MAC Address
                    self.src_mac = self.data[i]
                case 'arp.src.proto_ipv4': #Sender IP Address
                    self.srcip = self.data[i]
                case _:
                    print("Unknown ARP Key", i)
    def __str__(self): # https://en.wikipedia.org/wiki/Address_Resolution_Protocol
        builder = '-'*40+"ARP"+"-"*40+"\n"
        builder += "Hardware Type: "+self.getHWType()
        try: builder += " | Protocol Type: "+self.getProtoType()
        except:
            print(self.data)
            raise Exception("LOL")
        builder += " | Hardware Length: "+str(self.hwsize)
        builder += " | Protocol Length: "+str(self.protosize) + "\n"
        builder += "Operation: "+self.getOp()
        builder += " | Sender Hardware Address: "+self.src_mac+ " | Sender IP Address: "+self.srcip + "\n"
        builder += "Target Hardware Address: "+self.target_mac+" | Target IP Address: "+self.targetip + "\n"
        return builder
    def getOp(self):
        match self.opcode:
            case 1:
                return "Request"
            case 2:
                return "Reply"
            case _:
                raise Exception("Invalid ARP OPCODE Exception "+str(self.opcode))
    def getHWType(self):
        match self.hwtype:
            case 1:
                return "Ethernet"
            case _:
                raise Exception("Invalid ARP Hardware Type Exception "+str(self.hwtype))
    def getProtoType(self):
        match self.prototype:
            case 0x800:
                return "IPv4"
            case _:
                raise Exception(f"Invalid ARP Protocol Type Exception {self.prototype}")

class LLDP(util.DataFrame): #Link Layer Discovery Protocol
    def doMoarInit(self):
        for i in self.data:
            match i:
                case _:
                    print("Unknown LLDP key", i)
    def __str__(self):
        return str(self.data)
