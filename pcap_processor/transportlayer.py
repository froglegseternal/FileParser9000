import util
import tls_helpers.extensions as thelp

class TLSHandshake(util.DataFrame):
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"tls.handshake.cipher_suites_length": ("ciph_suit_len","uint16"), #Cipher Suites Length
                    "tls.handshake.ciphersuite":("ciphsuite","uint16"), #Cipher Suite
                    "tls.handshake.comp_method":("compmeth","uint8"), #Compression Method
                 "tls.handshake.comp_methods_length":("compmeth_len","uint8"), #Compression Methods Length
                 "tls.handshake.extensions_length":("ext_len","uint16"), #Extensions Length
                 "tls.handshake.length":("hs_len","uint24"), #Length
                 "tls.handshake.session_id_length":("sessid_len","uint16"), #Session ID Length
                 "tls.handshake.type":("handtype","uint8"), #Handshake Type
                 "tls.handshake.version":("ver","uint16"), #Version
                 "tls.handshake.ja3":("ja3","str"), #JA3
                 "tls.handshake.ja3_full":("ja3_full","str"), #JA3 Fullstring
                 "tls.handshake.ja3s":("ja3s","str"), #JA3S
                 "tls.handshake.ja3s_full":("ja3s_full","str"), #JA3S Fullstring
                 "tls.handshake.random":("rand","byteseq"), #Random
                 "tls.handshake.session_id":("sessid","byteseq"), #Session ID
                    "TLS Session Ticket":({
                        "tls.handshake.session_ticket":("ticket_bytes","byteseq"), #Session Ticket
                        "tls.handshake.session_ticket_length":("ticket_len","uint16"), #Session Ticket Length
                        "tls.handshake.session_ticket_lifetime_hint":("ticket_lifehint","uint32"), #Session Ticket Lifetime Hint
                        },"tree")
                    })
    trees = util.DataFrame.trees + ["tls.handshake.ciphersuites", #Cipher Suites (Label)
                                    "tls.handshake.comp_methods", #Compression Methods (Label)
                                    "tls.handshake.random_tree", #???
                                    ]
    def __init__(self, data, frame):
        self.ciphsuites = []
        self.exts = {}
        super().__init__(data, frame)
        for i in self.data:
            if i not in self.keyvals:
                if i[0:14] == "tls.handshake.":
                    match i[14:]: #tls.handshake.X
                        case _:
                            print("Unknown key in tls.handshake tree", i)
                else:
                    if "Extension" in i:
                        self.doTree(self.data[i], i, "Extension")
                    else:
                        match i:
                            case _:
                                print("Unknown key in tls.handshake tree", i)

    def doTree(self, tree, treename, treetype=None):
        if treename == 'tls.handshake.ciphersuites':
            for i in tree:
                match i:
                    case 'tls.handshake.ciphersuite': 
                        if isinstance(tree[i], list):
                            for j in tree[i]:
                                self.ciphsuites.append(self.getInt(j))
                        else:
                            self.ciphsuites.append(self.getInt(tree[i]))
                    case _:
                        print("Unknown key in tls.handshakes.ciphersuites tree", i)
        elif treename == 'tls.handshake.comp_methods':
            for i in tree:
                match i:
                    case 'tls.handshake.comp_method': #Compression Method
                        self.compmeth = int(tree[i])
                    case _:
                        print("Unknown key in tls.handshake.comp_methods tree", i)
        elif treename == "tls.handshake.random_tree":
            for i in tree:
                match i:
                    case 'tls.handshake.random': #Random
                        self.random = util.unpackByteSequence(tree[i])
                    case 'tls.handshake.random_bytes': #Random bytes
                        self.randbytes = util.unpackByteSequence(tree[i])
                    case 'tls.handshake.random_time': #GMT Unix Time (Date and Time)
                        self.randtime = tree[i]
                    case _:
                        print("Unknown key in tls.handshake.random_tree", i)
        elif treename == "TLS Session Ticket":
            print(tree)
            raise Exception("LOL")
        elif treetype == "Extension":
            self.exts[treename] = thelp.ext_mapping[self.getInt(tree['tls.handshake.extension.type'])](tree, self.framenum)
        else:
            print("Unknown TLS Handshake tree", treename)

    def __str__(self):
        builder = "-"*30+"TLSHandshake"+"-"*30+"\n"
        try:
            builder += "Message type: "+self.getHandType()+" | Handshake message data length: "+str(self.hs_len) + "\n"
        except:
            builder += "Unreadable, presumably encrypted.\n"
        builder += "\n"
        for i in self.exts:
            builder += "\n" + str(self.exts[i]) + "\n\n"
        return builder

    handtypes = {0: "HelloRequest (0)",
                 1: "ClientHello (1)",
                 2: "ServerHello (2)",
                 4: "NewSessionTicket (4)",
                 8: "EncryptedExtensions (TLS 1.3 only) (8)",
                11: "Certificate (11)",
                 12: "ServerKeyExchange (12)",
                 13: "CertificateRequest (13)",
                 14: "ServerHelloDone (14)",
                 15: "CertificateVerify (15)",
                 16: "ClientKeyExchange (16)",
                 20: "Finished (20)"}
    
    def getHandType(self):
        if self.handtype in self.handtypes:
            return self.handtypes[self.handtype]
        else:
            return "Unknown ("+str(self.handtype)+")"

class TLSRecord(util.DataFrame):
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"tls.app_data":("appdata","byteseq"), #Encrypted Application Data
                     "tls.record.content_type":("conttype","uint8"), #Content Type
                    "tls.record.length":("len","uint16"), #Length
                    "tls.record.opaque_type":("optype","uint8"), #Opaque Type
                    "tls.record.version":("version","uint16"), #Version
                    "tls.app_data_proto":("proto","str"), #Application Data Protocol
                })
    trees = util.DataFrame.trees + ["tls.handshake", #Handshake Protocol
                                    ]
    def __init__(self, data, frame):
        self.handshakes = []
        super().__init__(data, frame)
        if isinstance(self.data, list):
            for i in self.data:
                print(i)
        for i in self.data:
            if i not in self.keyvals:
                match i:
                    case 'tls.alert_message': #Alert Message
                        if isinstance(data[i], str):
                            self.alertmsg = data[i]
                        else:
                            print("Unknown alert message type in TLS",type(data[i]))
                    case 'tls.change_cipher_spec': #Change Cipher Spec Message (Label)
                        print("tls.change_cipher_spec", self.data[i])
                    case _:
                        print("Unknown key in tls.record tree", i)
    def doTree(self, tree, treename):
        if treename == "tls.handshake":
            if not isinstance(tree, list):
                self.handshakes.append(TLSHandshake(tree, self.framenum))
            else:
                for i in tree:
                    self.handshakes.append(TLSHandshake(i, self.framenum))
        else:
            print("Unknown TLS Record tree", treename)

    def __str__(self):
        builder = "-"*40+"TLSRecord"+"-"*40+"\n"
        builder += "Frame number: "+str(self.framenum)+"\n"
        if "conttype" in self.__dict__:
            builder += "Content Type: "+self.getType()
        elif "optype" in self.__dict__:
            builder += "Opaque Type: "+str(self.optype)
        builder += " | Legacy Version: "+self.getVersion()+" ("+str(self.version)+")"
        builder += " | Length: "+str(self.len)+"\n"
        if "conttype" in self.__dict__ and self.getType() == "Handshake (22)":
            for i in self.handshakes:
                try:
                    builder += str(i) + "\n"
                except:
                    print(builder)
                    
                    raise Exception("LOL")
        return builder

    types = {20: "ChangeCipherSpec (20)",
             21: "Alert (21)",
             22: "Handshake (22)",
             23: "Application (23)",
             24: "Heartbeat (24)"}
    def getType(self):
        if self.conttype in self.types:
            return self.types[self.conttype]
        else:
            return "Unknown Content Type ("+str(self.conttype)+")"
   
    versions = {0x300: "SSL 3.0",
               0x301: "TLS 1.0",
               0x302: "TLS 1.1",
               0x303: "TLS 1.2",
               0x304: "TLS 1.3"}
    def getVersion(self):
        if self.version in self.versions:
            return self.versions[self.version]
        else:
            return "Unknown"

class TLS(util.DataFrame): #Transport Layer Security https://en.wikipedia.org/wiki/Transport_Layer_Security
    trees = util.DataFrame.__dict__['trees'] + ['tls.record','tls.handshake']
    def __init__(self, data, frame):
        self.records = []
        self.handshakes = []
        self.exts = {}
        if isinstance(data, list):
            print(data)
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            if i in self.ints or i in self.trees:
                continue
            else:
                match i:
                    case _:
                        print("Unknown TLS key", i)
    
    def doTree(self, tree, treename, treetype=None):
        if treename == 'tls.handshake':
            self.handshakes.append(TLSHandshake(tree, self.framenum))
        elif treename == 'tls.record':
            if isinstance(tree, list):
                for i in tree:
                    self.records.append(TLSRecord(i, self.framenum))
            else:
                self.records.append(TLSRecord(tree, self.framenum))
        elif treetype == "Extension":
            self.exts[treename] = {}
            for i in tree:
                match i:
                    case 'tls.handshake.sig_hash_alg_len':
                        self.exts[treename]["sha_len"] = int(tree[i])
                    case 'tls.handshake.sig_hash_algs':
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown key in tls extension tree", i)
        else:
            print("Unknown TLS tree", treename)

    def __str__(self):
        builder = "-"*50 + "TLS"+"-"*50+"\n"
        for i in self.handshakes:
            builder += str(i) + "\n"
        for i in self.records:
            builder += str(i) + "\n"
        for i in self.exts:
            builder += str(i) + "\n"
        return builder

class QuicFrame(util.DataFrame):
    trees = util.DataFrame.trees + ['tls','quic.crypto.crypto_data']
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"quic.crypto.length":("len","uint64"), #Length
                "quic.crypto.offset":("offset","uint64"), #Offset
                "quic.frame_type":("frametype","uint64"), #Frame Type
                 "quic.padding_length":("padlen","uint32"), #Padding Length
                 })
    def __init__(self, data, frame):
        if isinstance(data, list):
            raise Exception("InvalidTypeException")
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown QuicFrame key", i, "with value", self.data[i])
    def doTree(self, tree, treename):
        if treename == 'tls':
            self.tls = TLS(tree, self.framenum)
            self.tls.doMoarInit()
        elif treename == 'quic.crypto.crypto_data':
            if len(tree) > 0:
                self.crypto_data = tree
            else:
                self.crypto_data = self.tls
        else:
            print("Unknown tree in QuicFrame",treename,"with values",tree.encode())

    def __str__(self):
        builder = "-"*40 + "QuicFrame"+"-"*40+"\n"
        builder += "Frame type: "+self.getType()+"\n"
        if self.frametype == 0:
            builder += "Padding Length: "+str(self.padlen)+"\n"
        elif self.frametype == 6:
            builder += "Offset: "+str(self.offset)+ " | Length: "+str(self.len)+"\n"
            builder += str(self.crypto_data)
        return builder

    types = {0: "PADDING (0)",
             6: "CRYPTO (6)"}
    def getType(self):
        if self.frametype in self.types:
            return self.types[self.frametype]
        else:
            return "Unknown Type ("+str(self.frametype)+")"

class QUIC(util.DataFrame): #https://en.wikipedia.org/wiki/QUIC
    trees = util.DataFrame.trees + ["quic.short", #QUIC Short Header (Label)
                                    "quic.frame", #Frame (Label)
                                    "QUIC Connection information", #???
                                    ]
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"quic.dcid":("dcid","byteseq"), #Destination Connection ID
                     "quic.payload":("payload","byteseq"), #Payload
                    "quic.remaining_payload":("rem_payload","byteseq"), #Remaining payload
                     "quic.scid":("scid","byteseq"), #Source Connection ID
                     'quic.dcil':('dcil',"uint8"), #Destination Connection ID Length
                 'quic.header_form':('header_form',"uint8"), #Header Form
                 'quic.length':('len','uint64'), #Length
                 'quic.long.packet_type':('longpacket_type','uint8'), #Packet Type
                 "quic.long.reserved":("long_reserved",'uint8'), #Reserved
        "quic.packet_length":("packet_length",'uint32'), #Packet Length
                 "quic.packet_number":("packet_number",'uint64'), #Packet Number
                 "quic.packet_number_full":("packet_number_full",'uint64'), #Packet Number (full)
                 "quic.packet_number_length":("packet_number_len",'uint8'), #Packet Number Length
                 "quic.scil":("scil",'uint8'), #Source Connection ID Length
                 "quic.supported_version":("supp_ver",'uint32'), #Supported Version
                 "quic.token_length":("tok_len",'uint64'), #Token Length
                 "quic.version":("version",'uint32'), #Version
                 "quic.vn.unused":("unused",'uint8'), #Unused
                "quic.fixed_bit":("fixed_bit","bool"), #Fixed Bit
                    })
    def __init__(self, data, frame):
        self.frames = []
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            if i not in self.keyvals:
                match i:
                    case _:
                        print("Unknown QUIC key", i.encode(),"with value",self.data[i])
    def doTree(self, tree, treename):
        if treename == "_ws.expert":
            self.expertnumber += 1
            for i in tree:
                if "_ws.expert" in i:
                   self.doProcessExpert(i, tree[i], self.expertnumber) 
                else:
                    match i:
                        case 'quic.decryption_failed': #Failed to decrypt handshake (Label)
                            self.failed_decryption = True
                        case _:
                            print("Unknown quic key in _ws.expert tree with keyname", i,"and value",tree[i])
        elif treename == "QUIC Connection information":
            for i in tree:
                match i:
                    case "quic.connection.number": #Connection Number (uint32)
                        self.conn_number = self.getInt(tree[i])
                    case _:
                        print("Unknown quic key in QUIC Connection information tree with keyname", i)
        elif treename == "quic.short":
            for i in tree:
                match i:
                    case 'quic.dcid': #Destination Connection ID (Byte sequence)
                        tmp = util.unpackByteSequence(tree[i])
                        if "dcid" in self.__dict__ and tmp != self.dcid:
                            raise Exception("Unequal dcid values")
                        else:
                            self.dcid = tmp
                    case 'quic.fixed_bit': #Fixed Bit
                        self.fixed_bit = bool(int(tree[i]))
                    case 'quic.header_form': #Header Form (uint8)
                        self.header_form = self.getInt(tree[i])
                    case 'quic.spin_bit': #Spin Bit
                        self.spin_bit = bool(int(tree[i]))
                    case _:
                        print("Unknown quic key in quic.short tree with keyname", i)
        elif treename == "quic.frame":
            if isinstance(tree, list):
                for i in tree:
                    self.frames.append(QuicFrame(i, self.framenum))
            else:
                self.frames.append(QuicFrame(tree, self.framenum))
        else:
            print("Unknown quic tree", treename, "with values", tree)
    
    def __str__(self):
        builder = "-"*50+"QUIC"+"-"*50+"\n"
        if "header_form" in self.__dict__:
            builder += "Header Form: "+str(self.header_form)+" ("+self.getHeaderForm()+")"
        if "fixed_bit" in self.__dict__:
            builder += " | Fixed bit: "+str(self.fixed_bit)
        if "spin_bit" in self.__dict__:
            builder += " | Spin bit: "+str(self.spin_bit)
        if self.header_form == 1:
            if "longpacket_type" in self.__dict__:
                builder += " | Long Packet Type: ("+self.getLongType()+")\n"
                if self.longpacket_type == 0:
                    builder += "Reserved bits: "+str(self.long_reserved)+" | Packet Number Length: "+str(self.packet_number_len)
                if self.longpacket_type == 2:
                    if "long_reserved" in self.__dict__:
                        builder += "Reserved bits: "+str(self.long_reserved)+" | Packet Number Length: "+str(self.packet_number_len)
                    elif "packet_number_len" in self.__dict__: builder += "Packet Number Length: "+str(self.packet_number_len)
                if self.longpacket_type in (1,3):
                    raise Exception("Unimplemented quic longpacket type "+self.getLongType())
            #Insert packet-type specific stuff here.
            builder += "Version: "+hex(self.version)
            builder += " | DCIL: "+str(self.dcil)
            if self.dcil > 0:
                builder += " | DCID: "+self.dcid.hex()
            builder += " | SCIL: "+str(self.scil)
            if self.scil > 0:
                builder += " | SCID: "+self.scid.hex()
            if "longpacket_type" in self.__dict__:
                if self.longpacket_type == 0:
                    builder += "\nToken Length: "+str(self.tok_len)
                    #insert token logic here
                    builder += "\nLength: "+str(self.len)+" | Packet number: "+str(self.packet_number)+"\n"
                    if "payload" in self.__dict__: builder += str(self.payload)
                    if "rem_payload" in self.__dict__: builder += str(self.rem_payload)
                if self.longpacket_type == 2:
                    if "packet_number" in self.__dict__:
                        builder += "\nLength: "+str(self.len)+" | Packet number: "+str(self.packet_number)+"\n"
                    else:
                        builder += "\nLength: "+str(self.len)+"\n"
                    if "payload" in self.__dict__: builder += str(self.payload)
                    if "rem_payload" in self.__dict__: builder += str(self.rem_payload)
        if "version" in self.__dict__ or "scil" in self.__dict__ or "dcil" in self.__dict__:
            builder += "\n"
        builder += "\n"
        if len(self.frames) > 0:
            for i in self.frames:
                builder += str(i) + "\n"
        return builder

    def getHeaderForm(self):
        if self.header_form == 1:
            return "Long Header"
        elif self.header_form == 0:
            return "Short Header"
        else:
            return "Unknown Header Form"
    
    longtypes = {0: "Initial (0x00)",
                 1: "0-RTT (0x01)",
                 2: "Handshake (0x02)",
                 3: "Retry (0x03)"}

    def getLongType(self):
        if self.longpacket_type in self.longtypes:
            return self.longtypes[self.longpacket_type]
        else:
            return "Invalid Long-Packet Type"

class GQUIC(util.DataFrame):
    def __init__(self, data, frame):
        self.frames = []
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            match i[6:]: #gquic.X
                case 'cid': #CID
                    self.cid = int(self.data[i])
                case 'dcil': #Destination Connection ID Length
                    self.dcil = int(self.data[i])
                case 'frame': #Frame
                    self.doTree(self.data[i],i)
                case 'message_authentication_hash': #Message Authentication Hash
                    self.mah = util.unpackByteSequence(self.data[i])
                case 'packet_number': #Packet Number
                    self.packetnum = int(self.data[i])
                case 'payload': #Payload
                    self.payload = util.unpackByteSequence(self.data[i])
                case 'puflags': #Public Flags
                    self.puflags = int(self.data[i],16)
                case 'puflags_tree': #???
                    self.doTree(self.data[i], i)
                case 'scil': #Source Connection ID Length
                    self.scil = int(self.data[i])
                case 'version': #Version
                    self.version = self.data[i]
                case _:
                    print("Unknown GQUIC key", i)
    def doTree(self, tree, treename):
        if treename == '_ws.expert':
            self.expertnumber+=1
            for i in tree:
                if '_ws.expert' in i:
                    self.doProcessExpert(i, tree[i], self.expertnumber)
                else:
                    match i:
                        case 'gquic.tag.length.truncated':
                            self.taglentrunc = True
                        case _:
                            print("Unknown GQUIC _ws.expert tree key", i)
        elif treename == '_ws.malformed':
            if isinstance(tree, dict):
                for i in tree:
                    if '_ws.malformed' in i:
                        self.doProcessMalformed(i, tree[i])
                    else:
                        match i:
                            case _:
                                print("Unknown GQUIC _ws.malformed tree key", i)
            elif isinstance(tree, str):
                self.malformed = tree
            else:
                print("Unknown structure for _ws.malformed value found in GQUIC packet, type of ", type(tree))
        elif treename == 'gquic.frame':
            if isinstance(tree, list):
                for i in tree:
                    self.frames.append(QuicFrame(i, self.framenum))
            else:
                self.frames.append(QuicFrame(tree, self.framenum))
            """for i in tree:
                match i[6:]: #gquic.X
                    case 'frame_type': #Frame Type
                        self.frametype = int(tree[i],16)
                    case 'frame_type_tree': #???
                        self.doTree(tree[i], 'gquic.frame_type_tree')
                    case 'frame_type.padding': #Padding
                        self.ft_padding = util.unpackByteSequence(tree[i])
                    case 'frame_type.padding.length': #Padding Length
                        self.padlen = int(tree[i])
                    case 'padding': #Padding
                        self.padding = util.unpackByteSequence(tree[i])
                    case 'stream_id': #Stream ID
                        self.streamid = int(tree[i])
                    case 'tag': #Tag
                        self.tag = tree[i]
                    case 'tag_number': #Tag Number
                        self.tagnum = int(tree[i])
                    case 'tags': #Tag/value
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown gquic frame tree key", i)"""
        elif treename == 'gquic.frame_type_tree':
            for i in tree:
                match i[24:]: #gquic.frame_type.stream.X
                    case '': #Stream
                        self.stream = bool(int(tree[i]))
                    case 'd': #Data Length
                        self.datalen = bool(int(tree[i]))
                    case 'f': #FIN
                        self.fin = bool(int(tree[i]))
                    case 'ooo': #Offset Length
                        self.offset_len = int(tree[i])
                    case 'ss': #Stream Length
                        self.stream_len = int(tree[i])
                    case _:
                        print("Unknown gquic frame_type tree key", i)
        elif treename == 'gquic.puflags_tree':
            for i in tree:
                match i[6:]: #gquic.X
                    case 'fixed_bit': #Fixed Bit
                        self.fixbit = bool(int(tree[i]))
                    case 'header_form': #Header form
                        self.headform = bool(int(tree[i]))
                    case 'long.packet_type': #Packet Type
                        self.packtype = int(tree[i])
                    case 'long.reserved': #Reserved
                        self.reserved = int(tree[i])
                    case 'packet_number_length': #Packet Number Length
                        self.packnumlen = int(tree[i])
                    case _:
                        print("Unknown gquic puflags tree key", i)
        elif treename == 'gquic.tag_offset_length_tree':
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.doTree(tree[i], i)
                    case '_ws.malformed':
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown gquic tag_offset_length tree key", i)
        elif treename == 'gquic.tags':
            for i in tree:
                match i[9:]: #gquic.tagX
                    case '.crt': #Certificate chain
                        self.crt = util.unpackByteSequence(tree[i])
                    case '_offset_end': #Tag offset end
                        self.tagoffend = int(tree[i])
                    case '_offset_length': #Tag length
                        self.tagofflen = int(tree[i])
                    case '_offset_length_tree': #???
                        self.doTree(tree[i], i)
                    case '_type': #Tag Type
                        self.tagtype = tree[i]
                    case '_value': #Tag/value
                        self.tagval = util.unpackByteSequence(tree[i])
                    case _:
                        print("Unknown gquic tags tree key", i)
        else:
            print("Unknown gquic tree name", treename)

    def __str__(self):
        builder = "-"*40+"GQUIC"+"-"*40+"\n"
        return builder

tmp = {"tcp.ack":("ack","uint32"), #Acknowledgement number
        "tcp.ack_raw":("ackraw","uint32"), #Acknowledgement number (raw)
        'tcp.analysis':"Specialtree", #SEQ/ACK analysis (Label)
        "tcp.checksum":("check","uint16"), #Checksum
        "tcp.checksum.status":("checkstat","uint8"), #Checksum status
        'tcp.completeness':("completeness","uint8"), #Conversation completeness
        'tcp.dstport':("dstport","uint16"), #Destination port
        "tcp.flags": ("flags","uint16"), #Flags
        "tcp.flags_tree":"Specialtree",
        'tcp.hdr_len':("hdr_len","uint8"), #Header Length
        'tcp.len':("len","uint32"), #TCP Segment Len
        'tcp.nxtseq':("nxtseq","uint32"), #Next Sequence Number
        'tcp.options': ("opt","byteseq"), #TCP Options
        'tcp.options_tree':"Specialtree",
        'tcp.payload': ("payload","byteseq"), #TCP payload
        'tcp.pdu.size': ("PDU_size","uint32"), #PDU Size
        'tcp.port':("port","uint16"), #Source or Destination Port
        'tcp.reassembled.data': ("realdata","byteseq"), #Reassembled TCP Data 
        'tcp.reassembled.length':("reasslen","uint32"), #Reassembled TCP length
        'tcp.reassembled_in':('reassref','framenum'), #Reassembled PDU in frame
        'tcp.segment': ('segment','framenum'), #TCP Segment
        'tcp.segment.count':("segcount","uint32"), #Segment count
        'tcp.segment_data': ("segdata","byteseq"), #TCP segment data
        'tcp.seq':("seqnum","uint32"), #Sequence Number
        'tcp.seq_raw':("seqnumraw","uint32"), #Sequence Number (raw)
        'tcp.srcport':("srcport","uint16"), #Source Port
        'tcp.stream':("strmind","uint32"), #Stream index
        'tcp.urgent_pointer':("urgpoint","uint16"), #Urgent Pointer
        'tcp.window_size':("windsize","uint32"), #Calculated window size
        'tcp.window_size_scalefactor':("windsizescale","uint32"), #Window size scaling factor
        'tcp.window_size_value':("wind","uint16"), #Window 
            }
class TCP(util.DataFrame, keyvals=tmp): #Transmission Control Protocol
    typ = "TCP"
    def doMoarInit(self):
        if 'type' not in self.__dict__:
            self.type = "EST?"
    def __str__(self): # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
        builder = '-'*50+'TCP'+'-'*50+'\n'
        builder += " "*10 + "HEADER"+"\n"
        builder += "Frame number: "+str(self.framenum)+"\n"
        builder += "Source Port: "+str(self.srcport)+" | Destination Port: "+ str(self.dstport)
        builder += " | Type: "+str(self.type)+'\n'
        builder += "Sequence Number: "+str(self.seqnum)+ " | Acknowledgement Number: "+str(self.ack)+"\n"
        builder += "Data Offset: "+str(self.hdr_len)+" | Flags - CWR:" 
        if self.flags_cwr: builder += "Y"
        else: builder += "N"
        builder += ", ECE:"
        if self.flags_ece: builder += "Y"
        else: builder += "N"
        builder += ", URG:"
        if self.flags_urg: builder += "Y"
        else: builder += "N"
        builder += ", ACK:"
        if self.flags_ack: builder += "Y"
        else: builder += "N"
        builder += ", PSH:"
        if self.flags_push: builder += "Y"
        else: builder += "N"
        builder += ", RST:"
        if self.flags_reset: builder += "Y"
        else: builder += "N"
        builder += ", SYN:"
        if self.flags_syn: builder += "Y"
        else: builder += "N"
        builder += ", FIN:"
        if self.flags_fin: builder += "Y"
        else: builder += "N"
        builder += " | Window size (calculated by wireshark): " + str(self.windsize)+ "\n"
        builder += "Checksum: " + str(self.check) + " (Status: "+str(self.checkstat)+")" + " | Urgent Pointer: " + str(self.urgpoint)+ "\n"
        if self.hdr_len > 20:
            builder += str(self.opt)+"\n"
        if "payload" in self.__dict__:
            builder += " "*10 + "DATA"+"\n"
            builder += str(self.payload)
        return builder
    
    def doTree(self, tree, treename):
        if treename == '_ws.expert':
            self.expertnumber += 1
            for i in tree:
                if "_ws.expert" in i:
                    self.doProcessExpert(i, tree[i], self.expertnumber)
                    continue
                match i:
                    case 'tcp.connection.fin': #Connection finish (FIN) (Label)
                        self.type = "FIN"
                    case 'tcp.connection.fin_active': #This frame initiates the connection closing
                        self.fintype = 'ACTIVE'
                    case 'tcp.connection.fin_passive': #This frame undergoes the connection closing
                        self.fintype = 'PASSIVE'
                    case 'tcp.connection.rst': #Connection reset (RST) (Label)
                        self.type = "RST"
                    case 'tcp.connection.syn': #Connection establish request (SYN) (Label)
                        self.type = "SYN"
                    case 'tcp.connection.synack': #Connection establish acknowledge (SYN+ACK) (Label)
                        self.type = "SYNACK"
                    case _:
                        print("Unknown key in tcp expert key",i,"packet proto is TCP, value is",tree[i])
        elif treename == 'tcp.analysis': #SEQ/ACK analysis (Label)
            for i in tree:
                match i[13:]: #tcp.analysis.X
                    case 'ack_rtt': #The RTT to ACK the segment was (Time offset)
                        self.ack_rtt = tree[i]
                    case 'acks_frame': #This is an ACK to the segment in frame X (Frame number)
                        self.ackref = int(tree[i])
                    case 'bytes_in_flight': #Bytes in flight (uint32)
                        self.bytesinfly = int(tree[i])
                    case 'duplicate_ack_frame': #Duplicate to the ACK in frame X (Frame number)
                        self.dupackref = int(tree[i])
                    case 'duplicate_ack_frame_tree': #???
                        self.doTree(tree[i], i)
                    case 'duplicate_ack_num': #Duplicate ACK # (uint32)
                        self.dupacknum = int(tree[i])
                    case 'flags': #TCP Analysis Flags (Label)
                        self.doTree(tree[i], i) 
                    case 'initial_rtt': #iRTT (Time offset)
                        self.irtt = tree[i]
                    case 'push_bytes_sent': #Bytes sent since last PSH flag (uint32)
                        self.pushbytes = int(tree[i])
                    case _:
                        print("Unknown key in tcp.analysis tree", i)
        elif treename == 'tcp.analysis.duplicate_ack_frame_tree':
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown key in tcp.analysis.duplicate_ack_frame_tree",i)
        elif treename == 'tcp.analysis.flags': #TCP Analysis Flags (Label)
            for i in tree:
                if i[0:13] == 'tcp.analysis.':
                    match i[13:]: #tcp.analysis.X
                        case 'duplicate_ack': #Duplicate ACK #Label)
                            print('duplicate_ack',tree[i])
                        case _:
                            print("Unknown key in tcp.analysis.flags tree", i)
                else:
                    match i:
                        case '_ws.expert':
                            self.doTree(tree[i],i)
                        case _:
                            print("Unknown key in tcp.analysis.flags tree", i)
        elif treename == 'tcp.flags.fin_tree' or treename == 'tcp.flags.reset_tree' or treename == 'tcp.flags.str_tree' or treename == 'tcp.flags.syn_tree':
            for i in tree:
                match i:
                    case '_ws.expert':
                        self.doTree(tree[i], i)
                    case _:
                        print(f"Unknown key in {treename} tree", i)
        elif treename == 'tcp.flags_tree':
            for i in tree:
                if i[0:10] == 'tcp.flags.':
                    match i[10:]: #tcp.flags.X
                        case 'ack': #Acknowledgement (Boolean)
                            self.flags_ack = bool(int(tree[i]))
                        case 'ae': #Accurate ECN (Boolean)
                            self.flags_ae = bool(int(tree[i]))
                        case 'cwr': #Congestion Window Reduced (Boolean)
                            self.flags_cwr = bool(int(tree[i]))
                        case 'ece': #ECN-Echo (Boolean)
                            self.flags_ece = bool(int(tree[i]))
                        case 'fin': #Fin (Boolean)
                            self.flags_fin = bool(int(tree[i]))
                        case 'fin_tree': #???
                            self.doTree(tree[i], i)
                        case 'push': #Push (Boolean)
                            self.flags_push = bool(int(tree[i]))
                        case 'res': #Reserved (Boolean)
                            self.flags_res = bool(int(tree[i]))
                        case 'reset': #Reset (Boolean)
                            self.flags_reset = bool(int(tree[i]))
                        case 'reset_tree': #???
                            self.doTree(tree[i], i)
                        case 'str': #TCP Flags (Character string)
                            self.flags_str = tree[i]
                        case 'str_tree': #???
                            self.doTree(tree[i], i)
                        case 'syn': #Syn   (Boolean)
                            self.flags_syn = bool(int(tree[i]))
                        case 'syn_tree': #???
                            self.doTree(tree[i], i)
                        case 'urg': #Urgent (Boolean)
                            self.flags_urg = bool(int(tree[i]))
                        case _:
                            print("Unknown key in tcp.flags_tree tree", i)
                else:
                    match i:
                        case _:
                            print("Unknown key in tcp.flags_tree tree", i)
        elif treename == 'tcp.options_tree':
            for i in tree:
                match i[12:]: #tcp.options.X
                    case 'mss': #TCP MSS Option
                        self.opt_mss = util.unpackByteSequence(tree[i])
                    case 'mss_tree': #???
                        self.doTree(tree[i], i)
                    case 'nop': #???
                        try: self.opt_nop = int(tree[i])
                        except: self.opt_nop = tree[i]
                    case 'nop_tree': #???
                        self.doTree(tree[i], i)
                    case 'sack_perm': #TCP SACK Permitted Option
                        self.sack_perm = util.unpackByteSequence(tree[i])
                    case 'sack_perm_tree': #???
                        self.doTree(tree[i], i)
                    case 'time_stamp': #TCP Time Stamp Option
                        self.timestampYN = bool(int(tree[i]))
                    case 'timestamp': #???
                        self.timestamp = util.unpackByteSequence(tree[i])
                    case 'timestamp_tree': #???
                        self.doTree(tree[i], i)
                    case 'wscale': #TCP Window Scale Option
                        self.wscale = util.unpackByteSequence(tree[i])
                    case 'wscale_tree': #???
                        self.doTree(tree[i], i)
                    case _:
                        print("Unknown key in tcp.options_tree tree", i)
        elif treename == 'tcp.options.mss_tree':
            for i in tree:
                match i[10:]: #tcp.optionX
                    case '_kind': #Kind
                        self.mss_kind = int(tree[i])
                    case '_len': #Length
                        self.mss_len = int(tree[i])
                    case 's.mss_val':
                        self.mss_val = int(tree[i])
                    case _:
                        print("Unknown key in tcp.options.mss_tree tree", i)
        elif treename == 'tcp.options.nop_tree':
            for i in tree:
                try:
                    match i[10:]: #tcp.optionX
                        case '_kind': #Kind
                            self.nop_kind = int(tree[i])
                        case _:
                            print("Unknown key in tcp.options.nop_tree tree", i)
                except:
                    self.nop_kinds = tree
        elif treename == 'tcp.options.sack_perm_tree':
            for i in tree:
                match i[10:]: #tcp.optionX
                    case '_kind': #Kind
                        self.sackperm_kind = int(tree[i])
                    case '_len': #Length
                        self.sackperm_len = int(tree[i])
                    case _:
                        print("Unknown key in tcp.options.sack_perm_tree tree", i)
        elif treename == 'tcp.options.timestamp_tree':
            for i in tree:
                match i[10:]: #tcp.optionX
                    case '_kind': #Kind
                        self.timestamp_kind = int(tree[i])
                    case '_len': #Length
                        self.timestamp_len = int(tree[i])
                    case 's.timestamp.tsecr': #Timestamp echo reply
                        self.timestamp_ereply = int(tree[i])
                    case 's.timestamp.tsval': #Timestamp value
                        self.timestamp_val = int(tree[i])
                    case _:
                        print("Unknown key in tcp.options.timestamp_tree tree", i)
        elif treename == 'tcp.options.wscale_tree':
            for i in tree:
                match i[10:]: #tcp.optionX
                    case '_kind': #Kind
                        self.wscale_kind = int(tree[i])
                    case '_len': #Length
                        self.wscale_len = int(tree[i])
                    case 's.wscale.multiplier': #Multiplier
                        self.wscale_mult = int(tree[i])
                    case 's.wscale.shift': #Shift count
                        self.wscale_shift = int(tree[i])
                    case _:
                        print("Unknown key in tcp.options.wscale_tree tree", i)
        elif treename == 'Timestamps':
            for i in tree:
                match i:
                    case 'tcp.time_delta': #Time since previous frame in this TCP stream
                        self.timedelt = tree[i]
                    case 'tcp.time_relative': #Time since first frame in this TCP stream
                        self.timerel = tree[i]
                    case _:
                        print("Unknown TCP key in Timestamps  tree", i)
        else:
            raise Exception(f"Unknown TCP tree {treename}")

class TCPSegments(TCP):
    typ = "TCPSegments" 
    def doMoarInit(self):
        for i in self.data:
            match i:
                case 'tcp.reassembled.data': #Byte sequence
                    pass
                case 'tcp.reassembled.length': #uint32
                    print("tcp.reassembled.length",self.data[i])
                case 'tcp.segment': #Frame number
                    print("tcp.segment",self.data[i])
                case 'tcp.segment.count': #uint32
                    print("tcp.segment.count",self.data[i])
                case _:
                    print("Unknown TCPSegment key", i)
    def __str__(self):
        builder = '-'*40+'TCPSegment'+'-'*40
        builder += super().__str__()
        return builder

class UDP(util.DataFrame): #User Datagram Protocol
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"udp.checksum":("checksum","uint16"), #Checksum
                    "udp.checksum.status":("checkstat","uint8"), #Checksum status
                    "udp.dstport":("dstport","uint16"), #Destination port
                    "udp.length":("len","uint16"), #Length
                    "udp.payload":("payload","byteseq"), #Payload
                    "udp.port":("port","uint16"), #Source or Destination Port
                    "udp.srcport":("srcport","uint16"), #Source Port
                    "udp.stream":("strm","uint32"), #Stream index
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
    def doMoarInit(self):
        for i in self.data:
            if i in self.keyvals:
                continue
            if i[0:4] == 'udp.':
                match i[4:]: #udp.X
                    case _:
                        print("Unknown private UDP key", i)
            else:
                match i:
                    case _:
                        print("Unknown UDP key",i)
    def __repr__(self):
        try:
            return self.payload.decode('utf8')
        except:
            return str(self.payload)
    def __str__(self):
        builder = "-"*40+"UDP"+"-"*40+"\n"
        builder += "Source port: "+str(self.srcport)+" | Destination port: " + str(self.dstport)+"\n"
        builder += "Length: "+str(self.len)+" | Checksum: "+ str(self.checksum)+" (Status: "+str(self.checkstat)+")\n"
        builder += "Data: "+str(self.payload)
        return builder

    def doTree(self, tree, treename):
        if treename == 'Timestamps':
            for i in tree:
                match i[9:]: #udp.time_X
                    case 'delta': #Time since previous frame
                        self.timedelta = tree[i]
                    case 'relative': #Time since first frame
                        self.timerel = tree[i]
                    case _:
                        print("Unknown UDP timestamps tree key", i)

