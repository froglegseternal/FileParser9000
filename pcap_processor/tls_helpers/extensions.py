import util

class GenericExtension(util.DataFrame):
    keyvals = util.DataFrame.keyvals.copy()
    keyvals.update({"tls.handshake.extension.len":("len","uint16"), #Length
                "tls.handshake.extension.type":("type","uint16"), #Type 
                    "tls.handshake.extension.data":("actual_data","byteseq"), #Data
                 })
    def __init__(self, data, frame):
        super().__init__(data, frame)
    def __str__(self):
        builder = "\033[32m "+"-"*15+self.typ+"-"*15+" \033[00m \n"
        builder += "Data Length: "+str(self.len)+"\n"
        if "actual_data" in self.__dict__ and self.len > 0:
            builder += "First ten chars of data: "+str(self.actual_data[0:11])+"\n"
        return builder

class ServerNameExtension(GenericExtension): #server_name
    keyvals = GenericExtension.keyvals.copy()
    keyvals["Server Name Indication extension"] = ({"tls.handshake.extensions_server_name":("servername","str"), #Server Name
                  "tls.handshake.extensions_server_name_len":("sn_len","uint16"), #Server Name Length
                 "tls.handshake.extensions_server_name_list_len":("list_len","uint16"), #Server Name list length
                 "tls.handshake.extensions_server_name_type":("nametype","uint8"), #Server Name Type
                  },"tree")
    typ = "server_name"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
               continue 
            match i:
                case _:
                    raise Exception("Unknown ServerNameExtension key "+str(i)+" with value "+str(self.data[i]))
    def doTree(self, tree, treename):
        if treename == "Server Name Indication extension":
            for i in tree:
                if i in self.keyvals[treename][0].keys():
                    continue
                match i:
                    case _:
                        raise Exception("Unknown SNI key in tree, key is "+str(i))
        else:
            raise Exception("Unknown treename in SNI Extension with name "+str(treename))
    def __str__(self):
        builder = super().__str__()
        try: builder += "Server Name: "+self.servername
        except: 
            print(self.data)
            if self.len > 0:
                raise Exception("Unexpected nonpresence of an expected value")
        return builder

class StatusReqExt(GenericExtension): #status_request (5)
    typ = "status_request"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions_status_request_exts_len":("sre_len","uint16"), #Request Extensions Length
                 "tls.handshake.extensions_status_request_len":("stat_len","uint16"), #Certificate Status Length
                 "tls.handshake.extensions_status_request_list_len":("list_len","uint16"), #Certificate Status List Length
                 "tls.handshake.extensions_status_request_responder_ids_len":("resp_ids_len","uint16"), #Responder ID list Length
                 "tls.handshake.extensions_status_request_type":("certtype","uint8"), #Certificate Status Type)
                 })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    raise Exception("Unknown status_request key "+str(i))

    def __str__(self):
        builder = super().__str__()
        try:
            builder += "CertificateStatusType: "+str(self.certtype)+"\n"
            builder += "ResponderID list length: "+str(self.resp_ids_len)+"\n"
            builder += "RequestExtensions list length: "+str(self.sre_len)+"\n"
            try: builder += "CertificateStatusLength: "+str(self.stat_len)+"\n"
            except: pass
            try: builder += "CertificateStatusLListLength: "+str(self.list_len)+"\n"
            except: pass
        except:
            if self.len > 0:
                raise Exception("Unexpected presence of expected values")
        return builder

class SuppGroup(GenericExtension): #helper class for SuppGroupsExtension
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions_supported_group":("group","uint16"), #Supported Group
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    raise Exception("Unknown SuppGroup key "+str(i))
    curve_dict = {23: "secp256r1",
                  24: "secp384r1",
                  25: "secp521r1",
                  29: "x25519",
                  30: "x448"}
    def getGroup(self):
        if self.group >=1 and self.group <= 22:
            return "Deprecated curve"
        elif self.group in self.curve_dict:
            return self.curve_dict[self.group]
        elif self.group >> 8 == 0xFE:
            return "Reserved curve"
        

class SuppGroupsExtension(GenericExtension): #supported_groups (10)
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions_supported_groups_length":("list_len","uint16"), #Supported Groups List Length
                 })
    trees = GenericExtension.trees + ["tls.handshake.extensions_supported_groups", #Supported Groups List (Label)
                                      ]
    typ = "supported_groups"
    def __init__(self, data, frame):
        self.supp_groups = []
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    raise Exception("Unknown Supported Groups Extension key "+str(i))

    def doTree(self, tree, treename):
        if treename == "tls.handshake.extensions_supported_groups":
            self.supp_groups.append(SuppGroup(tree, self.framenum))

class EcPointExtension(GenericExtension): #ec_point_formats
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions_ec_point_formats_length":("list_len","uint8"), #EC point formats Length
                 })
    trees = GenericExtension.trees + ["tls.handshake.extensions_ec_point_formats"]
    typ = "ec_point_formats"
    def __init__(self, data, frame):
        self.formats = []
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    raise Exception("Unknown ec_point_formats key "+str(i)+" with value "+str(self.data[i]))
    def doTree(self, tree, treename):
        if treename == "tls.handshake.extensions_ec_point_formats":
            for i in tree:
                match i:
                    case "tls.handshake.extensions_ec_point_format":
                        if isinstance(tree[i], list):
                            for j in tree[i]:
                                self.formats.append(self.getInt(j))
                        else:
                            self.formats.append(self.getInt(tree[i]))
                    case _:
                        raise Exception(f"Unknown key in {treename} with keyval {i}")
        else:
            raise Exception(f"Unknown tree in {self.typ} with name {treename}")

class SigAlgsExt(GenericExtension): #signature_algorithms
    typ = "signature_algorithms"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.sig_hash_alg":("sha_alg","uint16"), #Signature Algorithm
                    "tls.handshake.sig_hash_alg_len":("sha_len","uint16"), #Signature Hash Algorithms Length
                    "tls.handshake.sig_hash_algs":({
                        "tls.handshake.sig_hash_alg":("sha_alg2","uint16"),
                        "tls.handshake.sig_hash_alg_tree":({},"Specialtree")
                        },"tree"), #Signature Algorithms
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown SigAlgsExt key", i)

    def __str__(self):
        builder = super().__str__()
        try: builder += "sha_alg: "+str(self.sha_alg)+"\n"
        except: pass
        builder += "sha_len: "+str(self.sha_len)+"\n"
        builder += "sha_alg2: "+str(self.sha_alg2)+"\n"
        builder += "shas: "+str(self.shas)+"\n"
        return builder

    def doTree(self, tree, treename):
        if treename == "tls.handshake.sig_hash_algs":
            self.shas = tree
        else:
            raise Exception(f"Unknown treename {treename}")

class AppLayerProtoNego(GenericExtension): #application_layer_protcol_negotiation
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions_alpn_len":("list_len","uint8"), #ALPN Extension Length
                 })
    typ = "application_layer_protocol_negotiation"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown AppLayerProtoNego key", i)

class SigCertTime(GenericExtension): #signed_certificate_timestamp
    typ = "signed_certificate_timestamp"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown SigCertTime key", i)

class Padding(GenericExtension): #padding
    typ = "padding"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown padding key", i)


class ETMExtension(GenericExtension):
    typ = "encrypt_then_mac"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown ETM key", i)

class EMSExtension(GenericExtension): #extended_master_secret
    typ = "extended_master_secret"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown Extended Master-Secret key", i)

class TokenBinding(GenericExtension):
    typ = "token_binding"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown token_binding key", i)

class CompCert(GenericExtension): #compress_certificate
    typ = "compress_certificate"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.compress_certificate.algorithm":("alg","uint16"), #Algorithm
                "tls.compress_certificate.algorithms_length":("alg_len","uint8")
                 })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown CompCert key", i)



class SessionTicketExtension(GenericExtension): #session_ticket
    typ = "session_ticket"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown session_ticket key", i)

class PSKExt(GenericExtension):
    typ = "pre_shared_key"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown pre_shared_key key", i)

class SuppVersions(GenericExtension): #supported_versions
    typ = "supported_versions"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.handshake.extensions.supported_version":("vers","uint16"), #Supported Version
                    "tls.handshake.extensions.supported_versions_len":("supplen","uint8"), #Supported Versions length
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                if i == "tls.handshake.extensions.supported_versions_len":
                    self.supplen = self.supplen // 2
                continue
            match i:
                case _:
                    print("Unknown SuppVersions key", i)
    
    def __str__(self):
        builder = super().__str__()
        try: builder += "Length: "+str(self.supplen)+"\n"
        except: builder += "Length: "+str(self.len// 2)+"\n"
        if isinstance(self.vers, int):
            builder += "Supported Version: "+self.getVersion(self.vers)+"\n"
        elif self.supplen < 0:
            raise Exception("A length value should never be less than zero. Maybe check type conversions?")
        elif self.supplen == 0:
            pass
        elif self.supplen >= 2:
            builder += "Supported Versions: "
            for i in range(self.supplen):
                builder += self.getVersion(self.vers[i])
                if i+1 < self.supplen:
                    builder += ", "
        return builder

    versions = {0x300: "SSL 3.0",
               0x301: "TLS 1.0",
               0x302: "TLS 1.1",
               0x303: "TLS 1.2",
               0x304: "TLS 1.3"}
    def getVersion(self, vers):
        if vers in self.versions:
            return self.versions[vers]
        else:
            return "Unknown ("+hex(vers)+")"


class PSKModes(GenericExtension): #psk_key_exchange_modes
    typ = "psk_key_exchange_modes"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"tls.extension.psk_ke_mode":("ke_mode","uint8"), #PSK Key Exchange Mode
                    "tls.extension.psk_ke_modes_length":("ke_len","uint8"), #PSK Key Exchange Modes Length
                    })
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown PSKModes key", i)
    def __str__(self):
        builder = super().__str__()
        builder += "PSK Key Exchange Modes Length: "+str(self.ke_len)+"\n"
        if self.ke_len < 0:
            raise Exception("Invalid value")
        elif self.ke_len == 0:
            raise Exception("Unimplemented")
        elif self.ke_len == 1:
            builder += "PSK Key Exchange Mode: "+str(self.ke_mode)+"\n"
        elif self.ke_len > 1:
            raise Exception("Unimplemented")
        return builder


class KeyShare(GenericExtension): #key_share
    typ = "key_share"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"Key Share extension":({
        "tls.handshake.extensions_key_share_client_length":("client_len","uint16"), #Client Key Share Length
        },"tree")})
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown KeyShare key", i)

class GREASEExtension(GenericExtension):
    typ = "GREASE"
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown GREASE key", i)
    def __str__(self):
        builder = super().__str__()
        builder += str(self.actual_data)
        return builder

class RenegoExtension(GenericExtension): #renegotation_info
    typ = "renegotiation_info"
    keyvals = GenericExtension.keyvals.copy()
    keyvals.update({"Renegotiation Info extension":({
        "tls.handshake.extensions_reneg_info":("reneg_info_bytes", "byteseq"),
        "tls.handshake.extensions_reneg_info_len":("renego_len","uint8")
        },"tree")})
    def __init__(self, data, frame):
        super().__init__(data, frame)
        for i in self.data:
            if i in self.keyvals:
                continue
            match i:
                case _:
                    print("Unknown RenegotiationExtension key", i)
    def __str__(self):
        builder = super().__str__()
        builder += "Length: "+str(self.renego_len)+"\n"
        try:
            builder += "Data: "+str(self.reneg_info_bytes)+"\n"
        except:
            assert self.renego_len == 0, "There is data but wireshark didn't report it back."
            builder += "Data: None or unreadable."
        return builder

#https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
ext_mapping = {0: ServerNameExtension,
               5: StatusReqExt,
               10: SuppGroupsExtension,
               11: EcPointExtension,
               13: SigAlgsExt,
               16: AppLayerProtoNego,
               18: SigCertTime,
               21: Padding,
               22: ETMExtension,
               23: EMSExtension,
               24:TokenBinding,
               27: CompCert,
               35: SessionTicketExtension,
               41: PSKExt,
               43: SuppVersions,
               45: PSKModes,
               51: KeyShare,
               2570: GREASEExtension,
               6682: GREASEExtension,
               10794: GREASEExtension,
               14906: GREASEExtension,
               19018: GREASEExtension,
               23130: GREASEExtension,
               27242: GREASEExtension,
               31354: GREASEExtension,
               35466: GREASEExtension,
               39578: GREASEExtension,
               43690: GREASEExtension,
               47802: GREASEExtension,
               51914: GREASEExtension,
               56026: GREASEExtension,
               60138: GREASEExtension,
               64250: GREASEExtension,
               65281: RenegoExtension}
