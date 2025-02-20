# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://refspecs.linuxbase.org/elf/elf.pdf
# https://refspecs.linuxfoundation.org/elf/TIS1.1.pdf
import struct
import argparse
import warnings

osabis = {0: "System V", 1: "HP-UX", 2:"NetBSD", 3:"Linux", 4:"GNU Hurd", 6: "Solaris", 7: "AIX (Monterey)", 8:  "IRIX", 9:"FreeBSD", 10:"Tru64", 11: "Novell Modesto", 12:"OpenBSD", 13: "OpenVMS", 14: "NonStop Kernel", 15: "AROS", 16: "FenixOS", 17: "Nuxi CloudABI", 18: "Stratus Technologies OpenVOS"}
etypes = {0: "ET_NONE", 1:"ET_REL", 2:"ET_EXEC", 3:"ET_DYN", 4:"ET_CORE"}
machines = {0:"No machine", 0x1: "AT&T WE 32100", 2: "SPARC", 3: "Intel Architecture", 4: "Motorola 68000", 5: "Motorola 88000", 7: "Intel 80860", 8: "MIPS RS3000 Big-Endian", 10: "MIPS RS4000 Big-Endian",  0x3E: "AMD x86-64"} #There are a lot more types than this (see wikipedia) but I was too lazy to put them in right now.
ptypes = {0: "PT_NULL", 1: "PT_LOAD",2:"PT_DYNAMIC", 3:"PT_INTERP", 4:"PT_NOTE", 5: "PT_SHLIB", 6:"PT_PHDR", 7:"PT_TLS"}

def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0] # https://stackoverflow.com/questions/27506474/how-to-byte-swap-a-32-bit-integer-in-python
def swap64(i):
    return struct.unpack("<Q", struct.pack(">Q", i))[0]
def getAdd(add, endi="big-endian"):
    if len(add) == 4:
        if endi == "little-endian":
            return hex(swap32(add))
        elif endi == "big-endian":
            return hex(add)
    elif len(add) == 8:
        if endi == "little-endian":
            return hex(swap64(add))
        elif endi == "big-endian":
            return hex(add)
class FileHeader():
    EI_MAG, EI_CLASS, EI_DATA = None, None, None
    def __init__(self):
        pass
    def otherInit(self, data, doCheck = 0):
        self.EI_VERSION = data[0x6-0x6]
        self.EI_OSABI = data[0x7-0x6]
        self.EI_ABIVERSION = data[0x8-0x6]
        self.EI_PAD = data[0x9-0x6:0x10-0x6]
        endi = self._getEnd()
        biglil = self._getClass()
        self.e_type = struct.unpack(endi + "H", data[0x10-0x6:0x12-0x6])[0]
        self.e_machine = struct.unpack(endi + "H", data[0x12-0x6:0x14-0x6])[0]
        self.e_version = struct.unpack(endi + "I", data[0x14-0x6:0x18-0x6])[0]
        if biglil == 64:
            self.e_entry = struct.unpack(endi + "Q", data[0x18-0x6:0x20-0x6])[0]
            self.e_phoff = struct.unpack(endi + "Q", data[0x20-0x6:0x28-0x6])[0]
            self.e_shoff = struct.unpack(endi + "Q", data[34:42])[0]
            nadd = 42
        else: #Should only flag for 32-bit but is to keep python from yelling at me about the use of nadd outside of the if-else statements.
            self.e_entry = struct.unpack(endi + "I", data[0x18-0x6:0x1c-0x6])[0]
            self.e_phoff = struct.unpack(endi + "I", data[0x1c-0x6:0x20-0x6])[0]
            self.e_shoff = struct.unpack(endi + "I", data[26:30])[0]
            nadd = 30
        self.e_flags = struct.unpack(endi+"I", data[nadd:nadd+4])[0]
        self.e_ehsize = struct.unpack(endi+"H",data[nadd+4:nadd+6])[0]
        self.e_phentsize = struct.unpack(endi + "H", data[nadd+6:nadd+8])[0]
        self.e_phnum = struct.unpack(endi+"H", data[nadd+8:nadd+10])[0]
        self.e_shentsize = struct.unpack(endi+"H", data[nadd+10:nadd+12])[0]
        self.e_shnum = struct.unpack(endi+"H", data[nadd+12:nadd+14])[0]
        self.e_shstrndx = struct.unpack(endi+"H", data[nadd+14:nadd+16])[0]
        if doCheck:
            self.runcheck()
    def runcheck(self):
        if self.EI_VERSION != 1:
            raise Exception("Unknown ELF file format version!")
        if self.getOsabi() == "Unknown":
            raise Exception("Unknown ABI Version!")
        if self.EI_PAD != 0:
            raise Exception("There is data in the padding bytes!")
        if self.e_version != 1:
            raise Exception("Unexpected e_version value {self.e_version}")
        clas = self._getClass()
        if (self.e_ehsize != 64 and clas == 64) or (self.e_ehsize != 52 and clas == 32):
            warnings.warn("The file header is reportedly a different size than the standard size. We are not treating it as such.")
        if (self.e_phoff != 0x34 and clas == 32) or (self.e_phoff != 0x40 and clas == 64):
            warnings.warn("The program header does not start immediately after the file header.")
        if (self.e_phentsize != 0x20 and clas == 32) or (self.e_phentsize != 0x38 and clas == 64):
            warnings.warn("Unusual program header entry size.")
        if (self.e_shentsize != 0x28 and clas == 32) or (self.e_shentsize != 0x40 and clas == 64):
            warnings.warn("Unusual section header table entry size.")
    def getOsabi(self):
        global osabis
        try:
            return osabis[self.EI_OSABI]
        except:
            if self.EI_OSABI == None:
                return "Not yet set"
            else:
                return "Unknown"
    def _getClass(self):
        match self.EI_CLASS:
            case None:
                return -1
            case 1:
                return 32
            case 2:
                return 64
            case _:
                raise Exception("Invalid value of e_ident[EI_CLASS]")
                return -2
    def getClass(self):
        return str(self._getClass())
    def getSize(self):
        match self.getClass():
            case "32":
                return 52
            case "64":
                return 64
            case _:
                raise Exception("Trying to read size of the header while that is currently unknown.")
                return -1
    def _getEnd(self):
        if self.EI_DATA == 2:
            return ">"
        elif self.EI_DATA == 1:
            return "<"
        elif self.EI_DATA == None:
            return "Not set"
        else:
            raise Exception("Invalid value of e_ident[EI_DATA]")
    def getEnd(self):
        tmp = self._getEnd()
        if tmp == ">":
            return "big-endian"
        elif tmp == "<":
            return "little-endian"
        else:
            return "Invalid or Unknown"
    def getMachine(self):
        global machines
        if self.e_machine in machines.keys():
            return machines[self.e_machine]
        else:
            raise Exception(f"Unknown machine code {self.e_machine}")
    def getetype(self):
        global etypes
        if self.e_type < 5:
            return etypes[self.e_type]
        elif self.e_type >> 8 == 0xfe:
            return "Unknown operating system specific value"
        elif self.e_type >> 8 == 0xff:
            return "Unknown processor specific value"
        else:
            raise Exception(f"Unknown e_type {self.e_type}.")
    def __str__(self):
        endi = self.getEnd()
        builder = "Header: \n"
        builder += "\te_ident:\n"
        builder += "\t\tEI_CLASS: "+str(int(self.EI_CLASS))+", which is "+self.getClass()+"-bit format.\n"
        builder += "\t\tEI_DATA: "+str(int(self.EI_DATA))+", which is "+endi+".\n"
        builder += "\t\tEI_VERSION: "+str(self.EI_VERSION)+", and 1 is the expected value. \n"
        builder += f"\t\tEI_OSABI: {self.EI_OSABI}, which is {self.getOsabi()}.\n"
        builder += f"\t\tEI_ABIVERSION: {self.EI_ABIVERSION} (note: this means something but currently I am unclear as to what it means. As such, ignore this.\n"
        builder += f"\te_type: {self.e_type}, which is {self.getetype()}.\n"
        builder += f"\te_machine: {self.e_machine}, which is {self.getMachine()}.\n"
        builder += f"\te_version: {self.e_version}, and 1 is the expected value. \n"
        builder += f"\te_entry: {self.e_entry}, which means that {hex(self.e_entry)} is the entrypoint address. If this is zero, then there is none.\n"
        builder += f"\te_phoff: {self.e_phoff}, which means that {hex(self.e_phoff)} is the program header table start address.\n"
        builder += f"\te_shoff: {self.e_shoff}, which means that {hex(self.e_shoff)} is the section header table start address.\n"
        builder += f"\te_flags: {self.e_flags} - the value of this is determined by the target architecture.\n"
        builder += f"\te_ehsize: {self.e_ehsize} - The size of the file header, normally 64 bytes for 64-bit and 52 bytes for 32-bit.\n"
        builder += f"\te_phentsize: {self.e_phentsize} - The size of a program header table entry, which will typically be 0x20 (32 bit) or 0x38 (64 bit).\n"
        builder += f"\te_phnum: {self.e_phnum} - The number of entries in the program header table.\n"
        builder += f"\te_shentsize: {self.e_shentsize} - The size of a section header table entry, which will typically be 0x28 (32 bit) or 0x40 (64 bit).\n"
        builder += f"\te_shnum: {self.e_shnum} - The number of entries in the section header table.\n"
        builder += f"\te_shstrndx: {self.e_shstrndx} - Contains index of the section header table entry that contains the section names.\n" 
        return builder

class ProgramHeader():
    def __init__(self, data, endi):
        (self.readable, self.writeable, self.executable) = (False, False, False)
        (self.typ_name, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz, self.p_align) = (None, None, None, None, None, None, None)
        self.typ = struct.unpack(endi + "I", data[0x0:0x4])[0]
        self.endi = endi
        pass
    def intFlags(self, fl_data): #interpret flags, interprets the flags for each section. fl_data is the data.
        if fl_data >> 2 == 1:
            self.readable = True
        else:
            self.readable = False
        if (fl_data >> 1) % 2 == 1:
            self.writeable = True
        else:
            self.writeable = False
        if fl_data % 2 == 1:
            self.executable = True
        else:
            self.executable = False
    def doCheck(self):
        if self.p_vaddr != self.p_offset % self.p_align and self.p_align != 0 and self.p_align != 1:
            warnings.warn("The physical address, the file offset, and the alignment appear to mismatch.")
    def getTypeName(self):
        if self.typ_name != None:
            return self.typ_name
        else:
            global ptypes
            if self.typ in ptypes.keys():
                self.typ_name = ptypes[self.typ]
                return ptypes[self.typ]
            else:
                if self.typ >> 28 == 6:
                    self.typ_name = f"Operating System Specific Type {hex(self.typ)}"
                    return self.typ_name
                elif self.typ >> 28 == 7:
                    self.typ_name = f"Processor Specific Type {hex(self.typ)}"
                    return self.typ_name
                else:
                    raise Exception("Unknown section type specified by the section headers.")
    def __str__(self):
        builder = "Program Header Entry: \n"
        builder += "\t\tType: "+self.getTypeName()+"\n"
        builder += "\t\tFlags: "
        builder2 = ""
        if self.readable:
            builder2+="R"
        if self.writeable:
            builder2+="W"
        if self.executable:
            builder2+="X"
        builder += builder2 + "\n"
        builder += f"\t\tOffset: {hex(self.p_offset)}\n"
        builder += f"\t\tVirtual Address: {hex(self.p_vaddr)}\n"
        builder += f"\t\tPhysical Address: {hex(self.p_paddr)}\n"
        builder += f"\t\tSegment Size in File: {hex(self.p_filesz)}\n"
        builder += f"\t\tSegment Size in Memory: {hex(self.p_memsz)}\n"
        builder += f"\t\tAlignment: {hex(self.p_align)}\n"
        return builder

class ProgramHeader64(ProgramHeader):
    def __init__(self, data, endi):
        super().__init__(data, endi)
        self.p_flags = struct.unpack(self.endi+"I", data[0x4:0x8])[0]
        self.intFlags(self.p_flags)
        self.p_offset = struct.unpack(self.endi+"Q", data[0x8:0x10])[0]
        self.p_vaddr = struct.unpack(self.endi+"Q", data[0x10:0x18])[0]
        self.p_paddr = struct.unpack(self.endi+"Q", data[0x18:0x20])[0]
        self.p_filesz = struct.unpack(self.endi+"Q", data[0x20:0x28])[0]
        self.p_memsz = struct.unpack(self.endi+"Q", data[0x28:0x30])[0]
        self.p_align = struct.unpack(self.endi+"Q", data[0x30:0x38])[0]

class ProgramHeader32(ProgramHeader):
    def __init__(self, data, endi):
        super().__init__(data, endi)
        self.p_offset = struct.unpack(self.endi+"I", data[0x4:0x8])[0]
        self.p_vaddr = struct.unpack(self.endi+"I", data[0x8:0xc])[0]
        self.p_paddr = struct.unpack(self.endi+"I", data[0xc:0x10])[0]
        self.p_filesz = struct.unpack(self.endi+"I", data[0x10:0x14])[0]
        self.p_memsz = struct.unpack(self.endi+"I", data[0x14:0x18])[0]
        self.p_flags = struct.unpack(self.endi+"I", data[0x18:0x1c])[0]
        self.intFlags(self.p_flags)
        self.p_align = struct.unpack(self.endi+"I", data[0x1c:0x20])[0]

class PT_LOAD(ProgramHeader64, ProgramHeader32):
    def __init__(self, data, endi, ti):
        if ti == 64:
            ProgramHeader64.__init__(self, data, endi)
        else:
            ProgramHeader32.__init__(self, data, endi)
        if self.p_memsz > self.p_filesz:
            self.needs_moar = True

class sectionStore(dict):
    def __missing__(self, key):
        return -1

class SectionHeader():
    typ = None
    def __init__(self, data, sh_name, endi, bitty):
        #print(f'Length of data passed to superclass {len(data)}')
        self.sh_name = sh_name
        self.name = None
        self.endi = endi
        self.bitty = bitty
        self.data = data
        if bitty == 32:
            self.do32Init(data)
        elif bitty == 64:
            self.do64Init(data)
        else:
            raise Exception("You shouldn't have gotten this far in the code without being either 32 or 64 bit lmao. how.")
        self.intFlags()
    def do32Init(self, data):
        self.sh_flags = struct.unpack(self.endi+"I", data[0x8:0xC])[0]
        self.sh_addr = struct.unpack(self.endi+"I", data[0xC:0x10])[0]
        self.sh_offset = struct.unpack(self.endi+"I", data[0x10:0x14])[0]
        self.sh_size = struct.unpack(self.endi+"I", data[0x14:0x18])[0]
        self.sh_link = struct.unpack(self.endi+"I", data[0x18:0x1c])[0]
        self.sh_info = struct.unpack(self.endi+"I", data[0x1c:0x20])[0]
        self.sh_addralign = struct.unpack(self.endi+"I",data[0x20:0x24])[0]
        self.sh_entsize = struct.unpack(self.endi+"I", data[0x24:0x28])[0]
    def do64Init(self, data):
        #print(f'length of data passed to sub-initialization: {len(data)}')
        #print(data[0x38:0x40])
        self.sh_flags = struct.unpack(self.endi+"Q", data[0x8:0x10])[0]
        self.sh_addr = struct.unpack(self.endi+"Q", data[0x10:0x18])[0]
        self.sh_offset = struct.unpack(self.endi+"Q", data[0x18:0x20])[0]
        self.sh_size = struct.unpack(self.endi+"Q", data[0x20:0x28])[0]
        self.sh_link = struct.unpack(self.endi+"I", data[0x28:0x2c])[0]
        self.sh_info = struct.unpack(self.endi+"I",data[0x2c:0x30])[0]
        self.sh_addralign = struct.unpack(self.endi+"Q",data[0x30:0x38])[0]
        self.sh_entsize = struct.unpack(self.endi+"Q",data[0x38:])[0]
    def intFlags(self):
        if self.sh_flags & 0x1:
            self.writeable = True #SHF_WRITE
        else:
            self.writeable = False
        if self.sh_flags & 0x2:
            self.alloc = True #SHF_ALLOC
        else:
            self.alloc = False
        if self.sh_flags & 0x4:
            self.executable = True #SHF_EXECINSTR
        else:
            self.executable = False


    def __str__(self):
        builder = f"{self.typ} Section Header: \n"
        builder += f"\tsh_name: {self.sh_name}\n"
        if self.name != None:
            builder += f"\t\t{self.name}\n"
        builder += f"\tsh_flags: {self.sh_flags}\n"
        builder2 = ""
        if self.writeable:
            builder2 += "\t\tWriteable"
        if self.alloc:
            builder2 += "\t\tAllocated"
        if self.executable:
            builder2 += "\t\tExecutable"
        if builder2 != "":
            builder += builder2 + "\n"
        builder += f"\tsh_addr: {self.sh_addr}\n"
        builder += f"\tsh_offset: {self.sh_offset}\n"
        builder += f"\tsh_size: {self.sh_size}\n"
        builder += f"\tsh_link: {self.sh_link}\n"
        builder += f"\tsh_info: {self.sh_info}\n"
        builder += f"\tsh_addralign: {self.sh_addralign}\n"
        builder += f"\tsh_entsize: {self.sh_entsize}\n"
        return builder
    
    def __repr__(self):
        return self.__str__()

class SHT_NULL(SectionHeader):
    typ = "SHT_NULL"
    def __init__(self, data, sh_name, endi, bitty):
        super().__init__(data, sh_name, endi, bitty)

class SHT_PROGBITS(SectionHeader):
    typ = "SHT_PROGBITS"
    def __init__(self, data, sh_name, endi, bitty):
        super().__init__(data,sh_name,endi,bitty)

    #Other methods should probably be defined here once I get a better undersstanding of how codeflow works.

class SHT_NOTE(SectionHeader):
    typ = "SHT_NOTE"
    def __init__(self, data, sh_name, endi, bitty):
        #print(f'Length of data passed to subclass (SHT_NOTE) {len(data)}')
        super().__init__(data, sh_name, endi, bitty) 
        ''' self.namesz = struct.unpack(endi+"I",data[0:4])[0]
        self.descsz = struct.unpack(endi+"I",data[4:8])[0]
        print(f"namesz: {self.namesz}")
        print(f"descsz: {self.descsz}")
        if self.namesz > 0:
            self.name = struct.unpack(endi+str(self.namesz)+"c",data[8:8+self.namesz])'''
            
class SHT_OS(SectionHeader):
    typ = "SHT_OS"
    global gnu_name_dict
    def __init__(self, data, sh_name, endi, bitty):
        super().__init__(data, sh_name, endi, bitty)
        self.subtyp = None
    def addSubtype(self):
        if self.name != None:
            self.subtyp = gnu_name_dict[self.name](self.data, self.sh_name, self.endi, self.bitty)    
        else:
            warnings.warn("Attempting to add a subtype when subtype is not set.")
    def __str__(self):
        ret = super().__str__()
        if self.subtyp != None:
            ret += f'\n\tSubtype: {self.subtyp.typ}\n'
        return ret
class SHT_DYNSYM(SectionHeader): #Holds a set of dynamic linking symbols
    typ = "SHT_DYNSYM"

class SHT_STRTAB(SectionHeader): #Holds a string table
    typ = "SHT_STRTAB"

class SHT_RELA(SectionHeader): #Holds reloc entries
    typ = "SHT_RELA"

class SHT_INIT_ARRAY(SectionHeader):
    typ = "SHT_INIT_ARRAY"

class SHT_FINI_ARRAY(SectionHeader):
    typ = "SHT_FINI_ARRAY"

class SHT_DYNAMIC(SectionHeader): #Holds information for dynamic linking.
    typ = "SHT_DYNAMIC"

class SHT_NOBITS(SectionHeader): #Occupies no space in the file but otherwise resembles SHT_PROGBITS
    typ = "SHT_NOBITS"

class SHT_SYMTAB(SectionHeader): #Contains a symbol table
    typ = "SHT_SYMTAB"

class SHT_HASH(SectionHeader): #GNU-Specific
    typ = "SHT_HASH"

class SHT_GNU_versym(SectionHeader): #Gnu-Specific
    typ = "SHT_GNU_versym"

class symbol():
    def __init__(self, data, ver):
        self.data = data
        self.ver = ver
        if ver == 32:
            self.do32Init()
        else:
            self.do64Init()
    def do32Init(self):
        self.st_name = struct.unpack(self.ver+"I", data[0:4])
        self.st_value = struct.unpack(self.ver+"I", data[4:8])
        self.st_size = struct.unpack(self.ver+"I", data[8:12])
        self.st_info = struct.unpack(self.ver+"B", data[12])
        self.st_other = struct.unpack(self.ver+"B", data[13])
        self.st_shndx = struct.unpack(self.ver+"H", data[14:16]) 
    def do64Init(self):
        self.st_name = struct.unpack(self.ver+"I", data[0:4])
        self.st_info = struct.unpack(self.ver+"B", data[4])
        self.st_other = struct.unpack(self.ver+"B", data[5])
        self.st_shndx = struct.unpack(self.ver+"H", data[6:8])
        self.st_value = struct.unpack(self.ver+"Q", data[8:16])
        self.st_size = struct.unpack(self.ver+"Q", data[16:24])
    def updateNames(self, shs):
        self.name = shs[self.st_name]

class shstr():
    def __init__(self, data):
        self.array = []
        for i in data:
            if i == b'\x00':
                self.array.append(b'\x00')
            else:
                self.array.append(chr(i))
    def __getitem__(self, index):
        builder = ""
        for i in self.array[index:]:
            if i != '\x00':
                builder += i
            else:
                return builder
    def __str__(self):
        return "".join(self.array)

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--file', help='Path to the input file', required=True)
parser.add_argument('-fh', '--fileheader', help='Whether to print the file header', action='store_true')
parser.add_argument('-ph', '--progheader', help='Whether to print the program header table', action='store_true')
parser.add_argument('-sh', '--secthead', help='Whether to print the section header table', action='store_true')
parser.add_argument('-db', '--debug', help='Whether to print debugging information', action='store_true')

args = parser.parse_args()
file = open(args.file,"rb")

he = FileHeader()
tmp = file.read(4)
if not tmp == b'\x7fELF':
    raise Exception("This is not an ELF File.")
else:
    he.EI_MAG = tmp
tmp2 = file.read(1)
tmp3 = file.read(1)
he.EI_CLASS = struct.unpack("B", tmp2)[0]
he.EI_DATA = struct.unpack("B", tmp3)[0]
data = None
hgs = he.getSize()
match hgs:
    case 64:
        data = file.read(64-6)
    case 52:
        data = file.read(52-6)

he.otherInit(data)

ph = sectionStore()
locs = sectionStore()
segs = sectionStore()
endi = he._getEnd()

if args.fileheader:
    print(he)

if args.progheader:
    print("Program Header Table: \n\n")

PT_Mapping = {
        1:  PT_LOAD
        }

if (he.e_phoff == 64 and hgs == 64) or (he.e_phoff == 52 and hgs == 52):
    for i in range(he.e_phnum):
        tmp = file.read(he.e_phentsize)
        typ = struct.unpack(endi + "I", tmp[0x0:0x4])[0] 
        if typ in PT_Mapping.keys():
            tmp2 = PT_Mapping[typ](tmp, endi, he._getClass())
        elif he.e_phoff == 64:
            tmp2 = ProgramHeader64(tmp, endi)
        else:
            tmp2 = ProgramHeader32(tmp, endi)
        if args.progheader:
            print(f"\t{i}:",end=" - ")
            print(tmp2)
        tmp2.doCheck()
        ph[tmp2.p_offset] = tmp2
        locs[tmp2.p_offset] = i 
else:
    raise Exception("Unimplemented program header location.")

if args.debug:
    print("Reading actual segments of file.")
i = 0
current_location = hgs + he.e_phnum * he.e_phentsize
while len(file.peek()) > 0:
    #print(locs[current_location])
    if args.debug:
        print(f"Current location in file: {hex(current_location)}")
    curr = ph[current_location]
    if curr != -1:
        if args.debug:
            print(f"Current program section - {curr}")
            print(f"Size of current section: {hex(curr.p_filesz)}")
        segs[current_location] = file.read(curr.p_filesz)
        current_location += curr.p_filesz
    elif current_location ==  he.e_shoff:
        segs[current_location] = file.read(he.e_shnum * he.e_shentsize)
        current_location += he.e_shnum * he.e_shentsize
    else:
        #print(f"Currently at: {hex(current_location)}")
        if current_location >= max(list(ph)):
            if current_location < he.e_shoff and current_location < he.e_entry:
                if he.e_shoff < he.e_entry:
                    segs[current_location] = file.read(he.e_shoff - current_location)
                    current_location += he.e_shoff - current_location
                else:
                    segs[current_location] = file.read(he.e_entry - current_location)
                    current_location += he.e_entry - current_location
            elif current_location < he.e_shoff:
                segs[current_location] = file.read(he.e_shoff - current_location)
                current_location += he.e_shoff - current_location
            elif current_location < he.e_entry:
                segs[current_location] = file.read(he.e_entry - current_location)
                current_location += he.e_entry - current_location
            else:
                if args.debug:
                    print(f"Location when exiting: {hex(current_location)}")
                break
        else:
            for i in sorted(list(ph)):
                if i > he.e_shoff:
                    segs[current_location] = file.read(he.e_shoff - current_location)
                    current_location += he.e_shoff - current_location
                    break
                elif i > current_location:
                    segs[current_location] = file.read(i - current_location)
                    current_location += i - current_location
                    break


section_dict = { #There are more i just dont want to implement them rn.
                0:SHT_NULL,
                1:SHT_PROGBITS,
                2: SHT_SYMTAB,
                3: SHT_STRTAB,
                4: SHT_RELA,
                6: SHT_DYNAMIC,
                7: SHT_NOTE,
                8: SHT_NOBITS,
                0xb: SHT_DYNSYM,
                0xe: SHT_INIT_ARRAY,
                0xf: SHT_FINI_ARRAY
        }
shead = []
for i in range(len(segs[he.e_shoff])//he.e_shentsize):
    tmpdata = segs[he.e_shoff][i*he.e_shentsize:i*he.e_shentsize+he.e_shentsize]
    #print(f'len(tmpdata) {len(tmpdata)}')
    tmpnameind = struct.unpack(endi+"I",tmpdata[0:4])[0]
    typ = struct.unpack(endi+"I",tmpdata[4:8])[0]
    #print(f'len(tmpdata after initial unpacking) {len(tmpdata)}')
    if typ > 0x60000000:
        tmp = SHT_OS(tmpdata, tmpnameind,endi,he._getClass())
    else:
        tmp = section_dict[typ](tmpdata,tmpnameind,endi,he._getClass())
    if args.secthead:
        print(f'{typ} - {tmp.typ}')
    shead.append(tmp)
    if args.secthead:
        print(tmp)

strdx = shead[he.e_shstrndx].sh_offset

if args.debug:
    print(f"\nlength of section header array: {len(shead)}")
    print(f"the shstr is",end=" ")
    if strdx in segs.keys():
        print("easily accessible.")
    else:
        print("not easily accessible.")

def part_sect(di, idx, dbg, sz):
    '''
    Takes in a dictionary di, a key/address of said dictinary  idx, a debug boolean dbg, and a size sz.
    '''
    ans = 0
    ans = 0
    for i in di.keys():
        if i <= idx:
            ans = i
        else:
            ans2 = i
            break
    if dbg:
        print(f"The closest prior index to it is {ans}")
        print(f"The closest latter index to it is {ans2}")
        print(f"The index we want is {idx}")
        print(f"The first index to grab is {idx - ans}")
        print(f"The size of the section we want is {sz}")
    di[idx] = di[ans][idx - ans:sz+idx-ans]
    if (idx - ans) + sz < len(di[ans]):
        di[sz+ans] = di[ans][sz:]
    if idx - ans > 0:
        di[ans] = di[ans][0:idx - ans]
    
if strdx not in segs.keys() or shead[he.e_shstrndx].sh_size < len(segs[strdx]):
    part_sect(segs, strdx, args.debug, shead[he.e_shstrndx].sh_size)
    

shx = shstr(segs[strdx])
sect_names = {}

if args.debug:
    print("\nAssigning names to sections...")
for j in range(len(shead)):
    i = shead[j]
    if args.debug:
        print(shx[i.sh_name])
    i.name = shx[i.sh_name]
    if i.name not in sect_names.keys():
        sect_names[i.name] = [j]
    else:
        sect_names[i.name] = sect_names[i.name].append(j)

shead[he.e_shstrndx].actdat = shx

if ".strtab" in sect_names.keys():
    if args.debug:
        print("\nProcessing string table(s)...")
    for i in sect_names[".strtab"]:
        offset = shead[i].sh_offset
        sz = shead[i].sh_size
        if offset not in segs.keys() or shead[offset].sh_size < len(segs[offset]):
            part_sect(segs, offset, args.debug, sz)
        shead[i].actdat = shstr(segs[offset]) #actual data
        if args.debug:
            print(shead[i].actdat)
            print(f"<--- {i}")
    for i in sect_names[".dynstr"]:
        offset = shead[i].sh_offset
        sz = shead[i].sh_size
        if offset not in segs.keys() or shead[offset].sh_size < len(segs[offset]):
            part_sect(segs, offset, args.debug, sz)
        shead[i].actdat = shstr(segs[offset])
        if args.debug:
            pass


gnu_name_dict = {
            ".hash": SHT_HASH,
            ".gnu.hash": SHT_HASH,
            ".gnu.version": SHT_GNU_versym,
            ".gnu.version_r": SHT_GNU_versym

        }

for i in shead:
    if i.name in gnu_name_dict.keys():
        i.addSubtype()
