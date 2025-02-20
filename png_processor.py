# Citations:
#
# https://en.wikipedia.org/wiki/PNG
# http://libpng.org/pub/png/spec/iso/index-object.html
# https://wiki.mozilla.org/APNG_Specification
# https://en.wikipedia.org/wiki/APNG

import struct
import argparse
import zlib
import warnings
from itertools import islice
from math import floor, ceil


compmethods = {0:"Zlib datastream with deflate compression (0)"}
def getCompMeth(method):
    global compmethods
    try:
        return compmethods[method]
    except:
        return "Unknown Compression Method "+str(method)

def batched(iterable, n, *, strict=False): #From https://docs.python.org/3/library/itertools.html#itertools.batched, can't figure out how to update and the latest debian python package i have access to is 3.11..
    # batched('ABCDEFG',3) -> ABC DEF G
    if n < 1:
        raise ValueError('n must be at least one')
    iterator = iter(iterable)
    while batch := tuple(islice(iterator, n)):
        if strict and len(batch) != n:
            raise ValueError('batched(): incomplete batch')
        yield batch

class Chunk:
    le, data, CRC = None, None, None
    def __init__(self, le, data, CRC):
        self.le = le
        self.data = data
        self.CRC = CRC
    def __str__(self):
        pass
class IHDR_Chunk(Chunk):
    typ = "IHDR"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        self.width = struct.unpack(">I", data[0:4])[0]
        self.height = struct.unpack(">I", data[4:8])[0]
        if 0 == self.width or 0 == self.height:
            raise Exception("Invalid IHDR Chunk for the reason of invalid width and/or height of image in pixels.")
        self.bitdep = data[8]
        self.colortype = data[9]
        if not self.check_bitcolor():
            raise Exception("Invalid IHDR Chunk for the reason of invalid combination of bitdepth and colortype.")
        if self.colortype == 3:
            self.sampdep = 8 #Sample depth
        else:
            self.sampdep = self.bitdep
        self.compmeth = data[10]
        if self.compmeth != 0:
            raise Exception("Unknown if IHDR Chunk is valid for the reason of unimplemented compression method.")
        self.filtmeth = data[11]
        if self.filtmeth != 0:
            raise Exception("Unknown if IHDR Chunk is valid for the reason of unimplemented filter method.")
        self.intmeth = data[12]
        if self.intmeth not in (0, 1):
            raise Exception("Unknown if IHDR Chunk is valid for the reason of unimplemented interlace method.")
        print(self)
    def check_bitcolor(self):
        if self.colortype == 0:
            if self.bitdep in (1,2,4,8,16):
                return True
            return False
        if self.colortype == 2:
            if self.bitdep in (8,16):
                return True
            return False
        if self.colortype == 3:
            if self.bitdep in (1,2,4,8):
                return True
            return False
        if self.colortype in (4,6):
            if self.bitdep in (8,16):
                return True
            return False
        return False

    def __str__(self):
        builder = "IHDR: \n"
        builder += "\tSize of IHDR: "+str(self.le) + " ("+hex(self.le)+")\n"
        builder += "\tWidth in pixels: "+str(self.width)+" ("+hex(self.width)+")"+"\n"
        builder += "\tHeight in pixels: "+str(self.height)+" ("+hex(self.height)+")"+"\n"
        builder += "\tBit depth: "+str(self.bitdep)+" ("+hex(self.bitdep)+")\n"
        builder += "\tColour type: "+str(self.colortype)+" ("
        match self.colortype:
            case 0:
                builder += "Greyscale)\n"
            case 2:
                builder += "Truecolor)\n"
            case 3:
                builder += "Indexed-color)\n"
            case 4:
                builder += "Greyscale with alpha)\n"
            case 6:
                builder += "Truecolor with alpha)\n"
            case _:
                builder += "Unknown)\n"
        builder += "\tCompression method: "+str(self.compmeth)+" ("
        match self.compmeth:
            case 0:
                builder+="deflate/inflate compression with a sliding window of at most 32768 bytes)\n"
            case _:
                builder+="Unknown)\n"
        builder += "\tFilter method: "+str(self.filtmeth)+" ("
        match self.filtmeth:
            case 0:
                builder+="adaptive filtering with five basic filter types)\n"
            case _:
                builder+="Unknown)\n"
        builder += "\tInterlace method: "+str(self.intmeth)+" ("
        match self.intmeth:
            case 0:
                builder+="no interlace)\n"
            case 1:
                builder+="Adam7 interlace)\n"
            case _:
                builder+="Unknown)\n"
        return builder
class SRGB_Chunk(Chunk):
    typ = "sRGB"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        self.intent = data[0]
        print(self)
    def __str__(self):
        builder = "SRGB: \n"
        builder += "\tRendering intent: "
        match self.intent:
            case 0:
                builder += "Perceptual"
            case 1:
                builder += "Relative colorimetric"
            case 2:
                builder += "Saturation"
            case 3:
                builder += "Absolute colorimetric"
            case _:
                builder += "Unknown"
        builder += "\n"
        return builder
class BKGD_Chunk(Chunk):
    typ = "bKGD"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
    def moarInit(self, ihdr):
        self.colortype = ihdr.colortype
        if self.colortype in [0, 4]:
            self.greylevel = struct.unpack(">H", self.data)[0]
        elif self.colortype in [2, 6]:
            self.red = struct.unpack(">H", self.data[0:2])[0]
            self.green = struct.unpack(">H", self.data[2:4])[0]
            self.blue = struct.unpack(">H", self.data[4:6])[0]
        elif self.colortype == 3:
            self.palind = self.data
        print(self)
    def __str__(self):
        builder = "BKGD: \n"
        if self.colortype in [0, 4]:
            builder += "\tGrey level: "+str(self.greylevel)
        if self.colortype in [2,6]:
            builder += "\tRed level: "+str(self.red)+"\n"
            builder += "\tGreen level: "+str(self.green)+"\n"
            builder += "\tBlue level: "+str(self.blue)+"\n"
        if self.colortype == 3:
            builder += "\tPalette index: "+str(sel.palind)+"\n"
        return builder
class PHYS_Chunk(Chunk):
    typ = "pHYs"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        self.ppux = struct.unpack(">I", data[0:4])[0]
        self.ppuy = struct.unpack(">I", data[4:8])[0]
        self.unsp = data[8]
        print(self)
    def __str__(self):
        builder = "pHYs: \n"
        builder += "\tSize of pHYs: "+str(self.le)+" ("+hex(self.le)+")\n"
        builder += "\tPixels per unit, X axis: "+str(self.ppux)+"\n"
        builder += "\tPixels per unit, Y axis: "+str(self.ppuy)+"\n"
        builder += "\tUnit specifier: "
        if self.unsp == 0:
            builder += "unit is unknown\n"
        if self.unsp == 1:
            builder += "unit is the metre\n"
        return builder
class IDAT_Chunk(Chunk):
    typ = "IDAT"
    def __init__(self, le, data, CRC):
        act_CRC = struct.unpack(">I", CRC)[0]
        Chunk.__init__(self, le, data,act_CRC)
        print("IDAT...",end="")
class IEND_Chunk(Chunk):
    typ = "IEND"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        if(len(data)>0):
            yn = input("There's extra data in the IEND Chunk. Would you like to print it to the terminal? (If this is binary data, this may mess up the terminal.)")
            if yn == "y" or yn == "Y":
                       print(self.data)
        print(self)
    def __str__(self):
        builder = "IEND."
        return builder
class ACTL_Chunk(Chunk):
    typ = "acTL"

class FCTL_Chunk(Chunk):
    typ = "fcTL"

class FDAT_Chunk(Chunk):
    typ = "fdAT"

class ITXT_Chunk(Chunk):
    typ = "iTXt"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        words = data.partition(b'\x00')
        self.keyword = words[0]
        self.compflag = words[2][0]
        self.compmeth = words[2][1]
        words2 = words[2][2:].partition(b'\x00')
        self.langtag = words2[0]
        words3 = words2[2].partition(b'\x00')
        self.transkey = words3[0]
        self.text = words3[2]
        if self.compflag != 0:
            raise Exception("Unimplemented iTXt compression method")
        print(self)
    def __str__(self):
        builder = "\niTXt: \n"
        builder += "\tKeyword: "+str(self.keyword)+"\n"
        builder += "\tCompression Flag (0 for uncompressed, 1 for compressed): "+str(self.compflag)+"\n"
        if self.compflag != 0: 
            builder += "\tCompression Method: "+getCompMeth(self.compmeth)+"\n"
        if len(self.langtag) != 0:
            builder += "\tLanguage tag: "+str(self.langtag)+"\n"
        if len(self.transkey) != 0:
            builder += "\tTranslated keyword: "+str(self.transkey)+"\n"
        builder += "\n\tText: "+self.text.decode()+"\n"
        return builder

class TEXT_Chunk(Chunk):
    typ = "tEXt"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        words = data.partition(b'\x00')
        self.keyword = words[0]
        self.str = words[2]
        print(self)
    def __str__(self):
        builder = "\ntEXt: \n"
        builder += "\tKeyword: "+str(self.keyword)+"\n"
        builder += "\tText string: "+str(self.str)+"\n"
        return builder

class GAMA_Chunk(Chunk):
    typ = "gAMA"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        self.gamma = struct.unpack(">I", data)[0]/100000
        print(self)
    def __str__(self):
        builder = "gAMA: \n"
        builder += "\tSize of gAMA: "+str(self.le) + " ("+hex(self.le)+")\n"
        builder += "\tGamma value: "+str(self.gamma)+"\n"
        return builder

class ICCP_Chunk(Chunk):
    typ = "iCCP"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        words = data.partition(b'\x00')
        self.profname = words[0]
        self.compmeth = words[2][0]
        self.compprof = words[2][1:]
        print(self)
    def __str__(self):
        builder = "iCCP: \n"
        builder += "\tSize of iCCP: "+str(self.le) + " ("+hex(self.le)+")\n"
        builder += "\tProfile name: "+str(self.profname) + "\n"
        builder += "\tCompression method: "
        match self.compmeth:
            case 0:
                builder += "Zlib datastream with deflate compression (0)\n"
            case _:
                builder += "Unimplemented compression method ("+hex(self.compmeth)+")\n"
        builder += "\tSize of compressed profile: "+str(len(self.compprof))+ " ("+hex(len(self.compprof))+")\n"
        return builder

class CHRM_Chunk(Chunk):
    typ = "cHRM"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
        self.wpx = struct.unpack(">I",data[0:4])[0] / 100000 #White point x
        self.wpy = struct.unpack(">I",data[4:8])[0] / 100000 #White point y
        self.rx = struct.unpack(">I", data[8:12])[0] /100000 #Red x
        self.ry = struct.unpack(">I", data[12:16])[0]/100000 #Red y
        self.gx = struct.unpack(">I", data[16:20])[0]/100000 #Green x
        self.gy = struct.unpack(">I", data[20:24])[0]/100000 #Green y
        self.bx = struct.unpack(">I", data[24:28])[0]/100000 #Blue x
        self.by = struct.unpack(">I", data[28:32])[0]/100000 #Blue y
        print(self)
    def __str__(self):
        builder = "cHRM: \n"
        builder += "\tSize of cHRM: "+str(self.le)+" ("+hex(self.le)+")\n"
        try:
            builder += "\tWhite point (x, y): ("+str(self.wpx)+", "+str(self.wpy)+") - or in hex ("+hex(self.wpx)+", "+hex(self.wpy)+")\n"
        except:
            builder += "\tWhite point (x, y): ("+str(self.wpx)+", "+str(self.wpy)+")\n"
        try:
            builder += "\tRed (x, y): "+str(self.rx)+", "+str(self.ry)+") - or in hex ("+hex(self.rx)+", "+hex(self.ry)+")\n"
        except:
            builder += "\tRed (x, y): "+str(self.rx)+", "+str(self.ry)+")\n"
        try:
            builder += "\tGreen (x, y): "+str(self.gx)+", "+str(self.gy)+") - or in hex ("+hex(self.gx)+", "+hex(self.gy)+")\n"
        except:
            builder += "\tGreen (x, y): "+str(self.gx)+", "+str(self.gy)+")\n"
        try:
            builder += "\tBlue (x, y): "+str(self.bx)+", "+str(self.by)+") - or in hex ("+hex(self.bx)+", "+hex(self.by)+")\n"
        except:
            builder += "\tBlue (x, y): "+str(self.bx)+", "+str(self.by)+")\n"
        return builder
    def moarInit(self, ihdr):
        pass

class TRNS_Chunk(Chunk):
    typ = "tRNS"
    def __init__(self, le, data, CRC):
        Chunk.__init__(self, le, data, CRC)
    def moarInit(self, ihdr):
        self.colortype = ihdr.colortype
        match ihdr.colortype:
            case 0:
                self.gsv = struct.unpack(">H", data) #Grey sample value
            case 2:
                self.rsv = struct.unpack(">H", data[0:2]) #Red sample value
                self.bsv = struct.unpack(">H", data[2:4]) #Blue sample value
                self.gsv = struct.unpack(">H", data[4:6]) #Green sample value
            case 3:
                self.pas = [] #Alpha for palette indexes array
                for i in data:
                    self.pas.append(i)
                self.len = len(self.pas)
            case _:
                raise Exception("This specific color type should not have a tRNS chunk!!")
        print(self)
    def __str__(self):
        builder = "tRNS: \n"
        builder += "\tSize of tRNS: "+str(self.le)+" ("+hex(self.le)+")/n"
        match self.colortype:
            case 0:
                builder += "\tGrey sample value: "+str(self.gsv)+" ("+hex(self.gsv)+")\n"
            case 2:
                builder += "\tRed sample value: "+str(self.rsv)+" ("+hex(self.rsv)+")\n"
                builder += "\tBlue sample value: "+str(self.bsv)+" ("+hex(self.bsv)+")\n"
                builder += "\tGreen sample value: "+str(self.gsv)+" ("+hex(self.gsv)+")\n"
            case 3:
                builder += "\tColor palette alpha values: "+str(self.pas)+"\n"
        return builder
class TIME_Chunk(Chunk):
    typ = "tIME"
    def __init__(self, le, data, CRC):
        super().__init__(le, data, CRC)
        self.yr = data[0:2]
        self.mnth = data[2]
        self.day = data[3]
        self.hour = data[4]
        self.minute = data[5]
        self.second = data[6]
        print(self)
    def __str__(self):
        builder += "tIME: \n"
        return builder

class SBIT_Chunk(Chunk):
    typ = "sBIT"
    siggb, sigrb, sigbb, sigab = None, None, None, None
    def __init__(self, le, data, CRC):
        super().__init__(le, data, CRC)
    def moarInit(self, ihdr):
        self.colortype = ihdr.colortype
        match self.colortype:
            case 0:
                self.siggb = data[0] #significant greyscale bits
            case 2 | 3:
                self.sigrb = data[0] #significant red bits
                self.siggb = data[1] #... green ...
                self.sigbb = data[2] #... blue ...
            case 4:
                self.siggb = data[0] #... greyscale ...
                self.sigab = data[1] #... alpha ...
            case 6:
                self.sigrb = data[0] #... red ...
                self.siggb = data[1] #... green ...
                self.sigbb = data[2] #... blue ...
                self.sigab = data[3] #... alpha ...
        for i in (self.siggb, self.sigrb, self.sigbb, self.sigab):
            if i is not None:
                if i <= 0:
                    raise Exception("There can't be no significant bits in this channel!")
                if i > ihdr.sampdep:
                    raise Exception("There can't be more significant bits than present!")
        print(self)
    def __str__(self):
        builder = "sBIT: \n"
        builder += "\tSize of sBIT: "+str(self.le)+" ("+hex(self.le)+")\n"
        match self.colortype:
            case 0 | 4:
                builder += "\tSignificant greyscale bits: "+str(self.siggb)+" ("+hex(self.siggb)+")\n"
            case 2 | 3 | 6:
                builder += "\tSignificant red bits: "+str(self.sigrb)+" ("+hex(self.sigrb)+")\n"
                builder += "\tSignificant green bits: "+str(self.siggb)+" ("+hex(self.siggb)+")\n"
                builder += "\tSignificant blue bits: "+str(self.sigbb)+" ("+hex(self.sigbb)+")\n"
        if self.colortype == 4 or self.colortype == 6:
            builder += "\tSignificant alpha bits: "+str(self.sigab)+" ("+hex(self.sigab)+")\n"
        return builder
class PLTE_Chunk(Chunk):
    typ = "PLTE"
    colors = []
    def __init__(self, le, data, CRC):
        super().__init__(le, data, CRC)
        self.num_entries = self.le % 3
        if self.le % 3 != 0:
            raise Exception("The PLTE Chunk should be divisible by 3!")
        for i in struct.iter_unpack(">3B", data):
            self.colors.append((i[0],i[1],i[2]))

    def __str__(self):
        builder = "PLTE: \n"
        builder += "\tSize of PLTE: "+str(self.le)+" ("+hex(self.le)+")\n"
        builder += "\tNumber of Entries: "+str(self.le // 3)+"\n"
        yn = input("There are {self.le // 3} entries in the PLTE section. Print entries? (y/n)")
        if yn == "y" or yn == "Y":
            builder += "\tEntries: \n"
            for i in self.colors:
                builder += f"\t\t({i[0]},{i[1]},{i[2]})\n"
        elif yn == "n" or yn == "N" or yn == "":
            pass
        else:
            print("\tThat wasn't a valid answer man. Whatever, I'm just not going to print it then.")
        return builder

    def moarInit(self, ihdr):
        self.colortype = ihdr.colortype
        self.bitdep = ihdr.bitdep
        match ihdr.colortype:
            case 0:
                raise Exception("There's a PLTE Chunk here and there shouldn't be!")
            case 2:
                pass
            case 3:
                if self.num_entires > 2**self.bitdep:
                    raise Exception("There are too many entries in the Palette!")


class imageData():
    def __init__(self, hght=0, wdth=0, bitdep = 8):
        self.data = []
        self.xlen = wdth
        self.hght = hght
        self.ylen = hght
        self.wdth = wdth
        self.bitdep = bitdep
        self.bytdep = bitdep // 8 #Unsure if this is a real thing or a thing i just made up, calling it 'bytedepth'

    def __getitem__(self, index):
        try:
            if index[0] >= self.hght:
                print('in here')
                raise Exception("Height out of bounds.")
            if index[1] >= self.wdth:
                print('in there')
                raise Exception("Width out of bounds.")
        except Exception as inst:
            print(type(inst))
            print(inst.args)
            print(inst)
        try:
            ret = self.data[self.wdth*index[0]+index[1]]
            return ret
        except IndexError as e:
            print(f"Types: index[0]: {type(index[0])}, index[1]: {type(index[1])}")
            print(f"Index 0: {index[0]}")
            print(f"Height: {self.hght}")
            print(f"Index 1: {index[1]}")
            print(f"Width: {self.wdth}")
            print(f"The real index we're attempting to access is: "+str(self.wdth*index[0]+index[1]))
            #print(f"Data is {self.data}")
            print(f"Length of the backend data {len(self.data)}")
            print(f"Attempting to access (index[1],index[0]): {index[1]},{index[0]}")
            print(f"Height is {self.hght} and Width is {self.wdth}")
            print(e)
        return b'\x00'
    
    def getRGBA(self, index):
        pass

    def __repr__(self):
        return str(self.data)

    def __str__(self):
        builder = "RGB(A) Array: \n"
        for i in range(self.hght):
            for j in range(self.wdth):
                builder += self.getRGBA((i, j)) + " "
            builder += "\n"
        return str(builder)

    def __setitem__(self, key, value):
        self.data[key[0]*self.hght+key[1]] = value

    def __gai__(self, index): #Get Actual Index
        return index[0]*self.wdth+index[1]

class tcwaImageData(imageData): #true color with alpha
    def __init__(self, hght=0, wdth=0, bitdep=8):
        super().__init__(hght=hght, wdth=wdth, bitdep=bitdep)
        self.ne = 4 #number of entries
        match bitdep:
            case 8:
                self.form = ">4B"
                self.data = [bytes(4)] * (wdth+1) * (hght+1)
            case 16:
                self.form = ">4H"
                self.data = [bytes(8)] * (wdth+1) * (hght+1)
            case _:
                raise Exception("Invalid bitdepth for a Truecolor with alpha image type.")
        
    def __getitem__(self, index):
        if len(index) == 3:
            if index[0] >= self.hght:
                raise Exception("Object out of vertical bounds.")
            if index[1] >= self.wdth:
                raise Exception("Object out of horizontal bounds.")
            tmp = super().__getitem__((index[0],index[1]))
            spot = struct.unpack(self.form, tmp)
            ret = spot[index[2]]
        elif len(index) == 2:
            ret = super().__getitem__(index)
        return ret
    def __setitem__(self, key, value):
        o = self[key[0],key[1],0]
        p = self[key[0],key[1],1]
        q = self[key[0],key[1],2]
        r = self[key[0],key[1],3]
        gi = super().__gai__(key)
        if len(key) == 3:
            match key[2]:
                case 0:
                    self.data[gi] = struct.pack(self.form, value, p, q, r)
                case 1:
                    self.data[gi] = struct.pack(self.form, o, value, q, r)
                case 2:
                    self.data[gi] = struct.pack(self.form, o, p, value, r)
                case 3:
                    self.data[gi] = struct.pack(self.form, o, p, q, value)
                case _:
                    raise Exception("Something went wrong while indexing (writing) the image data.")
        elif len(key) == 2:
            gi = super().__gai__(key)
            self.data[gi] = value
    def getRGBA(self, index):
        tup = struct.unpack(self.form, self[index[0],index[1]])
        builder = ""
        for i in range(3):
            builder += hex(tup[i])+","
        builder+=hex(tup[3])
        return builder
class truecolorImageData(imageData):
    def __init__(self, hght=0, wdth=0, bitdep=8):
        super().__init__(hght=hght, wdth=wdth, bitdep=bitdep)
        self.ne = 3 #number of entries
        match bitdep:
            case 8:
                self.form = ">3B"
            case 16:
                self.form = ">3H"
            case _:
                raise Exception("Invalid bit depth for a color type of truecolor.")
        self.data = [bytes(3*self.bytdep)] * (wdth+1) * (hght+1)
    def __getitem__(self, index):
        if len(index) == 3:
            if index[0] >= self.hght:
                raise Exception("Object out of vertical bounds.")
            if index[1] >= self.wdth:
                raise Exception("Object out of horizontal bounds.")
            tmp = super().__getitem__(index)
            try:
                spot = struct.unpack(self.form, tmp)
            except:
                print(tmp)
            return spot[index[2]]
        elif len(index) == 2:
            return super().__getitem__(index)
        else:
            return self.data[index:index+self.wdth]
        
    def __setitem__(self, key, value):
        tmp = [self[key[0],key[1],0],self[key[0],key[1],1],self[key[0],key[1],2]]
        gi = self.__gai__(key)

        if len(key) == 3:
            match key[2]:
                case 0:
                    self.data[gi] = struct.pack(self.form, value, tmp[1], tmp[2])
                case 1:
                    self.data[gi] = struct.pack(self.form, tmp[0], value, tmp[2])
                case 2:
                    self.data[gi] = struct.pack(self.form, tmp[0], tmp[1], value)
    
        elif len(key) == 2 and isinstance(value,tuple):
            self[key[0],key[1],0] = value[0]
            self[key[0],key[1],1] = value[1]
            self[key[0],key[1],2] = value[2]
        elif len(key) == 2 and isinstance(value,bytes):
            gi = super().__gai__(key)
            
            self.data[gi] = value
    def getRGBA(self, index):
        tup = struct.unpack(self.form, self[index[0], index[1]])
        builder = ""
        for i in range(2):
            builder+=hex(tup[i])+","
        builder+=hex(tup[2])
        return builder

    @property
    def __array_interface__(self):
        return {
                'shape': (self.hght, self.wdth),
                'typestr': '>3V',
                'descr': [('r','>1'+self.form[2]),('g','>1'+self.form[2]),('b','>1'+self.form[2])]
            }

class Image:
    chunks = []
    idat_locs = []
    chunk_locs = {}
    chunk_count = {}
    chunk_mapping = {
            b'IHDR': IHDR_Chunk,
            b'sRGB': SRGB_Chunk,
            b'bKGD': BKGD_Chunk,
            b'pHYs': PHYS_Chunk,
            b'IDAT': IDAT_Chunk,
            b'IEND': IEND_Chunk,
            b'acTL': ACTL_Chunk,
            b'fcTL': FCTL_Chunk,
            b'fdAT': FDAT_Chunk,
            b'tEXt': TEXT_Chunk,
            b'tIME': TIME_Chunk,
            b'sBIT': SBIT_Chunk,
            b'PLTE': PLTE_Chunk,
            b'gAMA': GAMA_Chunk,
            b'cHRM': CHRM_Chunk,
            b'iCCP': ICCP_Chunk,
            b'tRNS': TRNS_Chunk,
            b'iTXt': ITXT_Chunk
    }
    needs_ihdr = [b'PLTE', b'bKGD',b'tRNS',b'cHRM',b'sBIT']
    def __init__(self):
        self.plt_proc = False
    def paeth(self, a,b,c):
        p = a+b-c
        pa = abs(p - a)
        pb = abs(p - b)
        pc = abs(p - c)
        if pa <= pb and pa <= pc:
            Pr = a
        elif pb <= pc:
            Pr = b
        else:
            Pr = c
        return Pr
    def createArray(self):
        if self.colortype == 2:
            tmp = truecolorImageData(hght=self.height, wdth=self.width, bitdep=self.bitdep)
            self.pixwid = 3 * tmp.bytdep
        elif self.colortype == 6:
            tmp = tcwaImageData(hght=self.height, wdth=self.width, bitdep=self.bitdep)
            self.pixwid = 4 * tmp.bytdep
        else:
            raise Exception("Unimplemented Color Type")
        self.undwid = 1 + self.pixwid * self.width #"undone" width, the width of a filtered scanline in bytes.
        self.filters = [0]*self.height
        for i in range(self.height):
            #print(f"i: {i}",end="")
            self.filters[i] = self.imgdata[i*self.undwid]
            formy = ">" + str(self.width*self.pixwid) + tmp.form[2]
            tmpz = self.imgdata[(i*self.undwid)+1:(i+1)*self.undwid]
            #print(tmpz)
            try:
                tmp2 = struct.unpack(formy, tmpz)
            except:
                print(len(tmpz))
                tmp2 = struct.unpack(formy, tmpz)
            n = 0
            for nk in list(batched(tmp2,tmp.ne,strict=True)):
                tmp[i, n] = nk
                n = n+1
        self.imgdata = tmp
    def doDefilterZ(self):
        if self.colortype == 2:
            ra = 3
        elif self.colortype == 6:
            ra = 4
        if self.imgdata.bytdep != 1:
            raise Exception("Unimplemented bit depth.")
        for i in range(self.height):
            filtype = self.filters[i]
            tmp3 = []
            for j in range(self.width):
                for k in range(ra):
                    filt_byte = self.imgdata[i,j,k]
                    if j > 0:    
                        a = self.imgdata[i,j,k]
                    else:
                        a = 0
                match filtype:
                    case 0:
                        to_add = filt_byte
                    case 1:
                        to_add = (filt_byte + a)%256
                    case 2:
                        if i == 0:
                            b = b'\x00'
                        else:
                            b = self.imgdata[i-1,j,k]
                        to_add = (filt_byte + b)%256
                    case 3:
                        if i == 0:
                            b = b'\x00'
                        else:
                            b = self.imgdata[i-1,j,k]
                        to_add = (filt_byte + floor((a + b)/2))%256
                    case 4:
                        if i == 0:
                            b = b'\x00'
                            c = b'\x00'
                        else:
                            b = self.imgdata[i-1,j,k]
                            c = self.imgdata[i-1,j-1,k]
                        pp = self.paeth(a, b, c)
                        to_add = (filt_byte + pp)%256
                    case _:
                        raise Exception("Invalid Filter Type Spotted!")
                if len(tmp3) == 2 and self.colortype == 2:
                    tmp3.append(to_add)
                    self.imgdata[i, j] = tmp3
                    tmp3 = []
                elif len(tmp3) == 3 and self.colortype == 6:
                    tmp3.append(to_add)
                    self.imgdata[i, j] = tmp3
                    tmp3 = []
                else:
                    tmp3.append(to_add)
    def doDecompZ(self):
        self.imgdata = b''
        for i in self.idat_locs:
            self.imgdata += self.chunks[i].data
        try:
            dobj = zlib.decompressobj()
        except:
            print("Something went wrong with decompression. here are the first 16 bytes of the data.")
            print(self.imgdata[0:17])
        with open("zlibdata.dat","wb") as f:
            f.write(self.imgdata)
        tmp = dobj.decompress(self.imgdata)
        print("Unused image data that was not used for decompression: ",end="\n\t")
        print(dobj.unused_data)
        self.imgdata = tmp
    def add_chunk(self, le, typ, data, CRC):
        if typ in self.chunk_mapping:
            tmp = self.chunk_mapping[typ](le, data, CRC)
            self.chunks.append(tmp)
            if typ == b'IHDR':
                self.hd_loc = len(self.chunks) - 1 #IHDR Location
                self.colortype = self.chunks[self.hd_loc].colortype
            if typ == b'IDAT':
                self.idat_locs.append(len(self.chunks)-1)
            if typ in self.needs_ihdr:
                self.chunks[len(self.chunks)-1].moarInit(self.chunks[self.hd_loc])
            typ2 = self.chunks[len(self.chunks)-1].typ
            if typ2 not in self.chunk_locs.keys():
                self.chunk_locs[typ2] = [len(self.chunks)-1]
            else:
                self.chunk_locs[typ2].append(len(self.chunks)-1)
        else:
            raise Exception(f"Unimplemented Chunk Type {typ}")
    def do_plt_proc(self):
        match self.colortype:
            case 2:
                pass
            case 3:
                pass
            case 6:
                pass
    def do_recon(self):
        self.filtmeth = self.chunks[self.hd_loc].filtmeth
        self.compmeth = self.chunks[self.hd_loc].compmeth
        self.bitdep = self.chunks[self.hd_loc].bitdep
        self.width = self.chunks[self.hd_loc].width
        self.height = self.chunks[self.hd_loc].height
        if self.compmeth == 0:
            self.doDecompZ()
        else:
            raise Exception("Unimplemented Decompression Type")
        with open("uncomp_data.dat","wb") as f:
            f.write(self.imgdata)
        self.createArray()
        with open("arr.dat","w") as f:
            f.write(str(self.imgdata))
        if self.filtmeth == 0:
            self.doDefilterZ()
        else:
            raise Exception("Unimplemented Filter Method")
        with open("post_filt.dat","w") as f:
            f.write(str(self.imgdata))
    def chunk_check(self):
        last_chunk = ""
        for i in range(len(self.chunks)):
            match self.chunks[i].typ:
                case "IHDR":
                    if i != 0:
                        raise Exception("The IHDR Chunk has to come first!")
                case "PLTE":
                    self.plt_proc = True
                    if "IDAT" in self.chunk_count.keys():
                        raise Exception("The PLTE Chunk has to come before the first IDAT Chunk!")
                case "IDAT":
                    if "IDAT" in self.chunk_count.keys() and last_chunk != "IDAT":
                        raise Exception("All IDAT Chunks must be consecutive!")
                    if "IDAT" not in self.chunk_count.keys():
                        self.chunk_count["IDAT"] = 1
                    else:
                        self.chunk_count["IDAT"]+=1
                case "iCCP":
                    if "sRGB" in self.chunk_count.keys():
                        raise Exception("The iCCP and sRGB chunks should not both be present!")
                case "sRGB":
                    if "iCCP" in self.chunk_count.keys():
                        raise Exception("The iCCP and sRGB chunks should  not both be present!")
            if self.chunks[i].typ in ["cHRM", "gAMA", "iCCP", "sBIT", "sRGB"]:
                if ("PLTE" in self.chunk_count.keys() and "PLTE" in self.chunk_locs.keys()) or "IDAT" in self.chunk_count.keys():
                    raise Exception("The "+self.chunks[i].typ+" chunk must come before all PLTE and IDAT chunks!")
            if self.chunks[i].typ in ["bKGD", "hIST", "tRNS"]:
                if ("PLTE" not in self.chunk_count.keys() and "PLTE" in self.chunk_locs.keys()) or "IDAT" in self.chunk_count.keys():
                    raise Exception("The "+self.chunks[i].typ+" chunk must come before all IDAT chunks and after the PLTE chunk!")
            if self.chunks[i].typ in ["pHYs","sPLT"]:
                if "IDAT" in self.chunk_count.keys():
                    raise Exception("The "+self.chunks[i].typ+" chunk must come before all IDAT chunks!")
            if self.chunks[i].typ in ["IHDR", "PLTE", "IEND", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "bKGD", "hIST", "tRNS", "pHYs", "tIME"]:
                if self.chunks[i].typ in self.chunk_count.keys():
                    raise Exception("There can only be one "+self.chunks[i].typ+" chunk!")
                else:
                    self.chunk_count[self.chunks[i].typ] = 1
            last_chunk = self.chunks[i].typ
        if self.colortype == 3 and "PLTE" not in self.chunk_count.keys():
            raise Exception("There's no PLTE Chunk in this file and there really should be!")
        if "sRGB" in self.chunk_count.keys():
            if "gAMA" in self.chunk_count.keys():
                loc = self.chunk_locs["gAMA"][0] #Only one of each of the conditions permitted
                ch = self.chunks[loc] #See below note.
                if not (floor(ch.gamma*100000) == 45455 or ceil(ch.gamma*100000) == 45455):
                    print(f"gamma: {ch.gamma*100000}")
                    raise Exception("Invalid gamma value!")
            if "cHRM" in self.chunk_count.keys():
                loc = self.chunk_locs["cHRM"][0] #Only one of each of the conditions permitted
                ch = self.chunks[loc] #Note: unsure if these are the values present in the file or if they are the values represented by the chunks. If it's the former, the current setup will incorrectly raise an exception. if this happens, don't freak out, just check what the actual values in the file are and change these if statements accordingly.)
                if not (floor(ch.wpx*100000) == 31270 or ceil(ch.wpx*100000) == 31270) or not (floor(ch.wpy*100000) == 32900 or ceil(ch.wpx*100000) == 32900):
                    raise Exception("Invalid whitepoint value!")
                if not (floor(ch.rx*100000) == 6400 or ceil(ch.rx*100000) == 6400) or not (floor(ch.ry*100000) == 33000 or ceil(ch.ry*100000) == 33000):
                    raise Exception("Invalid red value!")
                if not (floor(ch.gx*100000) == 30000 or ceil(ch.gx*100000) == 30000) or not (floor(ch.gy*100000) == 60000 or ceil(ch.gy*100000) == 60000):
                    raise Exception("Invalid green value!")
                if not (floor(ch.bx*100000) == 15000 or ceil(ch.bx*100000) == 15000) or not (floor(ch.by*100000) == 6000 or ceil(ch.by*100000) == 6000):
                    raise Exception("Invalid blue value!")
parser = argparse.ArgumentParser()

parser.add_argument('-i', '--file', help='Path to the input file', required=True)

args = parser.parse_args()

file = open(args.file,"rb")

tmp = file.read(8)
if tmp != b'\x89PNG\r\n\x1a\n':
    print("Uh oh!")
    print(tmp)
    raise Exception("This isn't a PNG file!")

im = Image()
while file.readable() and len(file.peek()) > 0:
    tmp = file.read(8)
    le = struct.unpack(">I",tmp[0:4])[0]
    typ = tmp[4:]
#    print(typ)
    dat = file.read(le)
    CRC = file.read(4)
    im.add_chunk(le,typ,dat,CRC)

file.close()
im.chunk_check()
im.do_recon()


if im.plt_proc:
    im.do_plt_proc()

