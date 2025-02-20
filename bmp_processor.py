import struct
#import numpy as np

# Citation in case I ever decide to upload to Github: https://en.wikipedia.org/wiki/BMP_file_format
# Another citation: https://www.digicamsoft.com/bmp/bmp.html
class DIB_Header:
    rinfo = {} #Readable information (much more detailed, intended for printing.)
    info = {} #Useable information (much less detailed, intended for utilization in code.)
    oss = None
    feat = None

    def __init__(self):
        if oss is not None: self.setAttr("Image OS_Support", oss)
        if feat is not None: self.setAttr("Image Version Features", feat)
    def setAttr(self, label, data, uselabel = None):
        self.rinfo[label] = data
        if uselabel is not None:
            self.info[uselabel] = data
    def __str__(self):
        builder = ""
        for i in self.rinfo:
            builder = builder + str(i)
            builder = builder + " : "
            builder = builder + str(self.rinfo[i])
            builder = builder + "\n"
        return builder
class BITMAPCOREHEADER(DIB_Header):
    oss = 'Windows 2.0 or later.'

class OS21XBITMAPHEADER(BITMAPCOREHEADER):
    oss = "OS/2 1.x"

class OS22XBITMAPHEADER(DIB_Header):
    oss = "OS/2 BITMAPCOREHEADER2"
    feat = "Adds halftoning. Adds RLE and Huffman 1D compression." 

class OS22XBITMAPHEADERv2(OS22XBITMAPHEADER):
    pass

class BITMAPINFOHEADER(DIB_Header):
    oss = 'Windows NT, 3.1x or later.'
    feat = "Extends bitmap width and height to 4 bytes. Adds 16 bpp and 32 bpp formats. Adds RLE compression."
    def __init__(self):
        super().__init__()
    def setComp(self, comp):
        self.setAttr("Compression Method",comp,uselabel="comp_meth")

class BITMAPV2INFOHEADER(DIB_Header):
    oss = "Undocumented"
    feat = "Adds RGB bit masks."

class BITMAPV3INFOHEADER(DIB_Header):
    oss = "Not officially documented, but this documentation was posted on Adobe's forums, by an employee of Adobe with a statement that the standard was at one point in the past included in official MS documentation."
    feat = "Adds alpha channel bit mask."

class BITMAPV4HEADER(DIB_Header):
    oss = "Windows NT 4.0, 95 or later"
    feat = "Adds color space type and gamma correction"

class BITMAPV5HEADER(DIB_Header):
    oss = "Windows NT 5.0, 98 or later"
    feat = "Adds ICC color profiles"

class BitMapImage:
    header_info = {}
    dib_info = {}
    dib = None
    image_data = None

def process_header(header, im):
    im.header_info["header"] = header[0:2] 
    print(b"Header field: " + header[0:2])
    if header[0:2] not in [b"BM",b"BA",b"CI",b"CP",b"IC",b"PT"]:
        raise Exception("Unknown BMP file format. Are you sure this is a bitmap image?")
    filesize = struct.unpack("<I",header[2:6])
    im.header_info["filesize"] = filesize[0]
    print("Size of the BMP file in bytes: "+str(filesize[0]) )
    junk = header[6:10]
    print(b"Some junk data, might be zero but doesn't have to be: "+junk)
    addr = struct.unpack("<I",header[10:14])[0]
    im.header_info["image_start_addr"] = addr
    print("Starting address of bitmap image data: "+str(addr))

def process_dib(dib, im):
    print("DIB Header Size: "+str(im.dib_info["size"]))
    if im.dib_info["size"] == 12:
        im.dib_info["type"] = "BITMAPCOREHEADER"
        im.dib = BITMAPCOREHEADER()
    if im.dib_info["size"] == 40:
        im.dib_info["type"] = "BITMAPINFOHEADER"
        im.dib = BITMAPINFOHEADER()
        size = []
        for i in struct.iter_unpack("<I",dib[0:8]):
            size.append(i[0])
        im.dib.setAttr("Bitmap width in pixels", size[0], uselabel="pix_width")
        im.dib.setAttr("Bitmap height in pixels",size[1], uselabel="pix_height")
        tmp = []
        for i in struct.iter_unpack("<H",dib[8:12]):
            tmp.append(i[0])
        if tmp[0] != 1:
            raise Exception("We've got an invalid bmp file!!! The number of color planes specified is a different number than expected (1).")
        im.dib.setAttr("Number of Color Planes",tmp[0], uselabel="color_planes")
        im.dib.setAttr("Color Depth (number of bits per pixel)",tmp[1], uselabel="color_depth")
        if tmp[1] != 1 and tmp[1] != 4 and tmp[1] != 8 and tmp[1] != 16 and tmp[1] != 24 and tmp[1] != 32:
            print(f"\nFancy! We've got an unusual color depth of {tmp[1]}")
        tmp = []
        for i in struct.iter_unpack("<I",dib[12:20]):
            tmp.append(i[0])
        comp_meth = None
        match tmp[0]:
            case 0:
                im.dib.setComp("BI_RGB")
            case 1:
                im.dib.setComp("BI_RLE8")
            case 2:
                im.dib.setComp("BI_RLE4")
            case 3:
                im.dib.setComp("BI_BITFIELDS")
            case 4:
                im.dib.setComp("BI_JPEG")
            case 5:
                im.dib.setComp("BI_PNG")
            case 6:
                im.dib.setComp("BI_ALPHABITFIELDS")
            case 11:
                im.dib.setComp("BI_CMYK")
            case 12:
                im.dib.setComp("BI_CMYKRLE8")
            case 13:
                im.dib.setComp("BI_CMYKRLE4")
            case _:
                raise Exception("Unsupported Compression Method")
                im.dib.setComp("Unknown")
        im.dib.setAttr("Size of raw bitmap data",tmp[1],uselabel="raw_size")
        tmp = []
        for i in struct.iter_unpack("<i",dib[20:28]):
            tmp.append(i[0])
        im.dib.setAttr("Horizontal resolution of the image in pixels per meter",tmp[0],uselabel="xppm")
        im.dib.setAttr("Vertical resolution of the image in pixels per meter",tmp[1],uselabel="yppm")
        tmp = []
        for i in struct.iter_unpack("<I",dib[28:]):
            tmp.append(i[0])
        if tmp[0] == 0 and im.dib_info["size"]+14 == im.header_info["image_start_addr"]:
            im.dib.setAttr("Number of colors in the color palette",0, uselabel="num_pal")
        elif tmp[0] == 0:
            im.dib.setAttr("Number of colors in the color palette",2**im.dib.info["color_depth"],uselabel="num_pal")
        else:
            im.dib.setAttr("Number of colors in the color palette",tmp[0],uselabel="num_pal")
        im.dib.setAttr("Number of important colors used",tmp[1])
    else:
        raise Exception("This specific type of DIB is not yet implemented.")

def process_data(im, data):
    im.image_data = 1

file = open(input("file?"),"rb")

header = file.read(14)
im = BitMapImage()

process_header(header,im)
im.dib_info["size"] = struct.unpack("<I", file.read(4))[0]

dib = file.read(im.dib_info["size"]-4)
process_dib(dib, im)

data = None
if im.dib.info["comp_meth"] == "BI_RGB":
    data = file.read(im.dib.info["raw_size"])
else:
    raise Exception("The compression method used in this file is not yet implemented.")

process_data(im, data)

print("Header Information: " + str(im.header_info))
print("DIB Information obtained from the Header: " + str(im.dib_info))
print("DIB Information obtained from the DIB itself: " + str(im.dib))
file.close()

