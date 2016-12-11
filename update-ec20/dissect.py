#!/usr/bin/python3
"""
Dissect a redbend/quectel EC20 system.diff
All rights reversed
"""

import sys
import struct
import io
import binascii
from PyCRC import CRC32

# initialize the tables once
crc32 = CRC32.CRC32()

def hexstring(array):
    return "".join(map(lambda b: format(b, "02x"), array))

filename = sys.argv[1]
print("Working on {}".format(filename))

data = open(filename, 'rb').read()
rstr = io.BytesIO(data)


# A chunk ....
# 32bit crc32 checksum
# 32bit len
# len-8 bytes of data..
# 0-3 bytes padding to the next chunk but not at the end
# of thr file and not accounted for in the len. See the
# dsp2.diff as an example?

# Parse the chunk..
checksum = rstr.read(4)
blen = rstr.read(4)
flen = struct.unpack("<I", blen)[0]
chunk1 = rstr.read(flen - 8)

print("Guessing CRC to match {} {}".format(
        struct.unpack("<I", checksum)[0],
        crc32.calculate(blen+chunk1)))

# read padding
if len(chunk1) % 4 > 0:
    rstr.read(4 - (len(chunk1) % 4))

# Parse the trailer
t_chksum = rstr.read(4)
t_blen = rstr.read(4)
t_flen = struct.unpack("<I", t_blen)[0]
t_chnk = rstr.read(t_flen - 8)
assert len(t_chnk) == t_flen - 8

print("Guessing CRC to match {} {}".format(
        struct.unpack("<I", t_chksum)[0],
        crc32.calculate(t_blen+t_chnk)))
print(len(t_chnk)%4)
trailer = rstr.read()
print("REST {} {}".format(len(trailer), hexstring(trailer)))

#wanted_le = struct.unpack("<I", checksum)[0]
#wanted_be = struct.unpack(">I", checksum)[0]
#for i in range(0, len(data)):
#    for j in range(0, len(data)):
#        crc = crc32.calculate(data[i:j])
#        if crc == wanted_le or wanted_be == crc:
#            print("Got it with {} {}".format(i, j))
