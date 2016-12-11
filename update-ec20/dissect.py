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

common_hdr = b'\x50\x40\x01\x00\x80\x38\x01\x00\x00\x00\x00'
fs_hdr     = common_hdr + b'\x80\x80\x02\x00\x00'

def dissect_upgrade(upd):
    """
    50 40 01 00 80 38 01 00 00 00 00 80 -- general header...

    The specific header...followed after fs_hdr
c8000200 -- ram size
00000400 -- sector size
c80d0000 -- dic_sz
b5040000 -- compress_sz
22000200 -- 0x22 min_alloc_ram_use | ext_info_sz 2
00005f00 -- 0x0000=num_copy 0x5f00==num_diff
03000000 -- 0x0300=num_insert 0x000==num_delete
00000000 -- 0x0000=num_delete_dirs 0x0000==num_dirs
00000400 -- 0x0000=num_del_link 0x0400=num_link
5f000300 -- 0x5f00=num_cri_update .. 0x0300=num_crit_inser
lzma now?

    """
    if fs_hdr != upd[0:len(fs_hdr)]:
        print("No fs type update with type: 0x%.2x" % upd[12])
        return 0
    assert fs_hdr == upd[0:len(fs_hdr)]
    upd_hdr = upd[len(fs_hdr):64]
    upd_dat = upd[64:]
    print(hexstring(upd_hdr))
    #print(hexstring(upd_dat))

# Parse the chunk..
checksum = rstr.read(4)
blen = rstr.read(4)
flen = struct.unpack("<I", blen)[0]
chunk1 = rstr.read(flen - 8)
assert struct.unpack("<I", checksum)[0] == crc32.calculate(blen+chunk1)
assert chunk1[0:len(common_hdr)] == common_hdr
dissect_upgrade(chunk1)

# read padding
if len(chunk1) % 4 > 2:
    rstr.read(4 - (len(chunk1) % 4))

# Parse the trailer
t_chksum = rstr.read(4)
t_blen = rstr.read(4)
t_flen = struct.unpack("<I", t_blen)[0]
t_chnk = rstr.read(t_flen - 8)
assert len(t_chnk) == t_flen - 8
assert  struct.unpack("<I", t_chksum)[0] == crc32.calculate(t_blen+t_chnk)
assert t_chnk[0:len(common_hdr)] == common_hdr

trailer = rstr.read()
assert len(trailer) == 0

