#!/usr/bin/python3
"""
Dissect a redbend/quectel EC20 system.diff
All rights reversed
"""

import sys
import struct
import io
import binascii
import lzma
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
    rstr = io.BytesIO(upd[len(fs_hdr):])
    ram_size = struct.unpack("<I", rstr.read(4))[0]
    sec_size = struct.unpack("<I", rstr.read(4))[0]
    dic_size = struct.unpack("<I", rstr.read(4))[0]
    com_size = struct.unpack("<I", rstr.read(4))[0]
    min_allo = struct.unpack("<H", rstr.read(2))[0]
    inf_size = struct.unpack("<H", rstr.read(2))[0]
    num_copy = struct.unpack("<H", rstr.read(2))[0]
    num_diff = struct.unpack("<H", rstr.read(2))[0]
    num_inse = struct.unpack("<H", rstr.read(2))[0]
    num_dele = struct.unpack("<H", rstr.read(2))[0]
    num_ddir = struct.unpack("<H", rstr.read(2))[0]
    num_dirs = struct.unpack("<H", rstr.read(2))[0]
    num_dlnk = struct.unpack("<H", rstr.read(2))[0]
    num_link = struct.unpack("<H", rstr.read(2))[0]
    num_cupd = struct.unpack("<H", rstr.read(2))[0]
    num_cins = struct.unpack("<H", rstr.read(2))[0]
    print("Delta Info: delta_size - %d" % (len(upd)+8))
    print("Delta Info: ver - ???")
    print("Delta Info: scout_ver - ???")
    print("Delta Info: flags - ???")
    print("Delta Info: runtype_flags - ???")
    print("Delta Info: ram_size - 0x%x" % ram_size)
    print("Delta Info: sector_size - 0x%x" % sec_size)
    print("Delta Info: dic_sz - 0x%x" % dic_size)
    print("Delta Info: compress_sz - 0x%x" % com_size)
    print("Delta Info: min_alloc_ram_use - 0x%x" % min_allo)
    print("Delta Info: ext_info_sz - %d" % inf_size)
    print("Delta Info: num_copy - %d" % num_copy)
    print("Delta Info: num_diff - %d" % num_diff)
    print("Delta Info: num_insert - %d" % num_inse)
    print("Delta Info: num_delete - %d" % num_dele)
    print("Delta Info: num_del_dirs - %d" % num_ddir)
    print("Delta Info: num_dirs - %d" % num_dirs)
    print("Delta Info: num_del_link - %d" % num_dlnk)
    print("Delta Info: num_link - %d" % num_link)
    print("Delta Info: num_critical_update - %d" % num_cupd)
    print("Delta Info: num_critical_insert - %d" % num_cins)

    # dump it temporarily
    d = rstr.read()
    with open("foo.bin", "wb") as f:
        f.write(d)

    # parse the index area...
    rstr = io.BytesIO(d)
    idx_len = (8 * num_diff) + (4 * num_inse)
    idx = rstr.read(idx_len)
    assert len(idx) == idx_len

    # decompress that file table...
    compr = lzma.LZMADecompressor()
    d = compr.decompress(rstr.read())
    print(d)
    print(hexstring(compr.unused_data))

    # XXX... how long is the _rest_ how to index

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

