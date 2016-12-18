#!/usr/bin/python3
"""
Build a single insert for RedBend OTA filesystem updates
All rights reversed
"""

from PyCRC import CRC32
import subprocess
import os
import io
import struct

permission_bytes = bytes.fromhex('1A 5F 72 65 64 62 65 6E 64 5F 30 34 30 37 35 35 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 30 34 31 37 37 37 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 30 34 32 37 35 35 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 31 30 30 36 34 34 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 31 30 30 37 35 35 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 31 30 30 37 37 37 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 31 30 34 37 35 35 3A 30 30 30 30 3A 30 30 30 30 00 1A 5F 72 65 64 62 65 6E 64 5F 31 32 30 37 37 37 3A 30 30 30 30 3A 30 30 30 30 00')
general_bytes = bytes.fromhex('50 40 01 00 80 38 01 00 00 00 00')
fs_bytes     = bytes.fromhex('80 80 02 00 00 ')

# initialize tables only once
crc32 = CRC32.CRC32()

def compress(fname):
    """I compress a file with LZMA and return the byte array"""
    lzma_fname = fname + ".lzma"
    print(lzma_fname)
    ret = subprocess.call(["lzma", "e", fname, lzma_fname])
    assert ret == 0
    with open(lzma_fname, "rb") as f:
        return f.read()

def build_toc(fname, size, compr_size):
    """I build the table of content for a single file and insert"""
    wr = io.BytesIO()
    # name + NUL
    wr.write(fname.encode('utf8'))
    wr.write(b'\0')
    # permissions
    wr.write(permission_bytes)
    # FILE_SIZE  + D100 0000 (offset to permission) + COMPR_SIZE
    off = len(wr.getvalue())
    wr.write(struct.pack('<I', size))
    wr.write(b'\xD1\x00\x00\x00')
    wr.write(struct.pack('<I', compr_size))
    return off, wr.getvalue()

def build_delta(num_insert, toc, offset, data):
    """I build the delta with the header, checksum, length, toc,
    offsets and the data"""

    hdr = io.BytesIO()
    hdr.write(general_bytes)
    hdr.write(fs_bytes)
    hdr.write(b'\xc8\x00\x02\x00') # ram size
    hdr.write(b'\x00\x00\x04\x00') # sector size
    hdr.write(struct.pack('<I', offset))
    hdr.write(struct.pack('<I', len(toc)))
    hdr.write(b'\x22\x00\x02\x00') # min_alloc_ram_use | ext_info_sz
    hdr.write(struct.pack('<H', 0)) # num_copy
    hdr.write(struct.pack('<H', 0)) # num_diff

    hdr.write(struct.pack('<H', num_insert)) # num_inser
    hdr.write(struct.pack('<H', 0)) # num_delete

    hdr.write(struct.pack('<H', 0)) # num_delete_dirs
    hdr.write(struct.pack('<H', 0)) # num_dirs

    hdr.write(struct.pack('<H', 0)) # num_del_link
    hdr.write(struct.pack('<H', 0)) # num_link

    hdr.write(struct.pack('<H', 0)) # num_cri_update
    hdr.write(struct.pack('<H', num_insert)) # num_crit_insert

    for i in range(0, num_insert):
        hdr.write(b'\x33\xC3\xC3\x33') # crc of the target file?

    combined = hdr.getvalue() + toc + data
    wr = io.BytesIO()
    wr.write(struct.pack("<I", len(combined) + 8))
    wr.write(combined)

    with_csum = io.BytesIO()
    with_csum.write(struct.pack("<I", crc32.calculate(wr.getvalue())))
    with_csum.write(wr.getvalue())
    return with_csum.getvalue()

def build_filenames(name):
    """I build a filenames table including the name"""
    wr = io.BytesIO()
    wr.write(general_bytes)
    wr.write(bytes.fromhex('00 00 03 00 00 01 00 00 00')) # never different
    wr.write(struct.pack('<I', len(name) + 1))
    wr.write(name.encode('utf8'))
    wr.write(b'\x00')
    wr.write(struct.pack('<I', 0))

    hdr = io.BytesIO()
    hdr.write(struct.pack("<I", len(wr.getvalue()) + 8))
    hdr.write(wr.getvalue())

    with_csum = io.BytesIO()
    with_csum.write(struct.pack("<I", crc32.calculate(hdr.getvalue())))
    with_csum.write(hdr.getvalue())
    return with_csum.getvalue()

def assemble(delta, filenames):
    """I put delta and filenamestable together.. I might add padding
    if the rule is understood correctly"""
    return delta + filenames


name = "system"
fname = "/bin/hello_world.sh"
fpath = "hello_world.sh"
flen = os.stat(fpath).st_size
fdata = compress(fpath)
(offset,toc) = build_toc(fname, flen, len(fdata))
with open("build_toc.bin", "wb") as f:
    f.write(toc)
toc_compr = compress("build_toc.bin")
delta = build_delta(1, toc_compr, offset, fdata)
namet = build_filenames(name)
update = assemble(delta, namet)
print(namet.hex())

with open(name + ".diff", "wb") as f:
    f.write(update)
