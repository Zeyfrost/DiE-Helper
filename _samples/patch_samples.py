"""Derive test variants from already-built samples (byte patching only; nothing is executed).

usage: python -I patch_samples.py <samples dir>
  hello32_upx_renamed.exe     UPX0/UPX1 renamed to abc0/abc1        -> custom DB rule "UPX (renamed sections)"
  hello_dll64_upx_renamed.dll same for the 64-bit DLL
  hello64_upx_scrambled.exe   sections renamed + "UPX!" magic wiped -> simulates an unknown/modified packer
"""
import os
import struct
import sys


def rename_sections(data, mapping):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec = e_lfanew + 24 + opt_size
    for i in range(nsec):
        off = sec + i * 40
        name = bytes(data[off:off + 8]).rstrip(b"\0")
        if name in mapping:
            data[off:off + 8] = mapping[name].ljust(8, b"\0")


def wipe_magic(data):
    count = 0
    pos = data.find(b"UPX!")
    while pos != -1:
        data[pos:pos + 4] = b"\0\0\0\0"
        count += 1
        pos = data.find(b"UPX!", pos + 4)
    return count


def make(src, dst, rename=True, wipe=False):
    data = bytearray(open(src, "rb").read())
    if rename:
        rename_sections(data, {b"UPX0": b"abc0", b"UPX1": b"abc1", b"UPX2": b"abc2"})
    if wipe:
        wipe_magic(data)
    open(dst, "wb").write(data)
    print("wrote", os.path.basename(dst))


def append_section(data, name, payload, characteristics, virtual_size=None):
    """Append a section header + raw data at the end of the file (no overlay expected) and fix
    NumberOfSections / SizeOfImage. Raw data is padded to FileAlignment. Returns the new section's RVA.
    Shared with make_toypacker.py."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    sec_align = struct.unpack_from("<I", data, opt + 32)[0]
    file_align = struct.unpack_from("<I", data, opt + 36)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    sec_table = opt + opt_size
    last = sec_table + (nsec - 1) * 40
    last_va, last_vs = struct.unpack_from("<I", data, last + 12)[0], struct.unpack_from("<I", data, last + 8)[0]
    align = lambda v, a: (v + a - 1) // a * a
    hdr = sec_table + nsec * 40
    if hdr + 40 > size_of_headers or any(data[hdr:hdr + 40]):
        raise ValueError("no free room for another section header")
    if virtual_size is None:
        virtual_size = len(payload)
    new_va = align(last_va + last_vs, sec_align)
    raw = payload + b"\0" * (align(len(payload), file_align) - len(payload))
    raw_off = align(len(data), file_align)
    data += b"\0" * (raw_off - len(data)) + raw
    data[hdr:hdr + 40] = struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\0"), virtual_size, new_va, len(raw), raw_off, 0, 0, 0, 0, characteristics)
    struct.pack_into("<H", data, e_lfanew + 6, nsec + 1)
    struct.pack_into("<I", data, opt + 56, align(new_va + virtual_size, sec_align))  # SizeOfImage
    return new_va


def make_fake_packed(src, dst):
    """Mimic an unknown packer: append an RWX section full of random bytes and move the EP into it.
    The file is NOT runnable - it only has to look packed to a static scanner."""
    import random
    data = bytearray(open(src, "rb").read())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt = e_lfanew + 24
    rnd = random.Random(1234)
    payload = bytes(rnd.getrandbits(8) for _ in range(0x10000))
    new_va = append_section(data, b".pk", payload, 0xE0000020)
    struct.pack_into("<I", data, opt + 16, new_va + 0x80)  # AddressOfEntryPoint inside the random blob
    open(dst, "wb").write(data)
    print("wrote", os.path.basename(dst))


def main():
    d = sys.argv[1]
    make(os.path.join(d, "hello32_upx.exe"), os.path.join(d, "hello32_upx_renamed.exe"))
    make(os.path.join(d, "hello_dll64_upx.dll"), os.path.join(d, "hello_dll64_upx_renamed.dll"))
    make(os.path.join(d, "hello64_upx.exe"), os.path.join(d, "hello64_upx_scrambled.exe"), wipe=True)
    make_fake_packed(os.path.join(d, "hello64.exe"), os.path.join(d, "hello64_unknownpacker.exe"))


if __name__ == "__main__":
    main()
