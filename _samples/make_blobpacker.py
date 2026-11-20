"""DiE Helper (fork addition): build toy "blob packer" samples for the static decompressor/rebuilder.

usage: python -I make_blobpacker.py <samples dir>

From hello64.exe it writes
  blobpacker_zlib64.exe   .text compressed with zlib (RFC 1950 stream, zlib.compress level 9)
  blobpacker_lzma64.exe   .text compressed with LZMA "alone" (13-byte header: props, dict size, size = -1, end marker)

Layout of both outputs:
  .text  keeps its RVA and VirtualSize, but becomes virtual-only (PointerToRawData = SizeOfRawData = 0) and RWX
  .blob  new section, the compressed .text at offset 0
  .stub  new section, the entry point:  lea rsi,[rip+blob] / lea rdi,[rip+.text] / mov ecx,size / mov edx,vsize / jmp OEP
The stub does NOT decompress anything: the files are NOT runnable and must never be executed. They only have to look
like a packed file to the static tools (blob reachable from the EP, high-entropy section, jmp rel32 to the OEP).
Only the standard library is used; nothing is executed.
"""
import lzma
import os
import struct
import sys
import zlib


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def pe_checksum(data, checksum_offset):
    total = 0
    size = len(data)
    padded = bytes(data) + (b"\0" if size % 2 else b"")
    for i in range(0, len(padded), 2):
        if i == checksum_offset or i == checksum_offset + 2:
            continue
        total += padded[i] | (padded[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


class Pe:
    def __init__(self, data):
        self.data = data
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        self.nsec = struct.unpack_from("<H", data, self.e_lfanew + 6)[0]
        self.opt_size = struct.unpack_from("<H", data, self.e_lfanew + 20)[0]
        self.opt = self.e_lfanew + 24
        magic = struct.unpack_from("<H", data, self.opt)[0]
        if magic != 0x20B:
            raise ValueError("expected a PE32+ (64-bit) file")
        self.sec_table = self.opt + self.opt_size
        self.dd = self.opt + 112  # PE32+ data directories
        self.sections = []
        for i in range(self.nsec):
            off = self.sec_table + i * 40
            name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", data, off)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append({"name": name.rstrip(b"\0"), "vsize": vsize, "va": va, "rsize": rsize, "rptr": rptr, "chars": chars})

    def u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]) and rva - s["va"] < s["rsize"]:
                return s["rptr"] + rva - s["va"]
        return None


def build(src_data, compress, out_path, label):
    pe = Pe(src_data)
    file_align = pe.u32(pe.opt + 36)
    sec_align = pe.u32(pe.opt + 32)
    size_of_headers = pe.u32(pe.opt + 60)
    oep_rva = pe.u32(pe.opt + 16)
    image_base = struct.unpack_from("<Q", src_data, pe.opt + 24)[0]

    text_index = next(i for i, s in enumerate(pe.sections) if s["name"] == b".text")
    text = pe.sections[text_index]
    text_bytes = bytes(src_data[text["rptr"]:text["rptr"] + min(text["rsize"], text["vsize"])])
    text_bytes += b"\0" * (text["vsize"] - len(text_bytes))
    blob = compress(text_bytes)

    if pe.sec_table + (pe.nsec + 2) * 40 > size_of_headers:
        raise ValueError("no room for two more section headers")

    # Debug directory entries hold FILE offsets (PointerToRawData): read them before anything moves.
    debug_rva, debug_size = struct.unpack_from("<II", src_data, pe.dd + 6 * 8)
    debug_entries = []
    if debug_rva and debug_size:
        debug_off = pe.rva_to_offset(debug_rva)
        if debug_off is not None:
            for i in range(debug_size // 28):
                debug_entries.append((debug_rva + i * 28, struct.unpack_from("<I", src_data, debug_off + i * 28 + 24)[0]))
    if struct.unpack_from("<II", src_data, pe.dd + 4 * 8) != (0, 0):
        raise ValueError("signed input is not supported (security directory present)")

    # 1) headers, 2) every section except .text, re-laid out in the original file order
    out = bytearray(src_data[:size_of_headers])
    out += b"\0" * (align(len(out), file_align) - len(out))
    old_to_new = []  # (old_ptr, old_size, new_ptr)
    order = sorted((i for i, s in enumerate(pe.sections) if s["rsize"]), key=lambda i: pe.sections[i]["rptr"])
    new_ptr = {}
    for i in order:
        s = pe.sections[i]
        if i == text_index:
            continue
        raw = bytes(src_data[s["rptr"]:s["rptr"] + s["rsize"]])
        new_ptr[i] = len(out)
        old_to_new.append((s["rptr"], s["rsize"], len(out)))
        out += raw + b"\0" * (align(len(raw), file_align) - len(raw))

    last_end_va = max(s["va"] + s["vsize"] for s in pe.sections)
    blob_va = align(last_end_va, sec_align)
    blob_ptr = len(out)
    out += blob + b"\0" * (align(len(blob), file_align) - len(blob))
    stub_va = align(blob_va + len(blob), sec_align)

    # stub: lea rsi,[rip+blob]; lea rdi,[rip+.text]; mov ecx,len(blob); mov edx,text vsize; jmp rel32 OEP; int3 padding
    stub = bytearray()
    stub += b"\x48\x8D\x35" + struct.pack("<i", blob_va - (stub_va + len(stub) + 7))
    stub += b"\x48\x8D\x3D" + struct.pack("<i", text["va"] - (stub_va + len(stub) + 7))
    stub += b"\xB9" + struct.pack("<I", len(blob))
    stub += b"\xBA" + struct.pack("<I", text["vsize"])
    stub += b"\xE9" + struct.pack("<i", oep_rva - (stub_va + len(stub) + 5))
    stub += b"\xCC" * (0x40 - len(stub))
    stub_ptr = len(out)
    out += stub + b"\0" * (align(len(stub), file_align) - len(stub))

    # section table
    for i, s in enumerate(pe.sections):
        off = pe.sec_table + i * 40
        if i == text_index:
            struct.pack_into("<II", out, off + 16, 0, 0)       # SizeOfRawData, PointerToRawData
            struct.pack_into("<I", out, off + 36, 0xE0000020)  # code, RWX (the stub would write it)
        elif i in new_ptr:
            struct.pack_into("<I", out, off + 20, new_ptr[i])
    hdr = pe.sec_table + pe.nsec * 40
    out[hdr:hdr + 40] = struct.pack("<8sIIIIIIHHI", b".blob", len(blob), blob_va, align(len(blob), file_align), blob_ptr, 0, 0, 0, 0, 0x40000040)
    out[hdr + 40:hdr + 80] = struct.pack("<8sIIIIIIHHI", b".stub", len(stub), stub_va, align(len(stub), file_align), stub_ptr, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<H", out, pe.e_lfanew + 6, pe.nsec + 2)
    struct.pack_into("<I", out, pe.opt + 16, stub_va)                             # AddressOfEntryPoint
    struct.pack_into("<I", out, pe.opt + 56, align(stub_va + len(stub), sec_align))  # SizeOfImage
    struct.pack_into("<I", out, pe.e_lfanew + 12, 0)                              # PointerToSymbolTable
    struct.pack_into("<I", out, pe.e_lfanew + 16, 0)                              # NumberOfSymbols

    # debug directory PointerToRawData (file offsets) follow their section
    new_pe = Pe(out)
    for entry_rva, old_ptr in debug_entries:
        entry_off = new_pe.rva_to_offset(entry_rva)
        if entry_off is None or old_ptr == 0:
            continue
        for o_ptr, o_size, n_ptr in old_to_new:
            if o_ptr <= old_ptr < o_ptr + o_size:
                struct.pack_into("<I", out, entry_off + 24, n_ptr + old_ptr - o_ptr)
                break

    struct.pack_into("<I", out, pe.opt + 64, 0)
    struct.pack_into("<I", out, pe.opt + 64, pe_checksum(out, pe.opt + 64))
    with open(out_path, "wb") as f:
        f.write(out)

    print("wrote %s (%s): .blob 0x%X bytes at RVA 0x%X (file 0x%X), stub RVA 0x%X" % (os.path.basename(out_path), label, len(blob), blob_va, blob_ptr, stub_va))
    return oep_rva, image_base, text


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    d = sys.argv[1]
    src = os.path.join(d, "hello64.exe")
    with open(src, "rb") as f:
        data = bytearray(f.read())

    oep_rva, image_base, text = build(data, lambda b: zlib.compress(b, 9), os.path.join(d, "blobpacker_zlib64.exe"), "zlib")
    build(data, lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE), os.path.join(d, "blobpacker_lzma64.exe"), "lzma alone")

    print("original OEP: RVA 0x%X, VA 0x%X" % (oep_rva, image_base + oep_rva))
    print(".text: RVA 0x%X, VirtualSize 0x%X, original SizeOfRawData 0x%X" % (text["va"], text["vsize"], text["rsize"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
