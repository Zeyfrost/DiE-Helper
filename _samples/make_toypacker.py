"""Toy packer for the OEP finder tests (byte patching only; nothing is executed).

usage: python -I make_toypacker.py <samples dir>
  toypacker32.exe          hello32.exe, .text XOR-encrypted, stub in ".toy": pushad .. popad; jmp rel32 OEP
  toypacker32_pushret.exe  same, stub ends with push OEP; ret
  toypacker64.exe          hello64.exe, .text XOR-encrypted, stub: push rsi/rcx .. pop rcx/rsi; jmp rel32 OEP

Each output gets: .text raw data XOR-ed with a 1-byte key, .text made writable, a new ".toy" section
holding a hand-assembled decryption stub, the EP moved to the stub, and DYNAMICBASE cleared (the
x86 stub uses absolute addresses, and relocations must not be applied to encrypted .text bytes).
The script then re-parses every output and checks the headers and the stub bytes statically.
"""
import importlib.util
import os
import struct
import sys

KEY = 0xA5  # 1-byte XOR key

IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CODE_RX = 0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040


def load_patch_samples():
    """Import patch_samples.py from this script's folder by absolute path (works under python -I)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch_samples.py")
    spec = importlib.util.spec_from_file_location("patch_samples", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_pe(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if is64 else struct.unpack_from("<I", data, opt + 28)[0]
    sections = []
    sec_table = opt + opt_size
    for i in range(nsec):
        off = sec_table + i * 40
        name, vs, va, rs, ro = struct.unpack_from("<8sIIII", data, off)
        ch = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({"name": name.rstrip(b"\0"), "vs": vs, "va": va, "rs": rs, "ro": ro, "ch": ch, "hdr": off})
    return {
        "opt": opt,
        "is64": is64,
        "image_base": image_base,
        "ep": struct.unpack_from("<I", data, opt + 16)[0],
        "size_of_image": struct.unpack_from("<I", data, opt + 56)[0],
        "dll_characteristics": struct.unpack_from("<H", data, opt + 70)[0],
        "sections": sections,
    }


def find_section(pe, name):
    for section in pe["sections"]:
        if section["name"] == name:
            return section
    raise ValueError("section %r not found" % name)


def stub_x86(stub_va, text_va, size, oep_va, pushret):
    """32-bit stub. All addresses are absolute VAs (DYNAMICBASE is cleared)."""
    code = bytearray()
    code += b"\x60"                                  # pushad                       save all GPRs
    code += b"\xBE" + struct.pack("<I", text_va)     # mov esi, text_va             start of encrypted .text
    code += b"\xB9" + struct.pack("<I", size)        # mov ecx, size                bytes to decrypt
    loop = len(code)
    code += b"\x80\x36" + bytes([KEY])               # L: xor byte ptr [esi], KEY
    code += b"\x46"                                  # inc esi
    rel8 = loop - (len(code) + 2)
    code += b"\xE2" + struct.pack("<b", rel8)        # loop L                       dec ecx; jnz L (rel8 = -6)
    code += b"\x61"                                  # popad                        restore all GPRs
    if pushret:
        code += b"\x68" + struct.pack("<I", oep_va)  # push oep_va
        code += b"\xC3"                              # ret                          "returns" to the OEP
    else:
        site = stub_va + len(code)
        code += b"\xE9" + struct.pack("<i", oep_va - (site + 5))  # jmp rel32 OEP
    return bytes(code)


def stub_x64(stub_va, text_va, size, oep_va):
    """64-bit stub, position independent (RIP-relative lea + rel32 jmp)."""
    code = bytearray()
    code += b"\x56"                                  # push rsi
    code += b"\x51"                                  # push rcx
    site = stub_va + len(code)
    code += b"\x48\x8D\x35" + struct.pack("<i", text_va - (site + 7))  # lea rsi, [rip + disp32] -> text_va
    code += b"\xB9" + struct.pack("<I", size)        # mov ecx, size
    loop = len(code)
    code += b"\x80\x36" + bytes([KEY])               # L: xor byte ptr [rsi], KEY
    code += b"\x48\xFF\xC6"                          # inc rsi
    code += b"\xFF\xC9"                              # dec ecx
    rel8 = loop - (len(code) + 2)
    code += b"\x75" + struct.pack("<b", rel8)        # jnz L                        (rel8 = -10)
    code += b"\x59"                                  # pop rcx
    code += b"\x5E"                                  # pop rsi
    site = stub_va + len(code)
    code += b"\xE9" + struct.pack("<i", oep_va - (site + 5))  # jmp rel32 OEP
    return bytes(code)


def pack(patch_samples, src, dst, pushret=False):
    data = bytearray(open(src, "rb").read())
    pe = parse_pe(data)
    text = find_section(pe, b".text")
    image_base = pe["image_base"]
    oep_va = image_base + pe["ep"]
    size = min(text["vs"], text["rs"])  # what the loop decrypts in memory, all of it file-backed

    # 1. encrypt .text raw data
    for i in range(text["ro"], text["ro"] + size):
        data[i] ^= KEY

    # 2. .text writable (the stub decrypts in place)
    struct.pack_into("<I", data, text["hdr"] + 36, text["ch"] | IMAGE_SCN_MEM_WRITE)

    # 3. stub section; the VA is known before the stub is built because the stub length does not depend on it
    probe = stub_x64(0, 0, 0, 0) if pe["is64"] else stub_x86(0, 0, 0, 0, pushret)
    last = pe["sections"][-1]
    sec_align = struct.unpack_from("<I", data, pe["opt"] + 32)[0]
    stub_rva = (last["va"] + last["vs"] + sec_align - 1) // sec_align * sec_align
    stub_va = image_base + stub_rva
    text_va = image_base + text["va"]
    if pe["is64"]:
        stub = stub_x64(stub_va, text_va, size, oep_va)
    else:
        stub = stub_x86(stub_va, text_va, size, oep_va, pushret)
    assert len(stub) == len(probe)

    new_rva = patch_samples.append_section(data, b".toy", stub, IMAGE_SCN_CODE_RX)
    assert new_rva == stub_rva

    # 4. EP -> stub, no ASLR, checksum cleared
    opt = pe["opt"]
    struct.pack_into("<I", data, opt + 16, stub_rva)  # AddressOfEntryPoint
    dll_characteristics = pe["dll_characteristics"] & ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
    struct.pack_into("<H", data, opt + 70, dll_characteristics)
    struct.pack_into("<I", data, opt + 64, 0)  # CheckSum

    open(dst, "wb").write(data)
    print("wrote %-24s OEP VA 0x%X (RVA 0x%X), stub VA 0x%X, %d stub bytes, .text 0x%X bytes XOR 0x%02X"
          % (os.path.basename(dst), oep_va, pe["ep"], stub_va, len(stub), size, KEY))
    return oep_va


def verify(src, dst, oep_va, pushret=False):
    """Static re-check of the output against the source (headers, stub bytes, encrypted .text)."""
    orig = open(src, "rb").read()
    data = open(dst, "rb").read()
    pe0 = parse_pe(orig)
    pe = parse_pe(data)
    toy = pe["sections"][-1]
    text0 = find_section(pe0, b".text")
    text = find_section(pe, b".text")
    base = pe["image_base"]

    assert len(pe["sections"]) == len(pe0["sections"]) + 1
    assert toy["name"] == b".toy" and toy["ch"] == IMAGE_SCN_CODE_RX
    assert toy["ro"] % 0x200 == 0 and toy["ro"] + toy["rs"] == len(data)
    assert pe["ep"] == toy["va"], "EP is not the stub"
    assert pe["size_of_image"] >= toy["va"] + toy["vs"] and pe["size_of_image"] % 0x1000 == 0
    assert text["ch"] & IMAGE_SCN_MEM_WRITE
    assert not (pe["dll_characteristics"] & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    assert base + pe0["ep"] == oep_va

    size = min(text0["vs"], text0["rs"])
    enc = data[text["ro"]:text["ro"] + size]
    dec = bytes(b ^ KEY for b in enc)
    assert dec == orig[text0["ro"]:text0["ro"] + size], ".text does not decrypt back"
    assert enc != orig[text0["ro"]:text0["ro"] + size]

    stub = data[toy["ro"]:toy["ro"] + toy["vs"]]
    stub_va = base + toy["va"]
    if pe["is64"]:
        assert stub[:5] == b"\x56\x51\x48\x8D\x35"
        disp = struct.unpack_from("<i", stub, 5)[0]
        assert stub_va + 9 + disp == base + text["va"], "lea rsi target"
        assert struct.unpack_from("<I", stub, 10)[0] == size
        assert stub[-7:-5] == b"\x59\x5E" and stub[-5] == 0xE9
        target = stub_va + len(stub) + struct.unpack_from("<i", stub, len(stub) - 4)[0]
    else:
        assert stub[0] == 0x60 and stub[1] == 0xBE and stub[6] == 0xB9
        assert struct.unpack_from("<I", stub, 2)[0] == base + text["va"]
        assert struct.unpack_from("<I", stub, 7)[0] == size
        if pushret:
            assert stub[-7] == 0x61 and stub[-6] == 0x68 and stub[-1] == 0xC3
            target = struct.unpack_from("<I", stub, len(stub) - 5)[0]
        else:
            assert stub[-6] == 0x61 and stub[-5] == 0xE9
            target = stub_va + len(stub) + struct.unpack_from("<i", stub, len(stub) - 4)[0]
    assert target == oep_va, "tail transfer 0x%X != OEP 0x%X" % (target, oep_va)
    print("  ok  %-24s EP RVA 0x%X in .toy, tail -> 0x%X, stub %s" % (os.path.basename(dst), pe["ep"], target, stub.hex(" ").upper()))


def main():
    d = sys.argv[1]
    patch_samples = load_patch_samples()
    jobs = [
        ("hello32.exe", "toypacker32.exe", False),
        ("hello32.exe", "toypacker32_pushret.exe", True),
        ("hello64.exe", "toypacker64.exe", False),
    ]
    for src_name, dst_name, pushret in jobs:
        src = os.path.join(d, src_name)
        dst = os.path.join(d, dst_name)
        oep_va = pack(patch_samples, src, dst, pushret)
        verify(src, dst, oep_va, pushret)


if __name__ == "__main__":
    main()
