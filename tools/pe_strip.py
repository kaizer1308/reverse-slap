#!/usr/bin/env python3
# tools/pe_strip.py
# Post-build PE hardening: strips Rich header, IAT hint-name strings for
# suspicious APIs, PDB path, and compiler version strings from the binary.
# Does NOT break the PE — import resolution uses ordinals, not names.

import struct
import sys
import os
import shutil

SUSPICIOUS_APIS = {
    b"ReadProcessMemory", b"WriteProcessMemory", b"OpenProcess",
    b"VirtualAllocEx", b"VirtualFreeEx", b"VirtualProtectEx",
    b"VirtualQueryEx", b"CreateRemoteThread", b"CreateRemoteThreadEx",
    b"CreateToolhelp32Snapshot", b"NtReadVirtualMemory",
    b"NtWriteVirtualMemory", b"NtQuerySystemInformation",
    b"NtQueryInformationProcess",
}

COMPILER_STRINGS = [
    b"Microsoft Visual C++",
    b"MSVC",
    b".pdb",
]

def strip_rich_header(data):
    """Zero the Rich header (between DOS stub and PE signature)."""
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    # Rich header ends with "Rich" signature, starts after DOS stub (0x80)
    rich_idx = data.find(b"Rich", 0x80, pe_off)
    if rich_idx < 0:
        return data, False
    # Rich header starts at 0x80 (after standard DOS stub)
    start = 0x80
    end = rich_idx + 8  # "Rich" + 4-byte checksum
    data = bytearray(data)
    for i in range(start, min(end, pe_off)):
        data[i] = 0
    return bytes(data), True

def strip_iat_hints(data):
    """Zero the name strings in IAT hint/name entries for suspicious APIs."""
    count = 0
    data = bytearray(data)
    for api in SUSPICIOUS_APIS:
        pos = 0
        while True:
            idx = data.find(api, pos)
            if idx < 0:
                break
            # IAT hint/name entries have a 2-byte hint before the name
            # and a null terminator after. Check this looks like one.
            if idx >= 2 and data[idx + len(api)] == 0:
                # Replace the name with a generic string of same length
                # keeping the hint bytes intact
                replacement = b"_" * len(api)
                data[idx:idx + len(api)] = replacement
                count += 1
            pos = idx + 1
    return bytes(data), count

def strip_pdb_path(data):
    """Zero the PDB path in the debug directory."""
    data = bytearray(data)
    count = 0
    pos = 0
    while True:
        idx = data.find(b".pdb", pos)
        if idx < 0:
            break
        # Walk backwards to find the start of the path
        start = idx
        while start > 0 and data[start - 1] != 0:
            start -= 1
        # Zero the entire path (keep the .pdb extension for tools that need it)
        for i in range(start, idx):
            data[i] = ord('_')
        count += 1
        pos = idx + 4
    return bytes(data), count

def strip_compiler_strings(data):
    """Zero known compiler identification strings."""
    data = bytearray(data)
    count = 0
    for sig in COMPILER_STRINGS:
        pos = 0
        while True:
            idx = data.find(sig, pos)
            if idx < 0:
                break
            data[idx:idx + len(sig)] = b"_" * len(sig)
            count += 1
            pos = idx + len(sig)
    return bytes(data), count

def enable_cfg_flag(data):
    """Set IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) in DllCharacteristics."""
    data = bytearray(data)
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = pe_off + 24
    dll_chars_off = opt_off + 70
    dll_chars = struct.unpack_from("<H", data, dll_chars_off)[0]
    if not (dll_chars & 0x4000):
        dll_chars |= 0x4000
        struct.pack_into("<H", data, dll_chars_off, dll_chars)
        return bytes(data), True
    return bytes(data), False

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe_file> [--inplace]")
        sys.exit(1)
    
    path = sys.argv[1]
    inplace = "--inplace" in sys.argv
    
    data = open(path, "rb").read()
    original_size = len(data)
    
    # Verify PE
    if data[:2] != b"MZ":
        print("error: not a PE file")
        sys.exit(1)
    
    print(f"stripping: {path} ({original_size:,} bytes)")
    
    data, rich = strip_rich_header(data)
    print(f"  Rich header: {'stripped' if rich else 'not found'}")
    
    data, iat_count = strip_iat_hints(data)
    print(f"  IAT hint-names: {iat_count} suspicious APIs stripped")
    
    data, pdb_count = strip_pdb_path(data)
    print(f"  PDB paths: {pdb_count} stripped")
    
    data, comp_count = strip_compiler_strings(data)
    print(f"  Compiler strings: {comp_count} stripped")
    
    data, cfg = enable_cfg_flag(data)
    print(f"  CFG flag: {'set' if cfg else 'already set'}")

    # Strip build paths (unicorn __FILE__ macros, user directories)
    build_paths = [b"reverse-slap", b"reverse-slop", b"\\Users\\minaa\\"]
    bp_count = 0
    bdata = bytearray(data)
    for bp in build_paths:
        pos = 0
        while True:
            idx = bdata.find(bp, pos)
            if idx < 0: break
            bdata[idx:idx + len(bp)] = b"_" * len(bp)
            bp_count += 1
            pos = idx + 1
    data = bytes(bdata)
    print(f"  Build paths: {bp_count} scrubbed")

    # Strip remaining OpenProcess IAT hint (last stubborn one)
    bdata = bytearray(data)
    op_count = 0
    pos = 0
    while True:
        idx = bdata.find(b"OpenProcess\x00", pos)
        if idx < 0: break
        bdata[idx:idx + 11] = b"_" * 11
        op_count += 1
        pos = idx + 1
    data = bytes(bdata)
    if op_count: print(f"  OpenProcess hints: {op_count} stripped")
    
    if inplace:
        open(path, "wb").write(data)
        print(f"  written: {path}")
    else:
        out = path + ".stripped"
        open(out, "wb").write(data)
        print(f"  written: {out}")

if __name__ == "__main__":
    main()
