#!/usr/bin/env python3
import sys
import struct
from pathlib import Path

MAGICS = (
    0x58881688,
    0x58891688,
    0x1E1E1E1E,
    0x20100800,
    0x28041998,
    0x4D544B4C,
    0x4F474F4C,
)

def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def find_headers(data):
    n = len(data)
    hits = []
    for off in range(0, n - 3, 4):
        v = u32(data, off)
        if v in MAGICS:
            hits.append((off, v))
    return hits

def image_ranges(data):
    n = len(data)
    hits = find_headers(data)
    if not hits:
        return []
    result = []
    for i, (hdr_off, magic) in enumerate(hits):
        start = hdr_off + 512
        end = hits[i + 1][0] if i + 1 < len(hits) else n
        if start < end:
            result.append((i, hdr_off, start, end))
    return result

def hexdump(data, start, length):
    end = min(start + length, len(data))
    for off in range(start, end, 16):
        chunk = data[off:off + 16]
        if not chunk:
            break
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {off:04x}: {hx:<48} {asc}")

def cmd_dump(args):
    if len(args) < 1:
        print("dump FILE")
        return 1
    data = Path(args[0]).read_bytes()
    n = len(data)
    print(f"file {args[0]}")
    print(f"size {n}")
    print(f"head16 {data[:16].hex()}")
    print(f"u32@0 {u32(data, 0):#010x}")
    print()
    print("hexdump 0x0000..0x0200")
    hexdump(data, 0, min(0x200, n))
    print()
    print("u32 0x0000..0x0200")
    for off in range(0, min(0x200, n - 3), 4):
        v = u32(data, off)
        print(f"  {off:04x} {v:#010x} {v}")
    print()
    print("u16 0x0000..0x0200")
    for off in range(0, min(0x200, n - 1), 2):
        v = u16(data, off)
        print(f"  {off:04x} {v:#06x} {v}")
    print()
    hits = find_headers(data)
    print(f"magic hits {len(hits)}")
    for off, m in hits:
        print(f"  0x{off:08x} {m:#010x}")
    return 0

def cmd_analyze(args):
    if len(args) < 1:
        print("analyze FILE")
        return 1
    data = Path(args[0]).read_bytes()
    n = len(data)
    ranges = image_ranges(data)
    print(f"file {args[0]} size {n} images {len(ranges)}")
    for i, hdr_off, start, end in ranges:
        hdr = data[hdr_off:hdr_off + 512]
        print()
        print(f"image {i}")
        print(f"  header 0x{hdr_off:08x} data 0x{start:08x}..0x{end:08x} len {end - start}")
        print(f"  magic {u32(hdr, 0):#010x}")
        for off in (0x04, 0x06, 0x08, 0x0A, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58):
            v32 = u32(hdr, off)
            v16 = u16(hdr, off)
            print(f"  u32@{off:#04x} {v32:#010x} {v32}  u16 {v16:#06x} {v16}")
    return 0

def cmd_safe(args):
    if len(args) < 2:
        print("safe FILE OUT")
        return 1
    src, dst = args[0], args[1]
    data = bytearray(Path(src).read_bytes())
    ranges = image_ranges(data)
    if not ranges:
        print("no images found")
        return 1
    for i, hdr_off, start, end in ranges:
        length = end - start
        fill = b"\xff\xff" * (length // 2) + b"\x00" * (length & 1)
        data[start:end] = fill
        print(f"image {i} filled white len {length}")
    Path(dst).write_bytes(data)
    print(f"wrote {dst} {len(data)}")
    return 0

def cmd_patch(args):
    if len(args) < 4:
        print("patch FILE OUT OFFSET VALUE [SIZE]")
        return 1
    src, dst, off_s, val_s = args[0], args[1], args[2], args[3]
    size = int(args[4], 0) if len(args) > 4 else 4
    off = int(off_s, 0)
    val = int(val_s, 0)
    data = bytearray(Path(src).read_bytes())
    if off < 0 or off + size > len(data):
        print(f"offset {off:#x} out of range")
        return 1
    if size == 1:
        data[off] = val & 0xFF
    elif size == 2:
        struct.pack_into("<H", data, off, val & 0xFFFF)
    elif size == 4:
        struct.pack_into("<I", data, off, val & 0xFFFFFFFF)
    else:
        print("size must be 1, 2, or 4")
        return 1
    Path(dst).write_bytes(data)
    print(f"patched 0x{off:08x} = {val:#x} size {size}")
    return 0

def cmd_vuln(args):
    if len(args) < 3:
        print("vuln FILE OUT KIND")
        return 1
    src, dst, kind = args[0], args[1], args[2]
    data = bytearray(Path(src).read_bytes())
    ranges = image_ranges(data)
    if not ranges:
        print("no images found")
        return 1
    for i, hdr_off, start, end in ranges:
        length = end - start
        fill = b"\xff\xff" * (length // 2) + b"\x00" * (length & 1)
        data[start:end] = fill
        if kind == "pattern":
            pass
        elif kind == "alloc_short":
            struct.pack_into("<I", data, hdr_off + 0x28, 1)
            for j in range(0x2A, 0x2A + 0x24):
                data[hdr_off + j] = 0x41
        elif kind == "shift_neg":
            struct.pack_into("<H", data, hdr_off + 0x27C, 0)
        elif kind == "div_zero":
            struct.pack_into("<I", data, hdr_off + 0x50, 0)
            struct.pack_into("<I", data, hdr_off + 0x54, 0)
        elif kind == "huge_wh":
            struct.pack_into("<I", data, hdr_off + 0x18, 0xFFFFFFFF)
            struct.pack_into("<I", data, hdr_off + 0x1C, 0xFFFFFFFF)
        else:
            print(f"unknown kind {kind}")
            return 1
        print(f"image {i} vuln {kind}")
    Path(dst).write_bytes(data)
    print(f"wrote {dst} {len(data)}")
    return 0

def main():
    argv = sys.argv[1:]
    if not argv:
        print("commands:")
        print("  dump FILE")
        print("  analyze FILE")
        print("  safe FILE OUT")
        print("  patch FILE OUT OFFSET VALUE [SIZE]")
        print("  vuln FILE OUT [pattern|alloc_short|shift_neg|div_zero|huge_wh]")
        return 1
    cmd = argv[0]
    rest = argv[1:]
    if cmd == "dump":
        return cmd_dump(rest)
    if cmd == "analyze":
        return cmd_analyze(rest)
    if cmd == "safe":
        return cmd_safe(rest)
    if cmd == "patch":
        return cmd_patch(rest)
    if cmd == "vuln":
        return cmd_vuln(rest)
    print(f"unknown {cmd}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
