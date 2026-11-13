#!/usr/bin/env python3
import os
import sys
import struct
import random
from pathlib import Path

MAGIC = 0x58881688
TAG_LOGO = b"LOGO"
HDR_SIZE = 0x200
OFF_MAGIC = 0x00
OFF_SIZE = 0x04
OFF_TAG = 0x08


def parse(path):
    data = Path(path).read_bytes()
    if len(data) < HDR_SIZE:
        raise ValueError(f"file too small: {len(data)} < {HDR_SIZE}")
    magic = struct.unpack_from("<I", data, OFF_MAGIC)[0]
    size = struct.unpack_from("<I", data, OFF_SIZE)[0]
    tag = bytes(data[OFF_TAG:OFF_TAG + 4])
    hdr = bytes(data[:HDR_SIZE])
    body = bytes(data[HDR_SIZE:])
    return {
        "path": str(path),
        "total": len(data),
        "magic": magic,
        "size": size,
        "tag": tag,
        "header": hdr,
        "body": body,
        "body_len": len(body),
        "size_matches": (size == len(body)),
        "magic_ok": (magic == MAGIC),
        "tag_ok": (tag == TAG_LOGO),
    }


def build(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, len(body) & 0xFFFFFFFF)
    return bytes(hdr) + bytes(body)


def build_keep_size(header, body):
    return bytes(header) + bytes(body)


def write_out(path, blob):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)
    print(f"[+] wrote {path} ({len(blob)} bytes)")


def cmd_info(args):
    if len(args) < 1:
        print("info FILE")
        return 1
    info = parse(args[0])
    print(f"file        : {info['path']}")
    print(f"total       : {info['total']:,}")
    print(f"magic       : 0x{info['magic']:08x}  ({'OK' if info['magic_ok'] else 'BAD'})")
    print(f"tag         : {info['tag']}  ({'OK' if info['tag_ok'] else 'BAD'})")
    print(f"data_size   : {info['size']:,}  (0x{info['size']:08x})")
    print(f"body_len    : {info['body_len']:,}")
    print(f"size_matches: {info['size_matches']}")
    print()
    print("header hexdump (0x0000..0x0200):")
    for off in range(0, HDR_SIZE, 16):
        chunk = info["header"][off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {off:04x}: {hx:<48} {asc}")
    print()
    print(f"body head 64 bytes: {info['body'][:64].hex()}")
    return 0


def cmd_data_hex(args):
    if len(args) < 1:
        print("data_hex FILE [START] [LEN]")
        return 1
    info = parse(args[0])
    start = int(args[1], 0) if len(args) > 1 else 0
    length = int(args[2], 0) if len(args) > 2 else 0x100
    body = info["body"]
    end = min(start + length, len(body))
    print(f"body hexdump 0x{start:08x}..0x{end:08x}")
    for off in range(start, end, 16):
        chunk = body[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {off:08x}: {hx:<48} {asc}")
    return 0


def cmd_data_bmp_check(args):
    if len(args) < 1:
        print("data_bmp_check FILE")
        return 1
    info = parse(args[0])
    head = info["body"][:16]
    print(f"body head16 : {head.hex()}")
    print(f"body[0:2]   : {info['body'][0:2].hex()}  "
          f"-> {'BM (BMP)' if info['body'][:2] == b'BM' else 'not BM'}")
    for m in (b'BM', b'\x89P', b'\xff\xd8', b'GIF8', b'RIFF', b'\x00\x00'):
        if info["body"].startswith(m):
            print(f"matched signature: {m!r}")
    return 0


# ---------- PoC generators ----------

def gen_size_huge(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0xFFFFFFFF)
    return bytes(hdr) + bytes(body)


def gen_size_zero(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0x00000000)
    return bytes(hdr) + bytes(body)


def gen_size_boundary(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0x7FFFFFFF)
    return bytes(hdr) + bytes(body)


def gen_size_plus1(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, (len(body) + 1) & 0xFFFFFFFF)
    return bytes(hdr) + bytes(body)


def gen_size_half(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, len(body) // 2)
    return bytes(hdr) + bytes(body)


def gen_size_minus1(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, max(0, len(body) - 1))
    return bytes(hdr) + bytes(body)


def gen_size_pow2(header, body):
    hdr = bytearray(header)
    v = 1
    while v < len(body):
        v <<= 1
    struct.pack_into("<I", hdr, OFF_SIZE, v & 0xFFFFFFFF)
    return bytes(hdr) + bytes(body)


def gen_tag_bad(header, body):
    hdr = bytearray(header)
    hdr[OFF_TAG:OFF_TAG + 4] = b"XXXX"
    return bytes(hdr) + bytes(body)


def gen_tag_zero(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_TAG, 0)
    return bytes(hdr) + bytes(body)


def gen_magic_bad(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_MAGIC, 0xDEADBEEF)
    return bytes(hdr) + bytes(body)


def gen_fill_ff(header, body):
    return build(header, b"\xff" * len(body))


def gen_fill_00(header, body):
    return build(header, b"\x00" * len(body))


def gen_fill_aa(header, body):
    return build(header, b"\xaa" * len(body))


def gen_fill_55(header, body):
    return build(header, b"\x55" * len(body))


def gen_fill_fe(header, body):
    return build(header, b"\xfe" * len(body))


def gen_random(header, body):
    return build(header, os.urandom(len(body)))


def gen_rle_attack(header, body):
    pat = b"\x00\xff\xff\xff"
    n = len(body)
    data = (pat * ((n // len(pat)) + 1))[:n]
    return build(header, data)


def gen_rle_zero(header, body):
    pat = b"\x00\x00\x00\x00"
    n = len(body)
    data = (pat * ((n // len(pat)) + 1))[:n]
    return build(header, data)


def gen_rle_255(header, body):
    pat = b"\x00\xff\x00\x00"
    n = len(body)
    data = (pat * ((n // len(pat)) + 1))[:n]
    return build(header, data)


def gen_combo_huge_ff(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0xFFFFFFFF)
    return bytes(hdr) + b"\xff" * len(body)


def gen_combo_zero_ff(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0)
    return bytes(hdr) + b"\xff" * len(body)


def gen_combo_huge_rle(header, body):
    hdr = bytearray(header)
    struct.pack_into("<I", hdr, OFF_SIZE, 0xFFFFFFFF)
    n = len(body)
    pat = b"\x00\xff\xff\xff"
    data = (pat * ((n // len(pat)) + 1))[:n]
    return bytes(hdr) + data


def gen_truncate_data(header, body):
    return build(header, b"")


def gen_truncate_keep_size(header, body):
    return build_keep_size(header, b"")


def gen_pad_change(header, body):
    hdr = bytearray(header)
    for i in range(0x28, HDR_SIZE):
        hdr[i] = 0x00
    return bytes(hdr) + bytes(body)


def gen_header_ffff(header, body):
    hdr = bytearray(b"\xff" * HDR_SIZE)
    struct.pack_into("<I", hdr, OFF_MAGIC, MAGIC)
    struct.pack_into("<I", hdr, OFF_SIZE, len(body) & 0xFFFFFFFF)
    hdr[OFF_TAG:OFF_TAG + 4] = TAG_LOGO
    return bytes(hdr) + bytes(body)


GEN = {
    "size_huge": gen_size_huge,
    "size_zero": gen_size_zero,
    "size_boundary": gen_size_boundary,
    "size_plus1": gen_size_plus1,
    "size_half": gen_size_half,
    "size_minus1": gen_size_minus1,
    "size_pow2": gen_size_pow2,
    "tag_bad": gen_tag_bad,
    "tag_zero": gen_tag_zero,
    "magic_bad": gen_magic_bad,
    "fill_ff": gen_fill_ff,
    "fill_00": gen_fill_00,
    "fill_aa": gen_fill_aa,
    "fill_55": gen_fill_55,
    "fill_fe": gen_fill_fe,
    "random": gen_random,
    "rle_attack": gen_rle_attack,
    "rle_zero": gen_rle_zero,
    "rle_255": gen_rle_255,
    "combo_huge_ff": gen_combo_huge_ff,
    "combo_zero_ff": gen_combo_zero_ff,
    "combo_huge_rle": gen_combo_huge_rle,
    "truncate_data": gen_truncate_data,
    "truncate_keep_size": gen_truncate_keep_size,
    "pad_change": gen_pad_change,
    "header_ffff": gen_header_ffff,
}


def cmd_poc(args):
    if len(args) < 3:
        print("poc FILE OUT --kind KIND")
        return 1
    src, out = args[0], args[1]
    kind = None
    i = 2
    while i < len(args):
        if args[i] == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
            i += 2
        else:
            i += 1
    if kind not in GEN:
        print(f"unknown kind {kind}")
        print("available: " + ", ".join(GEN))
        return 1
    info = parse(src)
    blob = GEN[kind](info["header"], info["body"])
    write_out(out, blob)
    return 0


def cmd_all(args):
    if len(args) < 2:
        print("all FILE OUTDIR")
        return 1
    src, outdir = args[0], args[1]
    info = parse(src)
    for kind, fn in GEN.items():
        blob = fn(info["header"], info["body"])
        write_out(f"{outdir}/logo_{kind}.bin", blob)
    # 元ファイルも参考として同梱
    write_out(f"{outdir}/logo_original.bin", Path(src).read_bytes())
    return 0


def cmd_replace_raw(args):
    if len(args) < 4:
        print("replace_raw FILE W H OUT [COLOR] [KEEP_SIZE]")
        return 1
    src, ws, hs, out = args[0], args[1], args[2], args[3]
    color = args[4] if len(args) > 4 else "white"
    keep_size = (len(args) > 5 and args[5].lower() in ("1", "true", "yes"))
    w, h = int(ws, 0), int(hs, 0)
    info = parse(src)

    colors = {
        "white": (0xFF, 0xFF, 0xFF),
        "black": (0x00, 0x00, 0x00),
        "red":   (0xFF, 0x00, 0x00),
        "green": (0x00, 0xFF, 0x00),
        "blue":  (0x00, 0x00, 0xFF),
    }
    if color not in colors:
        print(f"unknown color {color}")
        return 1
    r, g, b = colors[color]
    v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    px = struct.pack("<H", v) * (w * h)

    if keep_size:
        n = len(info["body"])
        px = (px * ((n // len(px)) + 1))[:n]

    blob = build(info["header"], px)
    write_out(out, blob)
    print(f"[+] {w}x{h} RGB565 {color} = {len(px)} bytes body")
    return 0


def cmd_replace_bmp(args):
    if len(args) < 3:
        print("replace_bmp FILE BMP OUT [KEEP_SIZE]")
        return 1
    src, bmp_path, out = args[0], args[1], args[2]
    keep_size = (len(args) > 3 and args[3].lower() in ("1", "true", "yes"))
    info = parse(src)
    bmp = Path(bmp_path).read_bytes()
    if bmp[:2] != b"BM":
        print("not a BMP")
        return 1
    if keep_size:
        n = len(info["body"])
        if len(bmp) >= n:
            bmp = bmp[:n]
        else:
            bmp = bmp + b"\xff" * (n - len(bmp))
    blob = build(info["header"], bmp)
    write_out(out, blob)
    print(f"[+] bmp size={len(bmp)} body")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__ or "usage")
        print("commands: info, data_hex, data_bmp_check, poc, all, "
              "replace_raw, replace_bmp")
        return 1
    cmd = sys.argv[1]
    rest = sys.argv[2:]
    if cmd == "info":
        return cmd_info(rest)
    if cmd == "data_hex":
        return cmd_data_hex(rest)
    if cmd == "data_bmp_check":
        return cmd_data_bmp_check(rest)
    if cmd == "poc":
        return cmd_poc(rest)
    if cmd == "all":
        return cmd_all(rest)
    if cmd == "replace_raw":
        return cmd_replace_raw(rest)
    if cmd == "replace_bmp":
        return cmd_replace_bmp(rest)
    print(f"unknown command {cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
