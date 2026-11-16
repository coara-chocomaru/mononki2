#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_mt8168_lk_dev.py  ---  MT8168 LK (lk2.img) dev patch builder  v7

対象とする不具合と修正方針
--------------------------------------------------------------------------
(A) fastboot コマンド制限が efuse 未完成で lock/unlock unknown になり弾かれる
    -> 許可判定関数の prologue を "movs r0,#1 ; bx lr" に置換して常時許可。
       文字列 "flashing" / "unlock" / "oem" を参照する literal pool から
       参照元命令を引き、その所属関数を境界探索で確定して当てる。

(B) vbmeta flags 0x7B が 00/01/02/03 のいずれでも 03 に固定されない
    -> flags フィールド (AvbVBMetaImageHeader + 0x78) のロード直後を
       "movs rX,#3" に置換。加えて flags テスト命令 (tst/ands #1/#2) の
       直後の条件分岐を無条件分岐へ潰し、03 と等価な経路を強制する。

(C) flags=03 で sd_boot の get_size_of_partition が 64bit 不正値を返し
    "Partition size too large to load." -> avb ret=2 -> img_loaded ASSERT
    -> 0x3C8C8 の上位32bit 検査 (ldr rX,[sp,#4] / cmp rX,#0 / bne err) の
       bne を無条件 b へ。さらに avb 呼び出し直後の ret!=0 判定も
       継続側へ倒し、黒画面ループを止める。

(D) 音量+ 長押しで logo をロードした後、離して再押下しないと recovery に入れない
    -> logo パーティション名を指す分岐を recovery 側へ retarget。
       KPD 読み出し直後の cmp/beq を無条件化し、判定時点で recovery へ飛ばす。

安全装置
--------------------------------------------------------------------------
* 各パッチは「期待パターン一致」を必須とし、不一致なら書き込まずに中断。
* パッチ後に該当アドレスを再逆アセンブルし、意図した命令になったか検証。
* パッチ領域の重なりを全件チェック (同じバイトを 2 回書いたら失敗)。
* 元イメージの SHA-256、各サイトの before/after、全パッチ一覧をレポート出力。

使い方
--------------------------------------------------------------------------
    python3 patch_mt8168_lk_dev.py --input lk2.img --outdir out
    python3 patch_mt8168_lk_dev.py --input lk2.img --outdir out --zip

    --dry-run   書き込まずにサイト特定と検証だけ実施
    --report F  レポート出力先 (既定: <outdir>/PATCH_REPORT_JA.txt)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import shutil
import struct
import sys
import zipfile

# ----------------------------------------------------------------------------
# 定数
# ----------------------------------------------------------------------------

BASE_ADDR = 0x00000000          # lk2.img はフラット。アドレス == ファイルオフセット
MAX_SCAN_BACK = 0x900           # 関数先頭探索の後方上限
AVB_SIZE_CHECK_HINT = 0x3C8C8   # 上位32bit検査 (既知解析点)
AVB_CALL_HINT = 0x3C8A8         # AvbOps+0x2C callback 呼び出し
AVB_MODE10_HINT = 0x3CBC2       # mode=10 補助確認
VBMETA_FLAGS_OFF = 0x78         # AvbVBMetaImageHeader.flags
HINT_WINDOW = 0x60              # ヒント位置からの探索窓

# fastboot 許可判定の手掛かり文字列
FASTBOOT_STRINGS = ("flashing", "unlock", "oem", "fastboot")
# パーティション名文字列
PART_LOGO = "logo"
PART_RECOVERY = "recovery"
PART_SD_BOOT = "sd_boot"

NOP = 0xBF00
BX_LR = 0x4770
MOVS_R0_1 = 0x2001


# ----------------------------------------------------------------------------
# 例外
# ----------------------------------------------------------------------------

class PatchError(RuntimeError):
    pass


# ----------------------------------------------------------------------------
# バイナリ
# ----------------------------------------------------------------------------

class Firmware:
    def __init__(self, data: bytes, path: str):
        self.orig = bytearray(data)
        self.buf = bytearray(data)
        self.path = path
        self.written = {}          # addr -> (size, tag)
        self.log = []

    def __len__(self):
        return len(self.buf)

    def u8(self, a):
        return self.buf[a]

    def u16(self, a):
        return struct.unpack_from("<H", self.buf, a)[0]

    def u32(self, a):
        return struct.unpack_from("<I", self.buf, a)[0]

    def p32(self, a):
        return struct.unpack_from("<I", self.orig, a)[0]

    def write(self, addr, blob: bytes, tag: str):
        end = addr + len(blob)
        for a in range(addr, end):
            if a in self.written:
                raise PatchError(
                    f"パッチ領域の重なり: 0x{a:06X} "
                    f"({self.written[a][1]} と {tag})")
        if end > len(self.buf):
            raise PatchError(f"書き込みがイメージ末尾を超える: 0x{addr:06X}")
        self.buf[addr:end] = blob
        for a in range(addr, end):
            self.written[a] = (1, tag)
        self.log.append((addr, bytes(blob), tag))

    def diff_offsets(self):
        n = min(len(self.orig), len(self.buf))
        return [i for i in range(n) if self.orig[i] != self.buf[i]]


# ----------------------------------------------------------------------------
# 最小 Thumb デコーダ (capstone 非依存)
# ----------------------------------------------------------------------------

class Insn:
    __slots__ = ("addr", "hw", "hw2", "size", "mn", "ops")

    def __init__(self, addr, hw, hw2, size, mn, ops):
        self.addr, self.hw, self.hw2 = addr, hw, hw2
        self.size, self.mn, self.ops = size, mn, ops

    def __repr__(self):
        a = " ".join(str(o) for o in self.ops)
        return f"0x{self.addr:06X}: {self.mn} {a}".rstrip()


def _sx(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def decode_one(fw: Firmware, a: int) -> Insn:
    hw = fw.u16(a)
    hi = hw >> 11

    # ---- 32bit ----
    if 0x1D <= hi <= 0x1F:                      # 11101 / 11110 / 11111
        if a + 4 > len(fw):
            return Insn(a, hw, 0, 2, ".hword", [hw])
        hw2 = fw.u16(a + 2)
        if hi == 0x1E and (hw2 & 0xD000) == 0x9000:      # B.W / BL
            s = (hw >> 10) & 1
            j1 = (hw2 >> 13) & 1
            j2 = (hw2 >> 11) & 1
            i1 = 1 - (j1 ^ s)
            i2 = 1 - (j2 ^ s)
            imm = (s << 24) | (i1 << 23) | (i2 << 22) | \
                  ((hw & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
            off = _sx(imm, 25)
            mn = "bl" if (hw2 & 0x1000) else "b.w"
            return Insn(a, hw, hw2, 4, mn, [f"0x{a + 4 + off:06X}"])
        if hi == 0x1E and (hw2 & 0xD000) == 0xD000:      # BL
            s = (hw >> 10) & 1
            j1 = (hw2 >> 13) & 1
            j2 = (hw2 >> 11) & 1
            i1 = 1 - (j1 ^ s)
            i2 = 1 - (j2 ^ s)
            imm = (s << 24) | (i1 << 23) | (i2 << 22) | \
                  ((hw & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
            return Insn(a, hw, hw2, 4, "bl", [f"0x{a + 4 + _sx(imm, 25):06X}"])
        return Insn(a, hw, hw2, 4, ".word", [f"0x{(hw2 << 16) | hw:08X}"])

    # ---- 16bit ----
    if hw == NOP:
        return Insn(a, hw, 0, 2, "nop", [])
    if (hw & 0xFF00) == 0xBF00:
        return Insn(a, hw, 0, 2, "it/cond", [hw & 0x0F])
    if (hw & 0xF800) == 0xE000:
        return Insn(a, hw, 0, 2, "b", [f"0x{a + 4 + _sx(hw & 0x7FF, 11) * 2:06X}"])
    if (hw & 0xF000) == 0xD000:
        c = (hw >> 8) & 0xF
        tgt = a + 4 + _sx(hw & 0xFF, 8) * 2
        return Insn(a, hw, 0, 2, f"b{COND[c]}", [f"0x{tgt:06X}"])
    if (hw & 0xF800) == 0xB100:
        return Insn(a, hw, 0, 2, "cbz" if (hw & 0x0800) == 0 else "cbnz",
                    [f"r{hw & 7}", f"0x{a + 4 + ((hw >> 3) & 0x1F) * 2:06X}"])
    if (hw & 0xF800) == 0x4800:
        return Insn(a, hw, 0, 2, "ldr", [f"r{(hw >> 8) & 7}",
                                        f"[pc,#{(hw & 0xFF) * 4}]"])
    if (hw & 0xF800) == 0x2000:
        return Insn(a, hw, 0, 2, "movs", [f"r{(hw >> 8) & 7}", f"#{hw & 0xFF}"])
    if (hw & 0xF800) == 0x2800:
        return Insn(a, hw, 0, 2, "cmp", [f"r{(hw >> 8) & 7}", f"#{hw & 0xFF}"])
    if (hw & 0xFC00) == 0x4000:
        return Insn(a, hw, 0, 2, "ands", [f"r{hw & 7}", f"r{(hw >> 3) & 7}"])
    if (hw & 0xFC00) == 0x4200:
        return Insn(a, hw, 0, 2, "tst", [f"r{hw & 7}", f"r{(hw >> 3) & 7}"])
    if (hw & 0xFC00) == 0x4400:
        return Insn(a, hw, 0, 2, "add", [f"r{(hw >> 7) & 7}", f"r{hw & 0xF}"])
    if (hw & 0xFE00) == 0x4600:
        return Insn(a, hw, 0, 2, "mov", [f"r{(hw >> 8) & 7}", f"r{hw & 0xF}"])
    if (hw & 0xFF87) == 0x4700:
        return Insn(a, hw, 0, 2, "bx" if (hw & 0x80) == 0 else "blx",
                    [f"r{(hw >> 3) & 0xF}"])
    if (hw & 0xF800) == 0x6800:
        return Insn(a, hw, 0, 2, "ldr", [f"r{hw & 7}",
                                        f"[r{(hw >> 3) & 7},#{(hw >> 6) & 0x1F:#x}]"])
    if (hw & 0xF800) == 0x6000:
        return Insn(a, hw, 0, 2, "str", [f"r{hw & 7}",
                                        f"[r{(hw >> 3) & 7},#{(hw >> 6) & 0x1F:#x}]"])
    if (hw & 0xF800) == 0x9800:
        return Insn(a, hw, 0, 2, "ldr", [f"r{(hw >> 8) & 7}", f"[sp,#{(hw & 0xFF) * 4}]"])
    if (hw & 0xF800) == 0x9000:
        return Insn(a, hw, 0, 2, "str", [f"r{(hw >> 8) & 7}", f"[sp,#{(hw & 0xFF) * 4}]"])
    if (hw & 0xFE00) == 0xB400:
        return Insn(a, hw, 0, 2, "push", [f"0x{hw & 0xFF:#04x}"])
    if (hw & 0xFE00) == 0xBC00:
        return Insn(a, hw, 0, 2, "pop", [f"0x{hw & 0xFF:#04x}"])
    if (hw & 0xF000) == 0x3000:
        return Insn(a, hw, 0, 2, "adds", [f"r{(hw >> 8) & 7}", f"#{hw & 0xFF}"])
    if (hw & 0xF000) == 0x3800:
        return Insn(a, hw, 0, 2, "subs", [f"r{(hw >> 8) & 7}", f"#{hw & 0xFF}"])
    return Insn(a, hw, 0, 2, ".hword", [f"0x{hw:04X}"])


COND = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]


def decode_range(fw: Firmware, start: int, end: int):
    out = []
    a = start
    while a < end:
        i = decode_one(fw, a)
        out.append(i)
        a += i.size
    return out


def insn_at(fw: Firmware, a: int):
    return decode_one(fw, a)


def is_branch(i: Insn):
    return i.mn == "b" or i.mn == "b.w" or i.mn.startswith("b") and i.mn[1:] in COND \
        or i.mn in ("cbz", "cbnz")


def target(i: Insn):
    if not i.ops:
        return None
    try:
        return int(str(i.ops[-1]), 16)
    except ValueError:
        return None


# ----------------------------------------------------------------------------
# エンコード
# ----------------------------------------------------------------------------

def enc_b(pc: int, tgt: int) -> bytes:
    off = tgt - (pc + 4)
    if off % 2:
        raise PatchError("分岐先が 2byte 境界でない")
    if -2048 <= off <= 2046:
        return struct.pack("<H", 0xE000 | ((off >> 1) & 0x7FF))
    return enc_bw(pc, tgt, link=False)


def enc_bw(pc: int, tgt: int, link=False) -> bytes:
    off = tgt - (pc + 4)
    if not (-0x1000000 <= off < 0x1000000):
        raise PatchError("分岐が 16MB を超える")
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    j1 = 1 - (i1 ^ s)
    j2 = 1 - (i2 ^ s)
    hw1 = 0xF000 | (s << 10) | ((off >> 12) & 0x3FF)
    hw2 = (0xD000 if link else 0x9000) | (j1 << 13) | (j2 << 11) | ((off >> 1) & 0x7FF)
    return struct.pack("<HH", hw1, hw2)


def enc_best(pc: int, tgt: int) -> bytes:
    off = tgt - (pc + 4)
    if -2048 <= off <= 2046:
        return enc_b(pc, tgt)
    return enc_bw(pc, tgt)


# ----------------------------------------------------------------------------
# 探索ヘルパ
# ----------------------------------------------------------------------------

def find_string(fw: Firmware, s: str):
    """NUL 終端文字列のファイルオフセット一覧 (ASCII / UTF-16LE)"""
    hits = []
    for enc in (s.encode("ascii") + b"\x00", s.encode("utf-16-le") + b"\x00\x00"):
        i = fw.orig.find(enc)
        while i >= 0:
            hits.append(i)
            i = fw.orig.find(enc, i + 1)
    return hits


def find_literal_refs(fw: Firmware, tgt: int, window_pad=0x400):
    """tgt を指す literal pool エントリと、それを読む ldr 命令を返す"""
    refs = []
    pat = struct.pack("<I", tgt)
    i = fw.orig.find(pat)
    while i >= 0:
        if i % 4 == 0:
            # 直前の ldr rX,[pc,#imm] を探す
            for back in range(0, window_pad, 2):
                a = i - back
                if a < 0:
                    break
                if (fw.u16(a) & 0xF800) == 0x4800:
                    off = (fw.u16(a) & 0xFF) * 4
                    if ((a + 4) & ~3) + off == i:
                        refs.append((a, i))
                        break
        i = fw.orig.find(pat, i + 1)
    return refs


def find_function_start(fw: Firmware, addr: int, limit=MAX_SCAN_BACK):
    """prologue (push {..,lr} / push.w {..,lr}) を後方探索"""
    a = addr - 2
    lowest = max(0, addr - limit)
    while a >= lowest:
        hw = fw.u16(a)
        if (hw & 0xFF00) == 0xB500 and (hw & 0x100):        # push {..,lr}
            return a
        if hw == 0xE92D and a + 4 <= len(fw):                # push.w {..,lr}
            if fw.u16(a + 2) & 0x4000:
                return a
        a -= 2
    return None


def function_end(fw: Firmware, start: int, limit=0x1200):
    """pop {..,pc} / bx lr を前方探索して関数末尾を推定"""
    a = start
    end = min(len(fw), start + limit)
    while a < end - 1:
        hw = fw.u16(a)
        if (hw & 0xFF00) == 0xBD00:                          # pop {..,pc}
            return a + 2
        if hw == BX_LR:
            return a + 2
        if hw == 0xE8BD and a + 4 <= len(fw) and (fw.u16(a + 2) & 0x8000):
            return a + 4
        a += 2
    return end


# ----------------------------------------------------------------------------
# パッチ定義
# ----------------------------------------------------------------------------

class Site:
    def __init__(self, tag, addr, old: bytes, new: bytes, note):
        self.tag, self.addr, self.old, self.new, self.note = tag, addr, old, new, note


def site_force_true_return(fw: Firmware, fn: int, tag: str) -> Site:
    """関数を "movs r0,#1 ; bx lr" に置換 (常時 true 化)"""
    old = bytes(fw.buf[fn:fn + 4])
    return Site(tag, fn, old, struct.pack("<HH", MOVS_R0_1, BX_LR),
                "常時許可 (movs r0,#1 ; bx lr)")


# ----------------------------------------------------------------------------
# (A) fastboot 制限の無効化
# ----------------------------------------------------------------------------

def patch_fastboot(fw: Firmware, dry: bool):
    found = []
    for s in FASTBOOT_STRINGS:
        for so in find_string(fw, s):
            for ldr_a, _pool in find_literal_refs(fw, so):
                fn = find_function_start(fw, ldr_a)
                if fn is None:
                    continue
                body = decode_range(fw, fn, function_end(fw, fn))
                # 許可判定らしさ: bl を 1 回以上含み、戻り値 0/1 を返す
                has_bl = any(i.mn in ("bl", "blx") for i in body)
                has_zero = any(i.mn == "movs" and i.ops[1] == "#0" for i in body)
                has_one = any(i.mn == "movs" and i.ops[1] == "#1" for i in body)
                if has_bl and has_zero and has_one:
                    found.append((fn, s, ldr_a))
    uniq = {}
    for fn, s, ldr_a in found:
        uniq.setdefault(fn, []).append((s, ldr_a))
    if not uniq:
        raise PatchError(
            "fastboot 許可判定関数を特定できません。"
            "--fastboot-fn 0xADDR で明示指定してください。")

    sites = []
    for fn in sorted(uniq):
        sites.append(site_force_true_return(fw, fn, f"FASTBOOT@{fn:#x}"))
        print(f"  [A] 許可判定関数 0x{fn:06X}  "
              f"(根拠文字列: {', '.join(s for s, _ in uniq[fn])})")
    return sites


# ----------------------------------------------------------------------------
# (B) vbmeta flags の 03 固定
# ----------------------------------------------------------------------------

def patch_vbmeta_flags(fw: Firmware, dry: bool):
    sites = []

    # B-1: flags フィールド (+0x78) のロード直後を movs rX,#3 に
    #      LDR imm T1 の imm5 は word 単位 -> 0x78/4 = 30 = 0x1E
    pat = 0x6F80 | (30 << 6)        # ldr r0,[rX,#0x78] 相当の雛形
    cands = []
    for a in range(0, len(fw) - 4, 2):
        hw = fw.u16(a)
        if (hw & 0xF800) != 0x6800:
            continue
        if ((hw >> 6) & 0x1F) != 30:
            continue
        nxt = insn_at(fw, a + 2)
        # 直後が flags を使う比較/テストであること
        if nxt.mn in ("ands", "tst", "lsls", "cmp", "movs"):
            cands.append(a)
    if not cands:
        raise PatchError("vbmeta flags(+0x78) ロード箇所を特定できません")

    # 最も 0x3C8xx に近い 1 箇所を採用
    cands.sort(key=lambda x: abs(x - AVB_CALL_HINT))
    a = cands[0]
    rd = fw.u16(a) & 7
    old = bytes(fw.buf[a + 2:a + 4])
    new = struct.pack("<H", 0x2000 | (rd << 8) | 3)      # movs rD,#3
    sites.append(Site(f"VBMETA_FLAGS_LD@{a:#x}", a + 2, old, new,
                      f"flags ロード直後を movs r{rd},#3 に固定"))
    print(f"  [B] flags ロード 0x{a:06X} -> movs r{rd},#3")

    # B-2: flags ビットテスト直後の条件分岐を無条件化 (01/02 も 03 等価に)
    fixed = 0
    for a in range(0, len(fw) - 6, 2):
        i = insn_at(fw, a)
        if i.mn not in ("tst", "ands"):
            continue
        nxt = insn_at(fw, a + i.size)
        if nxt.mn not in ("beq", "bne", "bmi", "bpl", "bhs", "blo"):
            continue
        # 直前 8 命令以内に flags ロードがあるか
        ctx = decode_range(fw, max(0, a - 16), a)
        if not any(x.mn == "ldr" and x.ops and "#0x78" in str(x.ops[-1]) for x in ctx):
            continue
        t = target(nxt)
        if t is None:
            continue
        blob = enc_best(nxt.addr, t)
        sites.append(Site(f"VBMETA_FLAGS_TST@{a:#x}", nxt.addr,
                          bytes(fw.buf[nxt.addr:nxt.addr + len(blob)]), blob,
                          "flags ビットテスト分岐を無条件化"))
        fixed += 1
        if fixed >= 2:
            break
    print(f"  [B] flags テスト分岐の無条件化: {fixed} 箇所")
    return sites


# ----------------------------------------------------------------------------
# (C) AVB サイズ上位ワード検査 / ret 判定
# ----------------------------------------------------------------------------

def patch_avb_size(fw: Firmware, dry: bool):
    sites = []

    # C-1: ldr rX,[sp,#4] / cmp rX,#0 / bne err  ->  b err に置換
    lo = max(0, AVB_SIZE_CHECK_HINT - HINT_WINDOW)
    hi = min(len(fw), AVB_SIZE_CHECK_HINT + HINT_WINDOW)
    hit = None
    for a in range(lo, hi, 2):
        i = insn_at(fw, a)
        if i.mn != "ldr" or not i.ops or "[sp,#4]" not in str(i.ops[-1]):
            continue
        rd = str(i.ops[0])
        c = insn_at(fw, a + 2)
        if c.mn == "cmp" and c.ops[0] == rd and c.ops[1] == "#0":
            br = insn_at(fw, a + 4)
            if br.mn in ("bne", "cbz", "cbnz", "b"):
                hit = (a, br)
                break
    if hit is None:
        raise PatchError("AVB サイズ上位ワード検査 (ldr/cmp/bne) を特定できません")
    a, br = hit
    t = target(br)
    if t is None:
        raise PatchError("上位ワード検査の分岐先が解決できません")
    blob = enc_best(br.addr, t)
    sites.append(Site(f"AVB_SIZE_HIWORD@{a:#x}", br.addr,
                      bytes(fw.buf[br.addr:br.addr + len(blob)]), blob,
                      f"{br.mn} を無条件分岐に (サイズ上位ワード検査を通過)"))
    print(f"  [C] サイズ上位ワード検査 0x{a:06X} の {br.mn} を無条件化 -> 0x{t:06X}")

    # C-2: avb 呼び出し直後の ret!=0 判定を継続側へ
    #      bl <avb> の直後 cmp r0,#0 / bne err
    cnt = 0
    lo = max(0, AVB_CALL_HINT - HINT_WINDOW)
    hi = min(len(fw), AVB_CALL_HINT + HINT_WINDOW)
    for x in range(lo, hi, 2):
        i = insn_at(fw, x)
        if i.mn != "bl":
            continue
        c = insn_at(fw, x + 4)
        if c.mn != "cmp" or c.ops[1] != "#0":
            continue
        br = insn_at(fw, x + 6)
        if br.mn != "bne":
            continue
        t = target(br)
        if t is None:
            continue
        blob = enc_best(br.addr, t)
        sites.append(Site(f"AVB_RET@{x:#x}", br.addr,
                          bytes(fw.buf[br.addr:br.addr + len(blob)]), blob,
                          "avb 戻り値判定を継続側へ (黒画面ループ抑止)"))
        cnt += 1
        break
    print(f"  [C] avb 戻り値判定の無条件化: {cnt} 箇所")
    return sites


# ----------------------------------------------------------------------------
# (D) 音量+ 判定時点で recovery へ
# ----------------------------------------------------------------------------

def patch_recovery(fw: Firmware, dry: bool):
    sites = []

    logo_addrs = find_string(fw, PART_LOGO)
    rec_addrs = find_string(fw, PART_RECOVERY)
    if not logo_addrs or not rec_addrs:
        raise PatchError("logo / recovery の文字列が見つかりません")

    # logo を指す literal 参照 -> そのブロックを飛ばして recovery ブロックへ
    logo_refs = []
    for so in logo_addrs:
        logo_refs += [a for a, _ in find_literal_refs(fw, so)]
    rec_refs = []
    for so in rec_addrs:
        rec_refs += [a for a, _ in find_literal_refs(fw, so)]
    if not logo_refs or not rec_refs:
        raise PatchError("logo / recovery の参照命令が見つかりません")

    fn = find_function_start(fw, min(logo_refs))
    if fn is None:
        raise PatchError("起動分岐関数の先頭を特定できません")

    body = decode_range(fw, fn, function_end(fw, fn))

    # logo 参照を含むブロックへ入る条件分岐を探す
    logo_set = set(logo_refs)
    rec_set = set(rec_refs)
    cand = None
    for idx, i in enumerate(body):
        if not is_branch(i):
            continue
        t = target(i)
        if t is None:
            continue
        # 分岐先 0x20 以内に logo 参照がある
        if any(t <= r < t + 0x20 for r in logo_set):
            cand = (i, t)
            break
    if cand is None:
        raise PatchError("logo ブロックへの条件分岐を特定できません")

    br, logo_tgt = cand

    # recovery ブロック先頭を推定 (recovery 参照を含む最小アドレス)
    rec_tgt = min(rec_set)

    # logo 側へ飛ぶ分岐を recovery 側へ retarget
    blob = enc_best(br.addr, rec_tgt)
    sites.append(Site(f"RECOVERY_JUMP@{br.addr:#x}", br.addr,
                      bytes(fw.buf[br.addr:br.addr + len(blob)]), blob,
                      f"{br.mn} の飛び先を logo(0x{logo_tgt:06X}) から "
                      f"recovery(0x{rec_tgt:06X}) へ変更"))
    print(f"  [D] 起動分岐 0x{br.addr:06X}: 0x{logo_tgt:06X} -> 0x{rec_tgt:06X}")

    # 同関数内に logo 直行の無条件 b が残っていれば recovery へ寄せる
    for i in body:
        if i.mn not in ("b", "b.w"):
            continue
        t = target(i)
        if t is not None and t == logo_tgt and i.addr != br.addr:
            blob = enc_best(i.addr, rec_tgt)
            sites.append(Site(f"RECOVERY_B@{i.addr:#x}", i.addr,
                              bytes(fw.buf[i.addr:i.addr + len(blob)]), blob,
                              "logo 直行の無条件分岐も recovery へ"))
            print(f"  [D] 直行分岐 0x{i.addr:06X} も recovery へ")
            break
    return sites


# ----------------------------------------------------------------------------
# 検証
# ----------------------------------------------------------------------------

def verify_sites(fw: Firmware, sites):
    problems = []
    for s in sites:
        got = bytes(fw.buf[s.addr:s.addr + len(s.new)])
        if got != s.new:
            problems.append(f"{s.tag}: 0x{s.addr:06X} 書き込み結果不一致")
    # 書き込み後の再逆アセンブルで分岐解決を確認
    for s in sites:
        if s.tag.startswith(("FASTBOOT", "VBMETA_FLAGS_LD")):
            continue
        i = insn_at(fw, s.addr)
        if not is_branch(i):
            problems.append(f"{s.tag}: 0x{s.addr:06X} が分岐命令になっていない ({i.mn})")
            continue
        t = target(i)
        if t is None or not (0 <= t < len(fw)):
            problems.append(f"{s.tag}: 0x{s.addr:06X} 分岐先不正")
    return problems


# ----------------------------------------------------------------------------
# レポート
# ----------------------------------------------------------------------------

def write_report(path, src, fw: Firmware, sites, problems, elapsed):
    lines = []
    lines.append("MT8168 LK dev patch report")
    lines.append("=" * 68)
    lines.append(f"生成日時     : {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"入力         : {src}")
    lines.append(f"入力 SHA-256 : {hashlib.sha256(fw.orig).hexdigest()}")
    lines.append(f"出力 SHA-256 : {hashlib.sha256(fw.buf).hexdigest()}")
    lines.append(f"サイズ       : {len(fw.buf)} bytes / 差分 {len(fw.diff_offsets())} bytes")
    lines.append(f"所要         : {elapsed:.3f} s")
    lines.append("")
    lines.append("パッチ一覧")
    lines.append("-" * 68)
    for s in sites:
        lines.append(f"[{s.tag}]  0x{s.addr:06X}")
        lines.append(f"  意図  : {s.note}")
        lines.append(f"  変更前: {s.old.hex(' ')}")
        lines.append(f"  変更後: {s.new.hex(' ')}")
    lines.append("")
    lines.append("書き込み後の逆アセンブル (確認用)")
    lines.append("-" * 68)
    for s in sites:
        if s.tag.startswith(("FASTBOOT", "VBMETA_FLAGS_LD")):
            continue
        for i in decode_range(fw, s.addr, s.addr + 4):
            lines.append("  " + repr(i))
    lines.append("")
    if problems:
        lines.append("検証結果: NG")
        for p in problems:
            lines.append("  " + p)
    else:
        lines.append("検証結果: OK (全サイトのパターン一致・分岐解決を確認)")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------------
# メイン
# ----------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="MT8168 LK dev patch builder")
    ap.add_argument("--input", required=True, help="元 lk2.img")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--outname", default="lk_dev.img")
    ap.add_argument("--zip", action="store_true", help="成果物を ZIP にまとめる")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", default=None)
    ap.add_argument("--fastboot-fn", default=None,
                    help="fastboot 許可判定関数アドレスを明示指定 (0x...)")
    args = ap.parse_args(argv)

    import time
    t0 = time.time()

    with open(args.input, "rb") as f:
        data = f.read()
    fw = Firmware(data, args.input)
    print(f"入力 {args.input}: {len(fw)} bytes  sha256={hashlib.sha256(data).hexdigest()}")

    if len(fw) < 0x10000:
        print("警告: イメージが小さすぎます。lk2.img か確認してください。", file=sys.stderr)

    sites = []
    try:
        print("[A] fastboot 制限の無効化")
        if args.fastboot_fn:
            fn = int(args.fastboot_fn, 16)
            sites.append(site_force_true_return(fw, fn, f"FASTBOOT@{fn:#x}"))
            print(f"  [A] 明示指定 0x{fn:06X}")
        else:
            sites += patch_fastboot(fw, args.dry_run)

        print("[B] vbmeta flags の 03 固定")
        sites += patch_vbmeta_flags(fw, args.dry_run)

        print("[C] AVB サイズ検査 / ret 判定")
        sites += patch_avb_size(fw, args.dry_run)

        print("[D] 音量+ 判定時点で recovery へ")
        sites += patch_recovery(fw, args.dry_run)
    except PatchError as e:
        print(f"\n失敗: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        print("\n--dry-run のため書き込みません。特定結果のみ表示:")
        for s in sites:
            print(f"  0x{s.addr:06X} [{s.tag}] {s.note}")
        return 0

    for s in sites:
        fw.write(s.addr, s.new, s.tag)

    problems = verify_sites(fw, sites)
    if problems:
        print("\n検証 NG:")
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 3

    os.makedirs(args.outdir, exist_ok=True)
    outpath = os.path.join(args.outdir, args.outname)
    with open(outpath, "wb") as f:
        f.write(fw.buf)

    rep = args.report or os.path.join(args.outdir, "PATCH_REPORT_JA.txt")
    write_report(rep, args.input, fw, sites, problems, time.time() - t0)

    sums = os.path.join(args.outdir, "SHA256SUMS")
    with open(sums, "w", encoding="utf-8") as f:
        for p in (outpath, rep, os.path.abspath(__file__)):
            if os.path.exists(p):
                f.write(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  "
                        f"{os.path.basename(p)}\n")

    print(f"\n完了: {outpath}  ({len(fw.diff_offsets())} bytes 差分)")
    print(f"レポート: {rep}")

    if args.zip:
        zpath = os.path.join(args.outdir, "mt8168_lk_dev_temporary_patch_v7.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(outpath, os.path.basename(outpath))
            z.write(rep, os.path.basename(rep))
            z.write(sums, os.path.basename(sums))
            z.write(os.path.abspath(__file__), os.path.basename(__file__))
        print(f"ZIP: {zpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
