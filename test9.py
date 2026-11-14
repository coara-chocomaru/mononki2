#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
brom_drop.py  v1  —  preloader(META, 0e8d:2000) から RAM を破壊して BROM(0e8d:0003) へ落とす
================================================================================
test6.py (mode_tool.py v7) の Link / handshake / 0xD0..0xFE コマンド層を流用。
相違点は「モード切替」ではなく「RAM 破壊 → BROM 再列挙」に特化した点のみ。

【アセンブリ根拠 (preloader_a04br3 / 0x00000000-0x000043FF 実読分)】
  dispatch (0x1618): 1byte オペコードループ。失敗しても 0x16CC で無条件継続。
  0xD4 WRITE32 (0x19DA): addr + word count を echo → 0x1761C(r2=0) → u16(0)
                          → cnt×u32 (echo 付) → u16(final)
                          ★ アドレス整列は ands r2,r0,#3 で検査 (0x19DE-0x19E2)
  0xD5 JUMP   (0x18D8): addr を echo → u16(final) → blx  … 無条件
                          ★ ここが任意コード実行点
  0xD1 READ32 (0x197E): 整列必須 (lsls r3,r0,#0x1e / bne)
  0x1918-0x1942: ハンドオフ。再検証なし → RAM 改変がそのまま実行に反映される
  0x1928/0x192C/0x1930/0x1934: D-cache clean&inv, I-cache inv (blx 0x408/0x41c/0x414/0x434)
  → スタブ配置後はキャッシュ操作を自前で行う必要がある (下記 stub に内蔵)

【戦略ラダー】
  1) stub-drop   : 0x40001000 に ARM スタブ → 0xD5 で遷移
                   スタブが 0x0-0x10000 を 0xFFFFFFFF で埋め、
                   RTC_PDN1[5:0]=不正値, WDT_MODE/RESTART/SWRST を叩いて自壊
  2) brom-jump   : スタブを使わず BROM USB DL エントリ候補へ直接 0xD5
  3) plain-reset : 高域スクラブ + RTC 不正値 + WDT のみ
  各段の後 0e8d:0003 を一定時間ポーリング。出たら成功で確定。

【注意】
  - 115200 固定。0xD4 は 1 word ごとに echo が返るため高域スクラブは低速 (既定 off)。
  - 0x40001000 は DRAM。書込可否は --probe で先に確認できる。
  - BROM のエントリ番地は未確定。--brom-entry で複数指定可。
================================================================================
"""

import argparse
import os
import struct
import sys
import time

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
    try:
        p = s.Serial(port="__none__", baudrate=9600, timeout=0.01, write_timeout=0.01)
        p.close()
        SERIAL_CLS = s.Serial
    except TypeError:
        SERIAL_CLS = s.Serial
    except Exception:
        SERIAL_CLS = s.Serial
    return True


MTK_VID = 0x0E8D
PRE_PIDS = (0x2000, 0x2001, 0x201C, 0x3000, 0x2003, 0x201D, 0x6000, 0x20FF)
BROM_PIDS = (0x0003, 0x0006, 0x0007)
KW = ("mtk", "mediatek", "preloader", "vcom", "cdc", "usb port", "brom")

CMD_READ16 = 0xD0
CMD_READ32 = 0xD1
CMD_WRITE16 = 0xD2
CMD_WRITE32 = 0xD4
CMD_JUMP = 0xD5
CMD_SEND_DA = 0xD7
CMD_STATUS = 0xD8
CMD_PING = 0xFE

PATTERN_HINT = [0xA0, 0x0A, 0x50, 0x05]
PATTERN_EXTRA = [
    (0xA0, 0x0A, 0x50, 0x05),
    (0x50, 0x0A, 0xA0, 0x05),
    (0xA0, 0x05, 0x50, 0x0A),
    (0x05, 0x0A, 0xA0, 0x50),
]
HSHK_BYTE_TO = 0.5
HSHK_GAP = 0.05
HSHK_MAX = 5000
HSHK_BOOT_DELAY = 0.8

BAUD = 115200
IO_TO = 1.0
WR_TO = 6.0

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
STUB = 0x40001000

# スタブが潰す範囲 (0x0-0x10000 = 64KB)。ディスパッチャ 0x1618 を含む。
SCRUB_START = 0x00000000
SCRUB_WORDS = 0x4000

# RTC 不正値 (0x3F = MODE_MASK 全立。preloader が解釈できず BROM 側で停止し易い)
BAD_MODE = 0x3F

# BROM USB DL エントリ候補 (SoC 依存 / probe 前提)
BROM_ENTRIES = (0x00000000, 0x00000008, 0x00000100)

PRE_BASE_CANDIDATES = (0x00200000, 0x00201000, 0x000C0000, 0x40080000)


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
# リンク (test6.py から流用)
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
        time.sleep(HSHK_BOOT_DELAY)
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

    def _disc(self, e):
        s = str(e).lower()
        return ("cannot configure port" in s or "permissionerror" in s
                or "access is denied" in s or "clearcommerror" in s
                or "returned 31" in s or "機能していません" in str(e))

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
            if self._disc(e):
                self.dead = True
            raise LinkError(f"tx: {e}")

    def handshake(self, pattern=None):
        if pattern is not None:
            got = self._try_pattern(list(pattern))
            if got is not None:
                return got
            raise LinkError(f"handshake failed {[hex(x) for x in pattern]}")
        for pat in PATTERN_EXTRA:
            got = self._try_pattern(list(pat))
            if got is not None:
                return got
            time.sleep(HSHK_GAP)
        return self._scan_pattern()

    def _try_pattern(self, pat, tries=3):
        for _ in range(tries):
            self.flush_in()
            ok = True
            got = []
            for b in pat:
                self.tx(bytes([b]))
                r = self.rx(1, HSHK_BYTE_TO)
                if len(r) != 1 or r[0] != (b ^ 0xFF):
                    ok = False
                    break
                got.append(b)
            if ok and len(got) == len(pat):
                return got
            time.sleep(HSHK_GAP)
        return None

    def _scan_pattern(self):
        prefix, guess, steps, stale = [], PATTERN_HINT[0], 0, 0
        while steps < HSHK_MAX:
            seq = prefix + [guess]
            self.flush_in()
            pos, done = 0, True
            for b in seq:
                if steps >= HSHK_MAX:
                    done = False
                    break
                steps += 1
                self.tx(bytes([b]))
                r = self.rx(1, HSHK_BYTE_TO)
                if len(r) != 1:
                    done = False
                    break
                v = r[0]
                if v == (b ^ 0xFF):
                    pos += 1
                    stale = 0
                    continue
                if v == ((b + 1) & 0xFF):
                    prefix, guess, stale = seq[:pos], v, 0
                    done = False
                    break
                stale += 1
                if stale > 4:
                    prefix, guess, stale = [], (guess + 1) & 0xFF, 0
                done = False
                break
            if done and pos == len(seq):
                if len(seq) == 4:
                    return seq
                prefix, guess = seq, PATTERN_HINT[len(seq)]
            time.sleep(HSHK_GAP)
        raise LinkError("handshake failed")

    def echo(self, data, tag="e", timeout=None):
        self.tx(data)
        got = self.rx(len(data), timeout)
        if got != data:
            raise LinkError(f"{tag}: {data.hex()} != {got.hex()}")

    def begin(self, op, addr, cnt, tag, timeout=None):
        self.echo(bytes([op]), tag, timeout)
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), tag + ".a", timeout)
        self.echo(struct.pack(">I", cnt & 0xFFFFFFFF), tag + ".n", timeout)

    def _u16(self, timeout=None):
        d = self.rx(2, timeout or IO_TO)
        if len(d) != 2:
            raise LinkError(f"status short {len(d)}/2")
        return struct.unpack(">H", d)[0]

    def read32(self, addr, cnt, timeout=15.0):
        self.begin(CMD_READ32, addr, cnt, "read32", timeout)
        pre = self._u16(timeout)
        if pre != 0:
            raise LinkError(f"read32 pre 0x{pre:04X}")
        out = []
        while len(out) < cnt:
            d = self.rx(min(0x400, cnt - len(out)) * 4, timeout)
            n = len(d) // 4
            if n == 0:
                break
            out.extend(struct.unpack(">%dI" % n, d[:n * 4]))
        if len(out) != cnt:
            raise LinkError(f"read32 short {len(out)}/{cnt}")
        post = self._u16(1.0)
        if post != 0:
            raise LinkError(f"read32 post 0x{post:04X}")
        return out

    def read_u32(self, addr):
        return self.read32(addr, 1, timeout=4.0)[0]

    def write32(self, addr, vals, verify=True, timeout=8.0):
        if addr & 3:
            raise LinkError("write32: 4byte 整列必須")
        self.begin(CMD_WRITE32, addr, len(vals), "write32", timeout)
        pre = self._u16(timeout)
        if pre != 0:
            raise LinkError(f"write32 pre 0x{pre:04X}")
        for v in vals:
            self.echo(struct.pack(">I", v & 0xFFFFFFFF), "write32.d", timeout)
        post = self._u16(timeout)
        if post != 0:
            raise LinkError(f"write32 post 0x{post:04X}")
        if verify:
            back = self.read32(addr, len(vals), timeout=5.0)
            if back != [v & 0xFFFFFFFF for v in vals]:
                raise LinkError(f"write32 検証不一致 @0x{addr:08X}")

    def set32(self, addr, val, verify=True):
        self.write32(addr, [val], verify=verify)

    def jump(self, addr, timeout=2.5):
        self.echo(bytes([CMD_JUMP]), "jump")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "jump.a")
        return self._u16(timeout)

    def status(self):
        self.tx(bytes([CMD_STATUS]))
        e = self.rx(1, 1.0)
        if not e or e[0] != CMD_STATUS:
            raise LinkError("status echo 異常")
        time.sleep(0.05)
        rest = self.rx(6, 0.5)
        if len(rest) == 6:
            return struct.unpack(">H", rest[4:6])[0]
        if len(rest) >= 2:
            return struct.unpack(">H", rest[-2:])[0]
        raise LinkError("status 応答長 異常")

    def ping(self):
        self.tx(bytes([CMD_PING]))
        return self.rx(1, 0.5) == b"\x01"


# ================================================================
# ARM エンコーダ
# ================================================================
B_SELF = 0xEAFFFFFE
I_DCCISW = 0xEE070F1E      # mcr p15,0,pc,c7,c14,0   D-cache clean&inv
I_ICIALLU = 0xEE070F15     # mcr p15,0,pc,c7,c5,0    I-cache inv all
I_DSB = 0xEE070F9A         # mcr p15,0,pc,c7,c10,4   DSB


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


def build_drop_stub(scrub_start=SCRUB_START, scrub_words=SCRUB_WORDS,
                    bad_mode=BAD_MODE, feed_wdt_first=True):
    """0x40001000 用スタブ。

    1. D-cache/I-cache を落として自分を可視化
    2. [scrub_start, +scrub_words*4) を 0xFFFFFFFF で埋める (ディスパッチャ含む)
    3. RTC BBPU unlock → PDN1[5:0]=bad_mode → BBPU lock
    4. WDT_MODE / WDT_RESTART / WDT_SWRST
    5. b .
    """
    w = []
    w.append(I_DCCISW)
    w.append(I_ICIALLU)
    w.append(I_DSB)

    # --- scrub loop ---
    w.append(_movw(4, scrub_start & 0xFFFF))
    w.append(_movt(4, scrub_start))
    w.append(_mvn(5, 0))                      # r5 = 0xFFFFFFFF
    w.append(_movw(6, scrub_words & 0xFFFF))
    w.append(_movt(6, scrub_words))
    w.append(0xE4845004)                      # str r5, [r4], #4
    w.append(0xE2566001)                      # subs r6, r6, #1
    w.append(0x1AFFFFFB)                      # bne -8
    w.append(I_DSB)

    # --- RTC: unlock / PDN1 / lock ---
    w.append(_movw(0, RTC_BASE & 0xFFFF))
    w.append(_movt(0, RTC_BASE))
    w.append(_movw(1, RTC_KEY & 0xFFFF))
    w.append(_movt(1, RTC_KEY))
    w.append(_str_off(1, 0, 0x08))            # BBPU = key
    w.append(_movw(1, bad_mode & 0xFFFF))
    w.append(_movt(1, 0))
    w.append(_str_off(1, 0, 0x1C))            # PDN1 = bad_mode
    w.append(_movw(1, 0))
    w.append(_str_off(1, 0, 0x08))            # BBPU = 0 (lock)

    # --- WDT ---
    w.append(_movw(0, WDT_MODE & 0xFFFF))
    w.append(_movt(0, WDT_MODE))
    if feed_wdt_first:
        w.append(_movw(1, WDT_RESTART_KEY))
        w.append(_str_off(1, 0, 0x08))
    w.append(_movw(1, (WDT_MODE_KEY | 0x14) & 0xFFFF))
    w.append(_movt(1, (WDT_MODE_KEY | 0x14)))
    w.append(_str_off(1, 0, 0x00))            # WDT_MODE
    w.append(_movw(1, WDT_RESTART_KEY))
    w.append(_str_off(1, 0, 0x08))            # WDT_RESTART
    w.append(_movw(1, WDT_SWRST_KEY))
    w.append(_str_off(1, 0, 0x14))            # WDT_SWRST
    w.append(B_SELF)
    return words_to_bytes(w)


# ================================================================
# 実行段
# ================================================================
def probe(port, pattern):
    with Link(port) as l:
        l.handshake(pattern)
        log(f"status=0x{l.status():04X}", ".")
        for name, addr in (("STUB", STUB), ("RTC_PDN1", RTC_PDN1),
                           ("WDT_MODE", WDT_MODE)):
            try:
                log(f"READ {name} @0x{addr:08X} = 0x{l.read_u32(addr):08X}", "+")
            except LinkError as e:
                log(f"READ {name} @0x{addr:08X} NG: {e}", "!")
        try:
            l.set32(STUB, 0xEAFFFFFE, verify=True)
            log(f"STUB @0x{STUB:08X} 書込/読戻し OK", "+")
        except LinkError as e:
            log(f"STUB 書込 NG: {e}", "!")
        for base in PRE_BASE_CANDIDATES:
            try:
                log(f"pre_base 候補 0x{base:08X} = 0x{l.read_u32(base):08X}", ".")
            except LinkError as e:
                log(f"pre_base 候補 0x{base:08X} NG: {e}", ".")


def strategy_stub_drop(port, pattern, bad_mode, scrub_words, wait_brom,
                       scrub_high):
    """本命: スタブを置いて飛ばし、スタブ側で RAM 破壊 + RTC 不正 + WDT。"""
    l = Link(port).open()
    try:
        l.handshake(pattern)
        try:
            log(f"status=0x{l.status():04X}", ".")
        except LinkError as e:
            log(f"status NG: {e}", ".")

        stub = build_drop_stub(bad_mode=bad_mode, scrub_words=scrub_words)
        log(f"stub {len(stub)} bytes @0x{STUB:08X} 書込", ".")
        l.write32(STUB, list(struct.unpack("<%dI" % (len(stub) // 4), stub)),
                  verify=True)
        log("stub 読戻し一致", "+")

        if scrub_high:
            n = scrub_high // 4
            log(f"高域スクラブ 0x{SCRUB_START + scrub_words * 4:08X} から "
                f"{scrub_high} bytes", ".")
            addr = SCRUB_START + scrub_words * 4
            left = n
            while left > 0:
                k = min(0x800, left)
                try:
                    l.write32(addr, [0xFFFFFFFF] * k, verify=False, timeout=30.0)
                except LinkError as e:
                    log(f"高域スクラブ中断 @0x{addr:08X}: {e}", "!")
                    break
                addr += k * 4
                left -= k
            log("高域スクラブ完了", "+")

        log(f"0xD5 JUMP -> 0x{STUB:08X}", ".")
        try:
            st = l.jump(STUB)
            log(f"jump status=0x{st:04X}", ".")
        except LinkError as e:
            log(f"jump 応答なし (想定内): {e}", ".")
    finally:
        try:
            l.close()
        except Exception:
            pass

    hit = wait_for_pids(BROM_PIDS, wait_brom, "BROM(0e8d:0003)")
    if hit:
        log(f"BROM 検出: {hit[0]} 0e8d:{hit[1]:04x}", "+")
        return True
    return False


def strategy_brom_jump(port, pattern, entries, wait_brom):
    """BROM USB DL エントリへ直接 JUMP を撃つ。"""
    for e in entries:
        log(f"0xD5 JUMP -> 0x{e:08X} (BROM 候補)", ".")
        try:
            l = Link(port).open()
        except LinkError as ex:
            log(f"open 失敗: {ex}", "!")
            return False
        try:
            l.handshake(pattern)
            try:
                l.jump(e)
            except LinkError as ex:
                log(f"jump 応答なし: {ex}", ".")
        finally:
            try:
                l.close()
            except Exception:
                pass
        hit = wait_for_pids(BROM_PIDS, wait_brom, "BROM")
        if hit:
            log(f"BROM 検出: {hit[0]} 0e8d:{hit[1]:04x}", "+")
            return True
        # 戻ってきた preloader を探す
        if not wait_for_pids(PRE_PIDS, 3.0, "preloader 復帰"):
            log("preloader も BROM も見えない。挿し直しが必要", "!")
            return False
        log("preloader のまま。次候補へ", ".")
    return False


def strategy_plain_reset(port, pattern, bad_mode, wait_brom):
    """スタブ無し。RTC 不正値 + WDT のみ。"""
    l = Link(port).open()
    try:
        l.handshake(pattern)
        try:
            cur = l.read_u32(RTC_PDN1)
            new = (cur & ~MODE_MASK & 0xFFFFFFFF) | (bad_mode & MODE_MASK)
            l.set32(RTC_BBPU, RTC_KEY, verify=False)
            l.set32(RTC_PDN1, new, verify=False)
            l.set32(RTC_BBPU, 0, verify=False)
            log(f"RTC_PDN1 0x{cur:08X} -> 0x{new:08X}", ".")
        except LinkError as e:
            log(f"RTC 書込 NG: {e}", "!")
            try:
                l.set32(RTC_BBPU, RTC_KEY, verify=False)
                l.set32(RTC_PDN1, bad_mode & MODE_MASK, verify=False)
                l.set32(RTC_BBPU, 0, verify=False)
                log("RTC blind 書込", ".")
            except LinkError as e2:
                log(f"RTC blind も NG: {e2}", "!")
        try:
            l.set32(WDT_MODE, WDT_MODE_KEY | 0x14, verify=False)
            l.set32(WDT_RESTART, WDT_RESTART_KEY, verify=False)
            l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
            log("WDT_SWRST 発行", ".")
        except LinkError as e:
            log(f"WDT NG: {e}", "!")
    finally:
        try:
            l.close()
        except Exception:
            pass
    hit = wait_for_pids(BROM_PIDS, wait_brom, "BROM")
    if hit:
        log(f"BROM 検出: {hit[0]} 0e8d:{hit[1]:04x}", "+")
        return True
    return False


def parse_pattern(s):
    vals = [int(p, 16) for p in s.replace(" ", "").split(",") if p]
    if len(vals) != 4 or any(not (0 <= v <= 0xFF) for v in vals):
        raise ValueError("4 個の 0x00-0xFF が必要")
    return vals


def parse_list(s):
    return [int(x, 0) for x in s.replace(" ", "").split(",") if x]


def main(argv=None):
    ap = argparse.ArgumentParser(description="preloader(META) -> BROM 落とし")
    ap.add_argument("--port", default=None)
    ap.add_argument("--wait", type=float, default=60.0)
    ap.add_argument("--pattern", default=None)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--ports", action="store_true")
    ap.add_argument("--strategy", choices=("stub", "jump", "reset", "all"),
                    default="all")
    ap.add_argument("--bad-mode", type=lambda s: int(s, 0), default=BAD_MODE)
    ap.add_argument("--scrub-words", type=lambda s: int(s, 0),
                    default=SCRUB_WORDS,
                    help=f"スタブが潰すワード数 (既定 0x{SCRUB_WORDS:X} = "
                         f"0x0-0x{SCRUB_WORDS*4:X})")
    ap.add_argument("--scrub-high", type=lambda s: int(s, 0), default=0,
                    help="スタブ前にホストから潰す上位バイト数 (0=off, 例 0x30000)")
    ap.add_argument("--brom-entry", default=None,
                    help="BROM 候補 (カンマ区切り, 例 0x0,0x8,0x100)")
    ap.add_argument("--brom-wait", type=float, default=8.0,
                    help="BROM 列挙の待ち時間 (既定 8s)")
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

    pat = None
    if a.pattern:
        try:
            pat = parse_pattern(a.pattern)
        except Exception as e:
            print(f"--pattern 不正: {e}")
            return 2

    entries = parse_list(a.brom_entry) if a.brom_entry else list(BROM_ENTRIES)

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

    if a.probe:
        try:
            probe(port, pat)
        except LinkError as e:
            log(f"probe 失敗: {e}", "!")
            return 1
        return 0

    if a.dry_run:
        print(f"port={port} strategy={a.strategy} bad_mode=0x{a.bad_mode:02X} "
              f"scrub_words=0x{a.scrub_words:X} scrub_high=0x{a.scrub_high:X} "
              f"entries={['0x%X' % e for e in entries]}")
        print(f"stub bytes={len(build_drop_stub(bad_mode=a.bad_mode, scrub_words=a.scrub_words))}")
        return 0

    ok = False
    if a.strategy in ("stub", "all"):
        log("=== [1] stub-drop ===", "#")
        try:
            ok = strategy_stub_drop(port, pat, a.bad_mode, a.scrub_words,
                                    a.brom_wait, a.scrub_high)
        except LinkError as e:
            log(f"stub-drop 例外: {e}", "!")

    if not ok and a.strategy in ("jump", "all"):
        log("=== [2] brom-jump ===", "#")
        if not wait_for_pids(PRE_PIDS, 10.0, "preloader 復帰"):
            log("preloader 復帰せず。挿し直して再実行", "!")
            return 1
        hit = find_pids(PRE_PIDS)
        if hit:
            try:
                ok = strategy_brom_jump(hit[0][0], pat, entries, a.brom_wait)
            except LinkError as e:
                log(f"brom-jump 例外: {e}", "!")

    if not ok and a.strategy in ("reset", "all"):
        log("=== [3] plain-reset ===", "#")
        hit = find_pids(PRE_PIDS)
        if hit:
            try:
                ok = strategy_plain_reset(hit[0][0], pat, a.bad_mode, a.brom_wait)
            except LinkError as e:
                log(f"plain-reset 例外: {e}", "!")

    if ok:
        log("=== BROM 到達 ===", "#")
        for dev, pid, desc in find_pids(BROM_PIDS):
            log(f"  {dev} 0e8d:{pid:04x} {desc}", "+")
        log("BROM は 0xFE/0xD0.. の独自プロトコル。DA を送る前に"
            "ハンドシェイク (0xA0 0x0A 0x50 0x05) をやり直してください。", ".")
        return 0

    log("全戦略で BROM に落ちず", "!")
    log("対処: --scrub-high 0x30000 で破壊範囲を拡大 / "
        "--brom-entry に BROM 実エントリを指定 / バッテリ抜きで強制 BROM", "!")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中断")
        sys.exit(130)
