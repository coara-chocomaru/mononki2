#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
mtk_preloader_forge.py  v5
  MT8167 preloader (0e8d:2000) -> BROM (0e8d:0003/0006) 強制移行
================================================================================
【v5 の変更】
  1. 決して早期終了しない。ポートが無ければ待ち続け、見つからなければ次試行へ。
  2. 検出は VID/PID 依存をやめ、全ポート走査 + ハンドシェイク実測で確定。
  3. ハンドシェイクは 0x1672 の「期待値+1」仕様に合わせて自己修復。
  4. 0xFE は無音 (0x16E2) -> リンク生存確認に使用。
  5. 0xD5 は直前の 0xD7 成功が前提 (0x18E8)。全 JUMP 経路に PRIME を挿入。
  6. 0x2001 は警告 (0x18F6 でジャンプ継続)。成功扱いにする。
  7. 0xFD/0xFC -> 0xD5 の本来経路を実装 (0x17E2 / 0x17F6)。
  8. analyze で BROM 側を実読みしてエントリを検証。

【確定プロトコル (0x1618 ディスパッチャ)】
  handshake : 4 バイトパターン、一致で ^0xFF 応答、不一致で期待値+1
  0xD0/0xA2 : READ16  (addr,len) -> addr echo, len echo, data
  0xD2/0xA1 : WRITE16 (addr,len,data) -> 各エコー
  0xD1      : READ32  (addr,len,4整列必須)
  0xD4      : WRITE32 (addr,len,data,4整列必須)
  0xD5      : JUMP (addr echo -> status)。直前の 0xD7 成功が必須
  0xD7      : SEND_DA (addr,len,siglen,data) -> cksum echo -> status
  0xD8      : STATUS (3 ビット)
  0xFC      : エントリオフセット 3 個
  0xFD      : BROM ベース (0x08000000)
  0xFE      : 無音 PING
================================================================================
"""

import argparse
import datetime
import json
import os
import platform
import struct
import sys
import time
import traceback
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

# ---------------------------------------------------------------- 定数
MTK_VID = 0x0E8D
PRELOADER_PIDS = (0x2000, 0x2001, 0x201C, 0x3000, 0x2003, 0x201D)
BROM_PIDS = (0x0003, 0x0006, 0x0007)
KEYWORDS = ("mtk", "mediatek", "preloader", "vcom", "usb port", "cdc")

CMD_READ16 = 0xD0
CMD_WRITE16 = 0xD2
CMD_READ32 = 0xD1
CMD_WRITE32 = 0xD4
CMD_JUMP = 0xD5
CMD_SEND_DA = 0xD7
CMD_STATUS = 0xD8
CMD_ENTRY = 0xFC
CMD_BASE = 0xFD
CMD_PING = 0xFE

HSHK_PATTERN = [0xA0, 0x0A, 0x50, 0x05]
HSHK_PASSES = 40
HSHK_BYTE_TO = 0.35

BAUD = 115200
IO_TO = 1.0
WR_TO = 5.0
BROM_WAIT = 20.0
ATTEMPT_GAP = 2.5
RESET_SETTLE = 1.2

# レジスタ
SRAMROM_USBDL = 0x10209050
USBDL_VALUE = 0x444CFFFD
MISC_LOCK = 0x10209070
MISC_LOCK_KEY = 0x0000AD98
RST_CON = 0x10209078
WDT_MODE = 0x10007000
WDT_LENGTH = 0x10007004
WDT_RESTART = 0x10007008
WDT_SWRST = 0x10007014
WDT_SWSYSRST = 0x10007018
WDT_NONRST = 0x10007020
WDT_DEBUG = 0x10007040
RVBAD_CPU0 = 0x10200038
RTC_BASE = 0x10003000
RTC_BBPU = RTC_BASE + 0x08
RTC_PDN1 = RTC_BASE + 0x1C
RTC_KEY = 0x43000000

WDT_MODE_KEY = 0x22000000
WDT_MODE_AUTO = 1 << 4
WDT_MODE_EXTEN = 1 << 2
WDT_RESTART_KEY = 0x1971
WDT_SWRST_KEY = 0x1209
WDT_SWSYS_KEY = 0x88000000
WDT_SWSYS_MD = 1 << 7

STUB = 0x40001000
STUB_ALT = 0x40002000
DEF_BROM_BASE = 0x08000000
DEF_ENTRIES = (0x1000, 0x4000, 0x0004)

ERR_NOT_READY = 0x2001
ERR_CHECKSUM = 0x2003
ERR_TOO_LONG = 0x2006
ERR_MALLOC = 0x1000

LOG_PATH = "mtk_preloader_forge.log"
_logfh = None


def log(msg, tag="*"):
    line = f"[{tag}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    if _logfh:
        try:
            _logfh.write(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} {line}\n")
            _logfh.flush()
        except Exception:
            pass


def log_open():
    global _logfh
    try:
        _logfh = open(LOG_PATH, "w", encoding="utf-8")
    except Exception:
        _logfh = None
        return
    log(f"start {datetime.datetime.now().isoformat()} / {platform.platform()}", "=")


def log_close():
    global _logfh
    if _logfh:
        try:
            _logfh.close()
        finally:
            _logfh = None


# ---------------------------------------------------------------- リンク
class LinkError(Exception):
    pass


class Link:
    def __init__(self, port):
        self.port = port
        self.ser = None

    def open(self):
        self.ser = serial.Serial(self.port, BAUD, timeout=IO_TO, write_timeout=WR_TO)
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass
        for a in ("dtr", "rts"):
            try:
                setattr(self.ser, a, True)
            except Exception:
                pass
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
        if self.ser is not None:
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
            except serial.SerialException as e:
                raise LinkError(f"rx: {e}")
            if c:
                buf += c
        return bytes(buf)

    def tx(self, data):
        try:
            self.ser.write(data)
            self.ser.flush()
        except serial.SerialException as e:
            raise LinkError(f"tx: {e}")

    # --- ハンドシェイク (0x1672 の自己修復仕様) ---
    def handshake(self, passes=HSHK_PASSES):
        pat = list(HSHK_PATTERN)
        last = ""
        for _ in range(passes):
            self.flush_in()
            ok = True
            healed = False
            for i, b in enumerate(pat):
                try:
                    self.tx(bytes([b]))
                except LinkError as e:
                    last = str(e)
                    ok = False
                    break
                r = self.rx(1, HSHK_BYTE_TO)
                if r and r[0] == (b ^ 0xFF):
                    continue
                if r and r[0] == ((b + 1) & 0xFF):
                    pat[i] = r[0]           # 0x1674: 期待値+1 を教えてくれる
                    healed = True
                    last = f"healed pos{i} -> 0x{r[0]:02X}"
                    break
                last = f"pos{i} sent=0x{b:02X} got={r.hex() or 'none'}"
                ok = False
                break
            if ok and not healed:
                return pat
            time.sleep(0.12)
        raise LinkError(f"handshake failed: {last}")

    # --- エコー付き ---
    def echo(self, data, tag="echo", timeout=None):
        self.tx(data)
        got = self.rx(len(data), timeout)
        if got != data:
            raise LinkError(f"{tag}: echo {data.hex()} != {got.hex()}")

    def begin(self, op, addr, cnt, tag, timeout=None):
        self.echo(bytes([op]), tag, timeout)
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), tag + ".addr", timeout)
        self.echo(struct.pack(">I", cnt & 0xFFFFFFFF), tag + ".len", timeout)
        st = struct.unpack(">H", self.rx(2, timeout or IO_TO))[0]
        if st & 0xFF:
            raise LinkError(f"{tag} status 0x{st:04X}")

    # --- 実コマンド ---
    def ping(self):
        """0xFE: 無音。0x01 が返れば生存。"""
        self.tx(bytes([CMD_PING]))
        return self.rx(1, 0.5) == b"\x01"

    def status(self):
        self.tx(bytes([CMD_STATUS]))
        r = self.rx(1, 1.0)
        if not r:
            raise LinkError("status 無応答")
        return r[0]

    def brom_base(self):
        self.tx(bytes([CMD_BASE]))
        r = self.rx(2, 1.0)
        if len(r) < 2:
            raise LinkError("base 無応答")
        return struct.unpack(">H", r)[0]

    def entry_table(self):
        self.tx(bytes([CMD_ENTRY]))
        r = self.rx(6, 1.0)
        if len(r) < 6:
            raise LinkError("entry 無応答")
        return list(struct.unpack(">HHH", r))

    def read32(self, addr, cnt, timeout=20.0):
        self.begin(CMD_READ32, addr, cnt, "read32")
        out = []
        while len(out) < cnt:
            want = min(0x400, cnt - len(out))
            d = self.rx(want * 4, timeout)
            n = len(d) // 4
            if n == 0:
                break
            out.extend(struct.unpack(">%dI" % n, d[:n * 4]))
        if len(out) == cnt:
            self.rx(2, 1.0)
        if len(out) != cnt:
            raise LinkError(f"read32 short {len(out)}/{cnt}")
        return out

    def write32(self, addr, vals, verify=True, timeout=8.0):
        self.begin(CMD_WRITE32, addr, len(vals), "write32")
        for v in vals:
            self.echo(struct.pack(">I", v & 0xFFFFFFFF), "write32.data", timeout)
        self.rx(2, timeout)
        if verify:
            back = self.read32(addr, len(vals), timeout=5.0)
            if back != [v & 0xFFFFFFFF for v in vals]:
                raise LinkError(f"write32 verify mismatch @0x{addr:08X}")

    def set32(self, addr, val, verify=True):
        self.write32(addr, [val], verify=verify)

    def read16(self, addr, cnt):
        self.begin(CMD_READ16, addr, cnt, "read16")
        d = self.rx(cnt * 2, 10.0)
        self.rx(2, 1.0)
        return list(struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2]))

    def send_da(self, data, addr, timeout=8.0):
        """0xD7。成功で status 0、かつ usbdl 準備フラグが立つ。"""
        self.echo(bytes([CMD_SEND_DA]), "send_da")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "send_da.addr")
        self.echo(struct.pack(">I", len(data)), "send_da.len")
        self.echo(struct.pack(">I", 0), "send_da.sig")
        st = struct.unpack(">H", self.rx(2, timeout))[0]
        if st & 0xFF:
            return st
        self.tx(data)
        self.rx(2, timeout)              # デバイス側チェックサム
        tail = self.rx(2, timeout)
        if len(tail) < 2:
            return -1
        return struct.unpack(">H", tail)[0]

    def prime(self):
        """JUMP 前提条件 (0x18E8) を満たすための最小 0xD7。"""
        return self.send_da(b"\x00\x00\x00\x00", STUB, timeout=4.0)

    def jump(self, addr, timeout=2.5):
        self.echo(bytes([CMD_JUMP]), "jump")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "jump.addr")
        return struct.unpack(">H", self.rx(2, timeout))[0]

    def jump_tolerant(self, addr, timeout=0.5):
        try:
            self.tx(bytes([CMD_JUMP]))
            if not self.rx(1, timeout):
                return "NO_ECHO", -1
            self.tx(struct.pack(">I", addr & 0xFFFFFFFF))
            if len(self.rx(4, timeout)) < 4:
                return "ADDR_SHORT", -1
            st = self.rx(2, timeout)
            if len(st) < 2:
                return "STATUS_LOST", -1
            v = struct.unpack(">H", st)[0]
            return ("OK", 0) if v == 0 else ("NONZERO", v)
        except LinkError:
            return "EXC", -1


# ---------------------------------------------------------------- 検出
@dataclass
class Cand:
    device: str
    vid: Optional[int]
    pid: Optional[int]
    desc: str
    score: int = 0


def scan_all() -> List[Cand]:
    out = []
    if not HAS_SERIAL:
        return out
    try:
        for p in serial.tools.list_ports.comports():
            d = (p.description or "").lower()
            s = 0
            if p.vid == MTK_VID:
                s += 60
            if p.pid in PRELOADER_PIDS:
                s += 120
            elif p.pid in BROM_PIDS:
                s += 90
            elif p.pid is not None:
                s += 10
            if any(k in d for k in KEYWORDS):
                s += 40
            if p.vid is None and p.pid is None and not any(k in d for k in KEYWORDS):
                s += 5
            out.append(Cand(p.device, p.vid, p.pid, p.description or "", s))
    except Exception:
        pass
    out.sort(key=lambda c: -c.score)
    return out


def probe(port: str) -> bool:
    """ハンドシェイク実測。開けなければ False。"""
    try:
        with Link(port) as l:
            l.handshake(passes=3)
            return True
    except Exception:
        return False


def find_preloader(deadline: float, exclude=()) -> Optional[str]:
    """決して諦めない探索。deadline=0 で無限。"""
    seen = set()
    tick = 0
    while True:
        for c in scan_all():
            if c.device in exclude:
                continue
            if c.score >= 60 and probe(c.device):
                return c.device
            if c.score < 60 and c.device not in seen:
                seen.add(c.device)
                if probe(c.device):
                    return c.device
        if deadline and time.monotonic() > deadline:
            return None
        tick += 1
        if tick % 8 == 0:
            log(f"preloader 探索中... 検出 {len(scan_all())} ポート", ".")
        time.sleep(0.35)


def wait_brom(deadline: float) -> Optional[str]:
    while time.monotonic() < deadline:
        for c in scan_all():
            if c.pid in BROM_PIDS:
                return c.device
        time.sleep(0.15)
    return None


# ---------------------------------------------------------------- ペイロード
_B_SELF = 0xEAFFFFFE


def _movw(r, imm):
    imm &= 0xFFFF
    return 0xE3000000 | (((imm >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (imm & 0xFFF)


def _movt(r, imm):
    imm = (imm >> 16) & 0xFFFF
    return 0xE3400000 | (((imm >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (imm & 0xFFF)


def _str(rt, rn):
    return 0xE5800000 | ((rn & 0xF) << 16) | ((rt & 0xF) << 12)


def build(program, spin=True):
    w = []
    for a, v in program:
        w += [_movw(0, a), _movt(0, a), _movw(1, v), _movt(1, v), _str(1, 0)]
    if spin:
        w.append(_B_SELF)
    return b"".join(struct.pack("<I", x) for x in w)


def decode(payload):
    ws = struct.unpack("<%dI" % (len(payload) // 4), payload)
    out, i = [], 0
    while i + 5 <= len(ws):
        w = ws[i:i + 5]
        if ((w[0] & 0xFFF00000) == 0xE3000000 and (w[1] & 0xFFF00000) == 0xE3400000
                and (w[2] & 0xFFF00000) == 0xE3000000 and (w[3] & 0xFFF00000) == 0xE3400000
                and (w[4] & 0x0FF00000) == 0x05800000):
            a = (((w[0] >> 16) & 0xF) << 12 | (w[0] & 0xFFF)) | \
                ((((w[1] >> 16) & 0xF) << 12 | (w[1] & 0xFFF)) << 16)
            v = (((w[2] >> 16) & 0xF) << 12 | (w[2] & 0xFFF)) | \
                ((((w[3] >> 16) & 0xF) << 12 | (w[3] & 0xFFF)) << 16)
            out.append((a & 0xFFFFFFFF, v & 0xFFFFFFFF))
            i += 5
        else:
            i += 1
    return out


def p_misc():
    return [(MISC_LOCK, MISC_LOCK_KEY), (RST_CON, 1), (MISC_LOCK, 0)]


def p_usbdl():
    return [(SRAMROM_USBDL, USBDL_VALUE)]


def p_wdt():
    return [(WDT_RESTART, WDT_RESTART_KEY),
            (WDT_MODE, WDT_MODE_KEY | WDT_MODE_AUTO | WDT_MODE_EXTEN)]


def p_swrst():
    return [(WDT_SWRST, WDT_SWRST_KEY)]


PAYLOADS = {
    "P1": lambda: build(p_misc() + p_usbdl() + p_wdt() + p_swrst()),
    "P2": lambda: build(p_usbdl() + p_wdt() + p_swrst()),
    "P3": lambda: build([(0x0010303C, 0x504D454D), (0x1021405C, 0x504D454D),
                         (WDT_DEBUG, 0x59000000 | 0x10000 | 0xF1),
                         (WDT_MODE, 0x22000095), (WDT_LENGTH, 0x00008008),
                         (WDT_RESTART, 0x00001971), (WDT_LENGTH, 0x00001008),
                         (WDT_RESTART, 0x00001971)]),
    "P4": lambda: build(p_misc() + p_usbdl() +
                        [(RVBAD_CPU0, 0xDEADBEEF), (RVBAD_CPU0 + 8, 0xFFFFFFFF)] +
                        p_wdt() + p_swrst()),
    "P5": lambda: build(p_misc() + p_usbdl() +
                        [(WDT_SWSYSRST, WDT_SWSYS_KEY | WDT_SWSYS_MD),
                         (WDT_SWSYSRST, WDT_SWSYS_KEY)] + p_wdt() + p_swrst()),
    "P6": lambda: build(p_usbdl()),
    "P7": lambda: build(p_misc() + p_usbdl() +
                        [(WDT_NONRST, 0xFFFFFFFF), (WDT_NONRST + 4, 0xFFFFFFFF)] +
                        p_wdt() + p_swrst()),
    "P8": lambda: build(p_misc() + p_usbdl() +
                        [(RTC_BBPU, RTC_KEY), (RTC_PDN1, 1), (RTC_BBPU, RTC_KEY)] +
                        p_wdt() + p_swrst()),
}


def get_payload(pid):
    return PAYLOADS[pid]()


def to_words(payload):
    pad = (-len(payload)) % 4
    return list(struct.unpack("<%dI" % ((len(payload) + pad) // 4), payload + b"\x00" * pad))


# ---------------------------------------------------------------- モード
@dataclass
class Outcome:
    tag: str
    detail: str = ""
    jumped: bool = False


def m_da_jump(l, payload, addr):
    st = l.send_da(payload, addr)
    if st & 0xFF:
        return Outcome("SEND_DA_FAIL", f"0x{st:04X}")
    try:
        js = l.jump(addr)
    except LinkError as e:
        return Outcome("JUMP_ECHO_LOST", str(e), True)
    return Outcome("JUMP_OK" if js in (0, ERR_NOT_READY) else "JUMP_STATUS", f"0x{js:04X}", True)


def m_da_tolerant(l, payload, addr):
    st = l.send_da(payload, addr)
    if st & 0xFF:
        return Outcome("SEND_DA_FAIL", f"0x{st:04X}")
    v, js = l.jump_tolerant(addr)
    return Outcome(f"JUMP_{v}", f"0x{js:04X}", True)


def m_prime_jump(l, payload, addr):
    """M8: PRIME(0xD7) で 0x18E8 の前提を満たしてから JUMP。"""
    st = l.send_da(payload, addr)
    if st & 0xFF:
        return Outcome("SEND_DA_FAIL", f"0x{st:04X}")
    pr = l.prime()
    if pr & 0xFF:
        log(f"  prime 失敗 0x{pr:04X} (続行)", "!")
    try:
        js = l.jump(addr)
    except LinkError as e:
        return Outcome("JUMP_ECHO_LOST", str(e), True)
    return Outcome("JUMP_OK" if js in (0, ERR_NOT_READY) else "JUMP_STATUS", f"0x{js:04X}", True)


def m_w32_jump(l, payload, addr):
    l.write32(addr, to_words(payload))
    pr = l.prime()
    if pr & 0xFF:
        log(f"  prime 失敗 0x{pr:04X} (続行)", "!")
    try:
        js = l.jump(addr)
    except LinkError as e:
        return Outcome("JUMP_ECHO_LOST", str(e), True)
    return Outcome("JUMP_OK" if js in (0, ERR_NOT_READY) else "JUMP_STATUS", f"0x{js:04X}", True)


def m_w32_rvbad(l, payload, addr):
    l.write32(addr, to_words(payload))
    l.set32(RVBAD_CPU0, addr)
    try:
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
    except LinkError:
        return Outcome("SWRST_ISSUED", "切断", True)
    return Outcome("SWRST_ISSUED", "", True)


def m_regs_only(l, payload, addr):
    """M10: ペイロード無し。USBDL + RTC(RMW) + WDT + SWRST。"""
    l.set32(SRAMROM_USBDL, USBDL_VALUE)
    l.set32(MISC_LOCK, MISC_LOCK_KEY)
    l.set32(RST_CON, 1)
    l.set32(MISC_LOCK, 0)
    l.set32(RTC_BBPU, RTC_KEY)
    cur = l.read32(RTC_PDN1, 1)[0]
    l.set32(RTC_PDN1, (cur & 0xFFFFFFC0) | 1)
    l.set32(RTC_BBPU, RTC_KEY)
    l.set32(WDT_MODE, WDT_MODE_KEY | WDT_MODE_AUTO | WDT_MODE_EXTEN)
    l.set32(WDT_RESTART, WDT_RESTART_KEY)
    try:
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
    except LinkError:
        return Outcome("SWRST_ISSUED", "切断", True)
    return Outcome("SWRST_ISSUED", "", True)


def m_brom_entry(l, payload, addr):
    """M9: 0xFD ベース + 0xFC オフセット -> 0xD5 (本来経路)。"""
    base = l.brom_base()
    ents = l.entry_table()
    log(f"  base=0x{base:08X} entries={[hex(e) for e in ents]}", ".")
    if base != DEF_BROM_BASE:
        log(f"  base が想定外。0x{DEF_BROM_BASE:08X} を使用", "!")
        base = DEF_BROM_BASE
    if not ents:
        ents = list(DEF_ENTRIES)
    l.prime()
    last = ""
    for e in ents:
        tgt = (base + e) & 0xFFFFFFFF
        try:
            js = l.jump(tgt)
        except LinkError as ex:
            return Outcome("JUMP_ECHO_LOST", f"{str(ex)} @0x{tgt:08X}", True)
        last = f"0x{tgt:08X} -> 0x{js:04X}"
        log(f"  JUMP 0x{tgt:08X} status 0x{js:04X}", ".")
        if js in (0, ERR_NOT_READY):
            return Outcome("JUMP_OK", last, True)
    return Outcome("JUMP_STATUS", last, True)


def m_status_only(l, payload, addr):
    st = l.status()
    log(f"  status=0x{st:02X} ping={l.ping()}", ".")
    return Outcome("STATUS", f"0x{st:02X}", False)


def m_usbdl_swrst(l, payload, addr):
    l.set32(SRAMROM_USBDL, USBDL_VALUE)
    try:
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
    except LinkError:
        return Outcome("SWRST_ISSUED", "切断", True)
    return Outcome("SWRST_ISSUED", "", True)


MODES = {
    "M1": ("SEND_DA + JUMP", m_da_jump, True),
    "M2": ("WRITE32 + PRIME + JUMP", m_w32_jump, True),
    "M3": ("WRITE32 + RVBAD + SWRST", m_w32_rvbad, True),
    "M4": ("WRITE32 + RVBAD + SWRST (小chunk)", m_w32_rvbad, True),
    "M5": ("SEND_DA + tolerant JUMP", m_da_tolerant, True),
    "M6": ("SEND_DA(alt) + JUMP", m_da_jump, True),
    "M7": ("SEND_DA + PRIME + JUMP", m_prime_jump, True),
    "M8": ("SEND_DA + PRIME + JUMP (冗長)", m_prime_jump, True),
    "M9": ("0xFD+0xFC -> BROM エントリへ JUMP", m_brom_entry, False),
    "M10": ("レジスタ直叩き (USBDL+RTC+WDT+SWRST)", m_regs_only, False),
    "M11": ("USBDL + SWRST のみ", m_usbdl_swrst, False),
    "M12": ("STATUS/PING のみ", m_status_only, False),
}

PLAN = [
    ("P1", "M1"), ("P1", "M7"), ("P2", "M1"), ("P2", "M7"),
    ("P8", "M1"), ("P4", "M1"), ("P1", "M5"),
    ("P1", "M2"), ("P2", "M2"), ("P4", "M2"), ("P1", "M8"),
    ("P1", "M3"), ("P2", "M3"), ("P4", "M3"), ("P5", "M3"),
    ("P8", "M3"),
    ("-", "M10"), ("-", "M11"), ("-", "M9"),
    ("P3", "M1"), ("P3", "M2"), ("P7", "M1"), ("P7", "M3"),
    ("P6", "M1"), ("P6", "M7"), ("P6", "M2"),
    ("P1", "M6"), ("P2", "M6"), ("P2", "M5"),
]

LIKELY = ("JUMP_OK", "JUMP_ECHO_LOST", "JUMP_NO_ECHO", "JUMP_STATUS_LOST",
          "SWRST_ISSUED", "JUMP_ADDR_SHORT")


# ---------------------------------------------------------------- 実行
def run_session(port, pid, mid, addr):
    desc, fn, needs_pl = MODES[mid]
    payload = b""
    if needs_pl:
        if pid == "-":
            return "NO_PAYLOAD", None
        payload = get_payload(pid)
        log(f"  payload {pid}: {len(payload)}B")
        for a, v in decode(payload):
            log(f"    0x{a:08X} <- 0x{v:08X}", ".")
    try:
        link = Link(port).open()
    except Exception as e:
        return "OPEN_FAIL", str(e)
    try:
        try:
            pat = link.handshake()
            log(f"  handshake OK pattern={[hex(x) for x in pat]}", "+")
        except Exception as e:
            return "HSHK_FAIL", str(e)
        try:
            out = fn(link, payload, addr)
        except LinkError as e:
            return "LINK_ERR", str(e)
        log(f"  -> {out.tag} {out.detail}", "*")
        return out.tag, out.detail
    finally:
        try:
            link.close()
        except Exception:
            pass


def cmd_forge(args):
    plan = PLAN
    if args.only:
        want = {x.strip().upper() for x in args.only.split(",")}
        plan = [(p, m) for (p, m) in plan if p in want or m in want]
    if args.max_attempts:
        plan = plan[:args.max_attempts]

    history = []
    total = len(plan)
    log(f"プラン {total} 件 / 1 試行ごとに preloader を再探索します")

    for i, (pid, mid) in enumerate(plan, 1):
        desc = MODES[mid][0]
        log("")
        log("=" * 74)
        log(f"試行 {i}/{total}: {pid}+{mid}  ({desc})")
        log("=" * 74)

        b = wait_brom(time.monotonic() + 0.4)
        if b:
            log(f"既に BROM: {b}", "+")
            history.append((i, "ALREADY_BROM", "-", "SUCCESS"))
            return report_ok(history, i, "ALREADY_BROM", "-", b)

        deadline = time.monotonic() + args.wait if args.wait else 0
        port = find_preloader(deadline)
        if port is None:
            log("preloader 未検出。次試行へ", "!")
            history.append((i, pid, mid, "NO_PRELOADER"))
            time.sleep(ATTEMPT_GAP)
            continue
        log(f"preloader 検出: {port}", "+")

        addr = STUB_ALT if mid == "M6" else STUB
        tag, detail = run_session(port, pid, mid, addr)
        history.append((i, pid, mid, tag))
        log(f"  セッション結果: {tag} {detail or ''}")

        if tag in LIKELY:
            log(f"BROM 再列挙待機 {args.brom_timeout}s", "*")
            b = wait_brom(time.monotonic() + args.brom_timeout)
            if b:
                log(f"BROM 検出: {b}", "+")
                return report_ok(history, i, pid, mid, b)
            log("BROM 出現せず", "!")
        time.sleep(ATTEMPT_GAP)

    log("最終確認: BROM 待機 15s", "*")
    b = wait_brom(time.monotonic() + 15)
    if b:
        history.append((total + 1, "FINAL", "-", "SUCCESS"))
        return report_ok(history, total + 1, "FINAL", "-", b)
    return report_ng(history)


def report_ok(history, n, pid, mid, brom):
    log("")
    log("#" * 74)
    log(f"SUCCESS  BROM 移行  ({pid}+{mid})  port={brom}")
    log("#" * 74)
    for (i, p, m, r) in history:
        log(f"  {i:2d} {p}+{m} {r}")
    log("")
    log("次: 0e8d:0003 に対し 0xA0 で接続 -> DA を SEND_DA/JUMP で常駐")
    return 0


def report_ng(history):
    log("")
    log("#" * 74)
    log("FAILURE  全経路不成立")
    log("#" * 74)
    for (i, p, m, r) in history:
        log(f"  {i:2d} {p}+{m} {r}")
    log("")
    log("現在のポート:")
    for c in scan_all():
        log(f"  {c.device} vid={c.vid} pid={c.pid} score={c.score} {c.desc}")
    log("推奨: USB 抜いて 30 秒放電 / キー保持接続 / --soc 切替")
    return 1


# ---------------------------------------------------------------- 解析
def cmd_analyze(args):
    deadline = time.monotonic() + args.wait
    port = find_preloader(deadline)
    if not port:
        print("preloader 未検出")
        return 2
    log(f"対象: {port}", "+")
    with Link(port) as l:
        pat = l.handshake()
        log(f"handshake パターン確定: {[hex(x) for x in pat]}", "+")
        log(f"ping(0xFE) = {l.ping()}")
        st = l.status()
        log(f"status(0xD8) = 0x{st:02X}  bit0={st & 1} bit1={bool(st & 2)} bit2={bool(st & 4)}")
        base = l.brom_base()
        log(f"BROM base(0xFD) = 0x{base:08X}")
        ents = l.entry_table()
        log(f"entry(0xFC) = {[hex(e) for e in ents]}")
        print()
        print("BROM エントリ候補の実体確認:")
        for e in ents:
            tgt = base + e
            try:
                ws = l.read32(tgt & ~3, 4)
            except LinkError as ex:
                print(f"  0x{tgt:08X}: {ex}")
                continue
            raw = b"".join(struct.pack(">I", w) for w in ws)
            print(f"  0x{tgt:08X}: {raw.hex()}")
            if args.out:
                with open(f"{args.out}.{e:08x}.bin", "wb") as f:
                    f.write(raw)
        print()
        print("SRAMROM_USBDL 現在値:", end=" ")
        try:
            print(f"0x{l.read32(SRAMROM_USBDL, 1)[0]:08X}")
        except LinkError as ex:
            print(ex)
        try:
            print(f"RTC_PDN1: 0x{l.read32(RTC_PDN1, 1)[0]:08X}")
        except LinkError as ex:
            print(f"RTC_PDN1: {ex}")
    return 0


def cmd_ping(args):
    port = find_preloader(time.monotonic() + args.wait)
    if not port:
        print("未検出")
        return 2
    with Link(port) as l:
        l.handshake()
        print(f"{port}: ping={l.ping()} status=0x{l.status():02X}")
    return 0


def cmd_plan(args):
    for i, (p, m) in enumerate(PLAN, 1):
        print(f"{i:2d} {p}+{m}  {MODES[m][0]}")
    return 0


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description="MTK preloader -> BROM 強制移行 v5")
    ap.add_argument("--wait", type=float, default=60.0,
                    help="preloader 探索の総待機秒。0 で無制限 (既定 60)")
    ap.add_argument("--brom-timeout", type=float, default=BROM_WAIT)
    ap.add_argument("--only", default=None)
    ap.add_argument("--max-attempts", type=int, default=0)
    ap.add_argument("--out", default=None)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("forge")
    sub.add_parser("plan")
    sub.add_parser("ping")
    sub.add_parser("analyze")
    a = ap.parse_args(argv)

    if not HAS_SERIAL:
        print("pip install pyserial")
        return 2
    log_open()
    try:
        cmd = a.cmd or "forge"
        if cmd == "plan":
            return cmd_plan(a)
        if cmd == "ping":
            return cmd_ping(a)
        if cmd == "analyze":
            return cmd_analyze(a)
        return cmd_forge(a)
    except KeyboardInterrupt:
        print("\n中断")
        return 130
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        log_close()


if __name__ == "__main__":
    sys.exit(main())
