#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
mtk_preloader_brom.py  v7   MT8167 preloader(0e8d:2000) -> BROM(0e8d:0003)
================================================================================
【v7 修正】
  検出とハンドシェイクを分離した。検出は ct6 と同じ列挙のみで、
  ポートに一切触らない (開かない/閉じない/DTR を叩かない)。
  ハンドシェイクは採用したポートに対して attempt() 内で 1 回だけ実行。

【確定プロトコル (0x1618-0x1694)】
  pattern[i] と受信値を比較し、
    一致   -> (^0xFF) を返して i++
    不一致 -> (受信値+1) を返して i = 0 にリセット
  タイムアウト (0x164E cmp/bhi 0x1B56) で usbdl ループ自体が終了するので
  失敗したらポートを閉じて開き直す。

【実装済みコマンド】
  0xD0 READ16 0x1508 / 0xD1 READ32 0x197E / 0xD2 WRITE16 0x1584
  0xD4 WRITE32 0x19DA (0x19FC で 4 バイト整列検査)
  0xD5 JUMP 0x18D8 (0x18EE で準備フラグ検査、0x2001 でも飛ぶ)
  0xD7 SEND_DA 0x1750 (成功時 0x18D4 で準備フラグを立てる)
  0xD8 STATUS 0x1944 / 0xFC ENTRY 0x17E2 / 0xFD BASE 0x17F6 / 0xFE PING 0x17CE

【4 経路】
  R1 0xD7 -> 0xD5 / R2 0xD4 -> 0xD7(1w) -> 0xD5
  R3 0xD7 -> RVBAD -> SWRST / R4 0xD4 のみ
================================================================================
"""

import argparse
import datetime
import platform
import struct
import sys
import time
import traceback

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

# ---------------------------------------------------------------- 定数
MTK_VID = 0x0E8D
PRE_PIDS = (0x2000, 0x2001, 0x201C, 0x3000, 0x2003, 0x201D)
BROM_PIDS = (0x0003, 0x0006, 0x0007)
KW = ("mtk", "mediatek", "preloader", "vcom", "cdc", "usb port")

CMD_READ16 = 0xD0
CMD_READ32 = 0xD1
CMD_WRITE16 = 0xD2
CMD_WRITE32 = 0xD4
CMD_JUMP = 0xD5
CMD_SEND_DA = 0xD7
CMD_STATUS = 0xD8
CMD_ENTRY = 0xFC
CMD_BASE = 0xFD
CMD_PING = 0xFE

PATTERN_HINT = [0xA0, 0x0A, 0x50, 0x05]
HSHK_BYTE_TO = 0.35
HSHK_GAP = 0.10
HSHK_MAX = 900

BAUD = 115200
IO_TO = 1.0
WR_TO = 6.0
BROM_WAIT = 20.0
ATTEMPT_GAP = 2.5

SRAMROM_USBDL = 0x10209050
USBDL_MAGIC = 0x444CFFFD
MISC_LOCK = 0x10209070
MISC_LOCK_KEY = 0x0000AD98
RST_CON = 0x10209078
WDT_MODE = 0x10007000
WDT_RESTART = 0x10007008
WDT_SWRST = 0x10007014
RVBAD_CPU0 = 0x10200038
RTC_BBPU = 0x10003008
RTC_PDN1 = 0x1000301C
RTC_KEY = 0x43000000

WDT_MODE_KEY = 0x22000000
WDT_RESTART_KEY = 0x1971
WDT_SWRST_KEY = 0x1209

STUB = 0x40001000
STUB_ALT = 0x40002000
ST_OK = 0
ST_NOT_READY = 0x2001

LOG_PATH = "mtk_preloader_brom.log"
_fh = None


def log(msg, tag="*"):
    line = f"[{tag}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    if _fh:
        try:
            _fh.write(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} {line}\n")
            _fh.flush()
        except Exception:
            pass


# ================================================================
# 検出 — ct6 と同じ。列挙のみ。ポートに触らない
# ================================================================
def find_mtk_ports():
    """VID 0e8d かつ PID 既知のポートを列挙するだけ。"""
    out = []
    if not HAS_SERIAL:
        return out
    try:
        for p in serial.tools.list_ports.comports():
            if p.vid == MTK_VID and p.pid is not None:
                out.append((p.device, p.pid, p.description or ""))
    except Exception:
        pass
    return out


def find_preloader_ports():
    return [x for x in find_mtk_ports() if x[1] in PRE_PIDS]


def fallback_ports():
    """VID/PID が取れない環境向けの保険。説明文字列で拾う。"""
    out = []
    if not HAS_SERIAL:
        return out
    try:
        for p in serial.tools.list_ports.comports():
            d = (p.description or "").lower()
            if p.vid == MTK_VID or any(k in d for k in KW):
                out.append((p.device, p.pid, p.description or ""))
    except Exception:
        pass
    return out


def wait_preloader(timeout):
    """列挙のみで待つ。見つかったら即返す。ポートは開かない。"""
    end = time.monotonic() + timeout if timeout else 0
    tick = 0
    while True:
        hit = find_preloader_ports()
        if hit:
            return hit[0][0], hit[0][1]
        if timeout and time.monotonic() >= end:
            fb = fallback_ports()
            if fb:
                return fb[0][0], fb[0][1]
            return None, None
        tick += 1
        if tick % 30 == 0:
            log(f"preloader 探索中... MTKポート {len(find_mtk_ports())} 件", ".")
        time.sleep(0.1)


def wait_brom(deadline):
    while time.monotonic() < deadline:
        for dev, pid, desc in find_mtk_ports():
            if pid in BROM_PIDS:
                return dev
        time.sleep(0.15)
    return None


def dump_ports():
    log("現在のポート:", ".")
    for dev, pid, desc in find_mtk_ports():
        mark = "PRE" if pid in PRE_PIDS else ("BROM" if pid in BROM_PIDS else "-")
        log(f"  {dev} 0e8d:{pid:04x} [{mark}] {desc}", ".")
    fb = [x for x in fallback_ports() if x not in find_mtk_ports()]
    for dev, pid, desc in fb:
        log(f"  {dev} (pid不明) {desc}", ".")


# ================================================================
# リンク
# ================================================================
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
            self.ser.reset_output_buffer()
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

    # ---- 0x1674 仕様 ----
    def handshake(self):
        prefix = []
        guess = PATTERN_HINT[0]
        steps = 0
        while steps < HSHK_MAX:
            seq = prefix + [guess]
            self.flush_in()
            pos = 0
            done = True
            for b in seq:
                steps += 1
                if steps >= HSHK_MAX:
                    break
                self.tx(bytes([b]))
                r = self.rx(1, HSHK_BYTE_TO)
                if not r:
                    done = False
                    break
                v = r[0]
                if v == (b ^ 0xFF):
                    pos += 1
                    continue
                prefix = seq[:pos]
                guess = v if v == ((b + 1) & 0xFF) else ((guess + 1) & 0xFF)
                done = False
                break
            if done and pos == len(seq):
                if len(seq) == 4:
                    return seq
                prefix = seq
                guess = PATTERN_HINT[len(seq)]
            time.sleep(HSHK_GAP)
        raise LinkError(f"handshake failed (prefix={[hex(x) for x in prefix]})")

    # ---- エコー ----
    def echo(self, data, tag="echo", timeout=None):
        self.tx(data)
        got = self.rx(len(data), timeout)
        if got != data:
            raise LinkError(f"{tag}: {data.hex()} != {got.hex()}")

    def begin(self, op, addr, cnt, tag, timeout=None):
        self.echo(bytes([op]), tag, timeout)
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), tag + ".a", timeout)
        self.echo(struct.pack(">I", cnt & 0xFFFFFFFF), tag + ".n", timeout)
        st = struct.unpack(">H", self.rx(2, timeout or IO_TO))[0]
        if st & 0xFF:
            raise LinkError(f"{tag} status 0x{st:04X}")

    # ---- 0x1508 / 0x197E ----
    def read16(self, addr, cnt):
        self.begin(CMD_READ16, addr, cnt, "read16")
        d = self.rx(cnt * 2, 10.0)
        self.rx(2, 1.0)
        n = len(d) // 2
        return list(struct.unpack(">%dH" % n, d[:n * 2]))

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

    def read_u32(self, addr):
        return self.read32(addr, 1, timeout=4.0)[0]

    # ---- 0x19DA ----
    def write32(self, addr, vals, verify=True, timeout=8.0):
        if addr & 3:
            raise LinkError("write32: 4 バイト整列が必要 (0x19FC)")
        self.begin(CMD_WRITE32, addr, len(vals), "write32")
        for v in vals:
            self.echo(struct.pack(">I", v & 0xFFFFFFFF), "write32.d", timeout)
        self.rx(2, timeout)
        if verify:
            back = self.read32(addr, len(vals), timeout=5.0)
            if back != [v & 0xFFFFFFFF for v in vals]:
                raise LinkError(f"write32 検証不一致 @0x{addr:08X}")

    def set32(self, addr, val, verify=True):
        self.write32(addr, [val], verify=verify)

    # ---- 0x1750 ----
    def send_da(self, data, addr, timeout=8.0):
        self.echo(bytes([CMD_SEND_DA]), "send_da")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "send_da.a")
        self.echo(struct.pack(">I", len(data)), "send_da.n")
        self.echo(struct.pack(">I", 0), "send_da.sig")
        st = struct.unpack(">H", self.rx(2, timeout))[0]
        if st & 0xFF:
            return st
        self.tx(data)
        self.rx(2, timeout)
        tail = self.rx(2, timeout)
        if len(tail) < 2:
            return -1
        return struct.unpack(">H", tail)[0]

    # ---- 0x18D8 ----
    def jump(self, addr, timeout=2.5):
        self.echo(bytes([CMD_JUMP]), "jump")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "jump.a")
        return struct.unpack(">H", self.rx(2, timeout))[0]

    def jump_tolerant(self, addr, timeout=0.5):
        try:
            self.tx(bytes([CMD_JUMP]))
            if not self.rx(1, timeout):
                return "NO_ECHO", -1
            self.tx(struct.pack(">I", addr & 0xFFFFFFFF))
            if len(self.rx(4, timeout)) < 4:
                return "ADDR_SHORT", -1
            s = self.rx(2, timeout)
            if len(s) < 2:
                return "STATUS_LOST", -1
            v = struct.unpack(">H", s)[0]
            return ("OK" if v in (0, ST_NOT_READY) else "NONZERO"), v
        except LinkError:
            return "EXC", -1

    # ---- 0x1944 / 0x17CE / 0x17F6 / 0x17E2 ----
    def status(self):
        self.tx(bytes([CMD_STATUS]))
        r = self.rx(1, 1.0)
        if not r:
            raise LinkError("status 無応答")
        return r[0]

    def ping(self):
        self.tx(bytes([CMD_PING]))
        return self.rx(1, 0.5) == b"\x01"

    def brom_base(self):
        self.tx(bytes([CMD_BASE]))
        r = self.rx(2, 1.0)
        if len(r) < 2:
            raise LinkError("base 無応答")
        return struct.unpack(">H", r)[0]

    def entries(self):
        self.tx(bytes([CMD_ENTRY]))
        r = self.rx(6, 1.0)
        if len(r) < 6:
            raise LinkError("entry 無応答")
        return list(struct.unpack(">HHH", r))


# ================================================================
# ペイロード
# ================================================================
B_SELF = 0xEAFFFFFE


def _movw(r, v):
    v &= 0xFFFF
    return 0xE3000000 | (((v >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (v & 0xFFF)


def _movt(r, v):
    v = (v >> 16) & 0xFFFF
    return 0xE3400000 | (((v >> 12) & 0xF) << 16) | ((r & 0xF) << 12) | (v & 0xFFF)


def _str(rt, rn):
    return 0xE5800000 | ((rn & 0xF) << 16) | ((rt & 0xF) << 12)


def build(pairs, spin=True):
    w = []
    for a, v in pairs:
        w += [_movw(0, a), _movt(0, a), _movw(1, v), _movt(1, v), _str(1, 0)]
    if spin:
        w.append(B_SELF)
    return b"".join(struct.pack("<I", x) for x in w)


def decode(p):
    ws = struct.unpack("<%dI" % (len(p) // 4), p)
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


def words(p):
    pad = (-len(p)) % 4
    return list(struct.unpack("<%dI" % ((len(p) + pad) // 4), p + b"\x00" * pad))


def p_usbdl_wdt():
    return [(SRAMROM_USBDL, USBDL_MAGIC), (WDT_RESTART, WDT_RESTART_KEY),
            (WDT_MODE, WDT_MODE_KEY | 0x14), (WDT_SWRST, WDT_SWRST_KEY)]


def p_usbdl():
    return [(SRAMROM_USBDL, USBDL_MAGIC)]


def p_rvbad():
    return [(RVBAD_CPU0, 0xDEADBEEF), (RVBAD_CPU0 + 8, 0xFFFFFFFF),
            (SRAMROM_USBDL, USBDL_MAGIC), (WDT_RESTART, WDT_RESTART_KEY),
            (WDT_MODE, WDT_MODE_KEY | 0x14), (WDT_SWRST, WDT_SWRST_KEY)]


def p_lock():
    return [(MISC_LOCK, MISC_LOCK_KEY), (RST_CON, 1), (MISC_LOCK, 0),
            (SRAMROM_USBDL, USBDL_MAGIC)]


PAYLOADS = {"P1": p_usbdl_wdt, "P2": p_usbdl, "P3": p_rvbad, "P4": p_lock}


# ================================================================
# 4 経路
# ================================================================
def r1(l, payload, addr):
    st = l.send_da(payload, addr)
    if st & 0xFF:
        return f"SEND_DA=0x{st:04X}", False
    try:
        js = l.jump(addr)
    except LinkError as e:
        return f"JUMP echo loss ({e})", True
    return f"JUMP=0x{js:04X}", js in (ST_OK, ST_NOT_READY)


def r2(l, payload, addr):
    l.write32(addr, words(payload))
    pr = l.send_da(b"\x00\x00\x00\x00", STUB)
    if pr & 0xFF:
        log(f"  prime=0x{pr:04X} (続行)", "!")
    try:
        js = l.jump(addr)
    except LinkError as e:
        return f"JUMP echo loss ({e})", True
    return f"JUMP=0x{js:04X}", js in (ST_OK, ST_NOT_READY)


def r3(l, payload, addr):
    st = l.send_da(payload, addr)
    if st & 0xFF:
        return f"SEND_DA=0x{st:04X}", False
    l.set32(RVBAD_CPU0, addr)
    try:
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
    except LinkError:
        return "SWRST (切断)", True
    return "SWRST 発行", True


def r4(l, payload, addr):
    l.set32(SRAMROM_USBDL, USBDL_MAGIC)
    l.set32(MISC_LOCK, MISC_LOCK_KEY)
    l.set32(RST_CON, 1)
    l.set32(MISC_LOCK, 0)
    l.set32(RTC_BBPU, RTC_KEY)
    cur = l.read_u32(RTC_PDN1)
    l.set32(RTC_PDN1, (cur & 0xFFFFFFC0) | 1)
    l.set32(RTC_BBPU, RTC_KEY)
    l.set32(WDT_MODE, WDT_MODE_KEY | 0x14)
    l.set32(WDT_RESTART, WDT_RESTART_KEY)
    try:
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
    except LinkError:
        return "SWRST (切断)", True
    return "SWRST 発行", True


ROUTES = {
    "R1": ("0xD7 -> 0xD5", r1, "P1"),
    "R2": ("0xD4 -> 0xD7(1w) -> 0xD5", r2, "P1"),
    "R3": ("0xD7 -> RVBAD -> SWRST", r3, "P3"),
    "R4": ("0xD4 のみ", r4, "-"),
}

PLAN = [("P1", "R1"), ("P2", "R1"), ("P1", "R2"), ("P4", "R1"),
        ("P3", "R3"), ("P1", "R3"), ("P4", "R2"), ("P2", "R2"),
        ("-", "R4"), ("P1", "R1")]

LIKELY = ("JUMP=0x0000", "JUMP=0x2001", "JUMP echo loss", "SWRST")


# ================================================================
# 実行
# ================================================================
def attempt(port, pid, rid, addr, brom_timeout):
    desc, fn, defp = ROUTES[rid]
    payload = b""
    if defp != "-":
        if pid == "-":
            pid = defp
        payload = build(PAYLOADS[pid]())
        log(f"  payload {pid}: {len(payload)}B")
        for a, v in decode(payload):
            log(f"    0x{a:08X} <- 0x{v:08X}", ".")

    try:
        link = Link(port).open()
    except Exception as e:
        return "OPEN_FAIL", str(e)

    try:
        pat = link.handshake()
        log(f"  handshake OK {[hex(x) for x in pat]}", "+")
    except Exception as e:
        try:
            link.close()
        except Exception:
            pass
        return "HSHK_FAIL", str(e)

    try:
        detail, ok = fn(link, payload, addr)
    except LinkError as e:
        detail, ok = str(e), False
    finally:
        try:
            link.close()
        except Exception:
            pass

    log(f"  -> {detail}", "*")
    if not ok and not detail.startswith(LIKELY):
        return detail.split("=")[0], detail

    b = wait_brom(time.monotonic() + brom_timeout)
    if b:
        return "SUCCESS", b
    return "NO_BROM", detail


def main(argv=None):
    global _fh
    ap = argparse.ArgumentParser(description="preloader -> BROM 強制移行 v7")
    ap.add_argument("--wait", type=float, default=90.0, help="探索待機秒 (0=無制限)")
    ap.add_argument("--brom-timeout", type=float, default=BROM_WAIT)
    ap.add_argument("--only", default=None, help="R1..R4")
    ap.add_argument("--port", default=None, help="ポートを固定")
    ap.add_argument("--stub", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--ports", action="store_true", help="ポート一覧のみ")
    a = ap.parse_args(argv)

    if not HAS_SERIAL:
        print("pip install pyserial")
        return 2
    try:
        _fh = open(LOG_PATH, "w", encoding="utf-8")
    except Exception:
        _fh = None
    log(f"v7 start {datetime.datetime.now().isoformat()} / {platform.platform()}", "=")

    try:
        if a.ports:
            dump_ports()
            return 0

        if a.port:
            port = a.port
        else:
            log(f"preloader を最大 {a.wait}s 待機 (列挙のみ)", ".")
            port, _pid = wait_preloader(a.wait)
            if not port:
                log("preloader 未検出", "!")
                dump_ports()
                return 2
        log(f"port: {port}", "+")

        if a.probe:
            with Link(port) as l:
                pat = l.handshake()
                log(f"pattern={[hex(x) for x in pat]}", "+")
                for name, fn in (("ping", l.ping), ("status", l.status),
                                 ("base", l.brom_base), ("entries", l.entries)):
                    try:
                        v = fn()
                        log(f"{name} = {hex(v) if isinstance(v, int) else v}")
                    except Exception as e:
                        log(f"{name} = {e}")
            return 0

        plan = PLAN
        if a.only:
            want = {x.strip().upper() for x in a.only.split(",")}
            plan = [(p, r) for (p, r) in plan if r in want]
        if a.max:
            plan = plan[:a.max]

        history = []
        for i, (pid, rid) in enumerate(plan, 1):
            desc = ROUTES[rid][0]
            log("")
            log("=" * 72)
            log(f"{i}/{len(plan)}  {pid}+{rid}  ({desc})")
            log("=" * 72)

            b = wait_brom(time.monotonic() + 0.3)
            if b:
                log(f"既に BROM: {b}", "+")
                history.append((i, pid, rid, "ALREADY_BROM"))
                return done(history, b)

            if not a.port:
                port, _pid = wait_preloader(a.wait)
                if not port:
                    log("preloader 未検出", "!")
                    history.append((i, pid, rid, "NO_PRELOADER"))
                    time.sleep(ATTEMPT_GAP)
                    continue
            log(f"port: {port}", "+")

            addr = a.stub or (STUB_ALT if rid == "R2" and i % 2 == 0 else STUB)
            tag, detail = attempt(port, pid, rid, addr, a.brom_timeout)
            history.append((i, pid, rid, tag))
            if tag == "SUCCESS":
                return done(history, detail)
            time.sleep(ATTEMPT_GAP)

        b = wait_brom(time.monotonic() + 12)
        if b:
            history.append((len(plan) + 1, "-", "-", "SUCCESS"))
            return done(history, b)
        return fail(history)
    finally:
        if _fh:
            try:
                _fh.close()
            finally:
                _fh = None


def done(history, brom):
    log("")
    log("#" * 72)
    log(f"SUCCESS  BROM: {brom}")
    log("#" * 72)
    for h in history:
        log(f"  {h[0]:2d} {h[1]}+{h[2]} {h[3]}")
    log("")
    log("次: 0e8d:0003 へ 0xA0 で接続 -> DA を 0xD7/0xD5 で常駐")
    return 0


def fail(history):
    log("")
    log("#" * 72)
    log("FAILURE")
    log("#" * 72)
    for h in history:
        log(f"  {h[0]:2d} {h[1]}+{h[2]} {h[3]}")
    dump_ports()
    log("推奨: USB 抜いて 30 秒放電 / キー保持接続 / --probe で pattern 確認")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中断")
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
