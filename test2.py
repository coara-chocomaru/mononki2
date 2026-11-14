#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preloader_a04br3 (MT8167) -> BROM (0E8D:0003) 決定的エスケープ

設計根拠（preloader_a04br3 のアセンブリ）
  * 0xD7 (0x1748)  : A=転送先 / B=長さ / C=署名長。
                    0x182A の bl 0x1A8EC（コピー）が
                    0x1844 の bl 0x17458（ヘッダ検証）と
                    0x1884 の bl 0x17448（署名検証）より前に走る
                    → 検証に落ちてもペイロードは既に RAM 上にある
                    → status 0x2001 は「書けたが検証で落ちた」= 許容
  * 0x18CC         : フラグ byte を 1 にする（0xD5 の前提条件）
  * 0xD5 (0x18D8)  : 0x18F0 でフラグを検査し未設定なら 0x2001。
                    0x1920 で受信アドレスを定数で上書きするため、
                    引数が使われるかは実機で判定する必要がある
  * 0x17448/0x17458: 検証関数。00 20 70 47 (movs r0,#0; bx lr) で無力化
  * 0xD1 (0x197E)  : read32。書き込みの読み戻し検証に使う
  * 0xC7 (0x1B18)  : write16 系（引数幅が不明なので 2 通り試す）
  * 0xD3           : この preloader では未実装（0x16CC へ落ちる）

プロトコル: [cmd][echo cmd][u16 status][params...]  LE / 生バイト
            status 0x0000=OK 0x2001=未ロード/検証NG 0x2003=ヘッダ不正 0x2006=サイズ超過
BROM 側のみ BE。0xD4=WRITE32 0xD1=READ32 0xD8=GET_TARGET_CONFIG
"""
from __future__ import annotations

import argparse
import glob
import os
import struct
import sys
import time

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    sys.exit("pip install pyserial")

# ---------------------------------------------------------------- 定数
VID_MTK = 0x0E8D
PID_PRELOADER = 0x2000
PID_BROM = 0x0003

SYNC_TOKEN = b"PRELOADER"

CMD_ECHO_A = 0xC4
CMD_ECHO_B = 0xC5
CMD_WR16 = 0xC7
CMD_RD16 = 0xA1
CMD_RD16_E = 0xA2
CMD_RD32 = 0xD1
CMD_RD32_CHK = 0xD4          # preloader では READ32
CMD_JUMP = 0xD5
CMD_SEND_DA = 0xD7
CMD_CONN = 0xD8
CMD_NOOP = 0xDB
CMD_INFO1 = 0xFC
CMD_INFO2 = 0xFD

ST_OK = 0x0000
ST_NOLOAD = 0x2001
ST_VERIFY = 0x2003
ST_SIZE = 0x2006
ST_TOLERATED = (ST_OK, ST_NOLOAD)     # コピー済みなので 0x2001 は成功扱い

# BROM 側コマンド
B_READ32 = 0xD1
B_WRITE32 = 0xD4
B_SEND_DA = 0xD7
B_JUMP = 0xD5
B_TARGET_CONFIG = 0xD8

WDT_MODE = 0x10007000
WDT_LENGTH = 0x10007004
WDT_RESTART = 0x10007008
WDT_SWRST = 0x1000700C
WDT_ENABLE = 0x22000021
WDT_DISABLE = 0x22000000
WDT_KEY = 0x1971
BROM_WRITE_WINDOW = (0x10007000, 0x10008000)

DEFAULT_BASE = 0x00200000
BASE_CANDIDATES = (0x00200000, 0x00200D00, 0x00100000)
# 0x08C0 の mrc p15,0,r0,c1,c0,0 (0xEE110F10) — 基底同定用シグネチャ
BASE_SIGNATURE = 0xEE110F10
BASE_SIG_OFF = 0x08C0

VERIFY_FN_SIG = 0x00217448        # 基底 0x200000 前提
VERIFY_FN_HDR = 0x00217458
PATCH_RET0 = b"\x00\x20\x70\x47"  # movs r0,#0 ; bx lr

SCRATCH = 0x00230000              # イメージ終端 0x00227A64 より上
SCRATCH_MARK = SCRATCH
SCRATCH_PROBE = SCRATCH + 0x10
SCRATCH_STUB = SCRATCH + 0x40
MARKER = b"\xde\xad\xbe\xef"

BROM_API_MAGIC = b"BRLYT"
SRAM_SCAN_LO = 0x00100000
SRAM_SCAN_HI = 0x00180000
BROM_LO = 0x00000000
BROM_HI = 0x00020000

KICK_INTERVAL = 0.1


# ---------------------------------------------------------------- ログ
class Log:
    def __init__(self, path=None, quiet=False):
        self.fh = open(path, "w", encoding="utf-8") if path else None
        self.quiet = quiet

    def __call__(self, level, msg):
        line = "%s [%s] %s" % (time.strftime("%H:%M:%S"), level.upper(), msg)
        if not self.quiet:
            print(line, flush=True)
        if self.fh:
            self.fh.write(line + "\n")
            self.fh.flush()

    def close(self):
        if self.fh:
            self.fh.close()


LOG = Log()


def info(msg):
    LOG("info", msg)


def ok(msg):
    LOG("ok", msg)


def warn(msg):
    LOG("warn", msg)


def err(msg):
    LOG("error", msg)


# ---------------------------------------------------------------- USB 探索
def list_ports_for(vid, pid):
    out = []
    if os.name == "nt":
        try:
            import winreg
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Enum\USB")
            for i in range(winreg.QueryInfoKey(root)[0]):
                name = winreg.EnumKey(root, i)
                if ("VID_%04X&PID_%04X" % (vid, pid)) not in name.upper():
                    continue
                sub = winreg.OpenKey(root, name)
                for j in range(winreg.QueryInfoKey(sub)[0]):
                    inst = winreg.EnumKey(sub, j)
                    node = winreg.OpenKey(sub, inst)
                    try:
                        port = winreg.QueryValueEx(node, "PortName")[0]
                        out.append("\\\\.\\" + port)
                    except OSError:
                        pass
        except Exception:
            pass
        return out

    for p in list_ports.comports():
        if p.vid == vid and p.pid == pid and p.device:
            out.append(p.device)

    sysfs = "/sys/bus/usb/devices"
    if os.path.isdir(sysfs):
        for d in glob.glob(sysfs + "/*"):
            try:
                v = int(open(d + "/idVendor").read().strip(), 16)
                p_ = int(open(d + "/idProduct").read().strip(), 16)
            except (OSError, ValueError):
                continue
            if v != vid or p_ != pid:
                continue
            for t in glob.glob(d + "/*/tty*") + glob.glob(d + "/tty*"):
                dev = "/dev/" + os.path.basename(t)
                if os.path.exists(dev) and dev not in out:
                    out.append(dev)
    return out


def wait_port(vid, pid, timeout, prefer=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        found = list_ports_for(vid, pid)
        if prefer and prefer in found:
            return prefer
        if found:
            return found[0]
        time.sleep(0.2)
    return None


def wait_enum_change(timeout, prefer=None):
    """preloader が消えて BROM が現れるのを待つ（両方監視）"""
    end = time.monotonic() + timeout
    saw_brom = False
    while time.monotonic() < end:
        brom = list_ports_for(VID_MTK, PID_BROM)
        if brom:
            saw_brom = True
            if prefer and prefer in brom:
                return prefer
            return brom[0]
        time.sleep(0.15)
    return None


# ---------------------------------------------------------------- スタブ
def _literal_tail(literals):
    return b"".join(struct.pack("<I", v) for v in literals)


def build_probe():
    """WDT をアーム → SWRST → スピン。MMU は触らない。"""
    code = bytearray()
    code += b"\x10\x48"        # ldr r0,[pc,#16]   -> 0x10007000
    code += b"\x14\x49"        # ldr r1,[pc,#20]   -> 0x22000021
    code += b"\x01\x60"        # str r1,[r0]
    code += b"\x14\x49"        # ldr r1,[pc,#20]   -> 0x1000
    code += b"\x41\x60"        # str r1,[r0,#4]
    code += b"\x14\x49"        # ldr r1,[pc,#20]   -> 0x1971
    code += b"\x81\x60"        # str r1,[r0,#8]
    code += b"\xc1\x60"        # str r1,[r0,#12]   -> SWRST
    code += b"\xfe\xe7"        # b .
    code += b"\x00\xbf"        # nop (整列)
    assert len(code) == 20
    code += _literal_tail((WDT_MODE, WDT_ENABLE, 0x1000, WDT_KEY))
    return bytes(code)


def build_brom_stub(target):
    """MMU/D-cache を落として target へ分岐する位置独立スタブ。"""
    code = bytearray()
    code += b"\x10\x0f\x11\xee"   # mrc p15,0,r0,c1,c0,0
    code += b"\x20\xf0\x05\x00"   # bic.w r0,r0,#5
    code += b"\x10\x0f\x01\xee"   # mcr p15,0,r0,c1,c0,0
    code += b"\x00\x20"           # movs r0,#0
    code += b"\x17\x0f\x08\xee"   # mcr p15,0,r0,c8,c7,0
    code += b"\x95\x0f\x07\xee"   # mcr p15,0,r0,c7,c5,0
    code += b"\x4f\x8f\xbf\xf3"   # dsb
    code += b"\x6f\x8f\xbf\xf3"   # isb
    code += b"\x00\xbf"           # nop (整列)
    assert len(code) == 32
    code += b"\x00\x48"           # ldr r0,[pc,#0]
    code += b"\x00\x47"           # bx r0
    code += struct.pack("<I", target)
    return bytes(code)


# ---------------------------------------------------------------- preloader
class Preloader:
    def __init__(self, port, baud=115200, verbose=True):
        self.port = port
        self.baud = baud
        self.verbose = verbose
        self.s = None

    # -- 基本 ---------------------------------------------------------
    def open(self, tries=6):
        last = None
        for _ in range(tries):
            try:
                self.s = serial.Serial(self.port, self.baud, timeout=0.6,
                                       write_timeout=8, exclusive=True)
                try:
                    self.s.dtr = True
                    self.s.rts = True
                except Exception:
                    pass
                self.s.reset_input_buffer()
                return
            except Exception as exc:
                last = exc
                time.sleep(0.3)
        raise IOError("open %s failed: %s" % (self.port, last))

    def close(self):
        if self.s and self.s.is_open:
            try:
                self.s.close()
            except Exception:
                pass
        self.s = None

    def put(self, data):
        self.s.write(data)
        self.s.flush()

    def get(self, n, timeout=2.0):
        self.s.timeout = timeout
        buf = b""
        while len(buf) < n:
            chunk = self.s.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def drain(self, t=0.05):
        self.s.timeout = t
        try:
            while self.s.read(4096):
                pass
        finally:
            self.s.timeout = 0.6

    # -- 同期 ---------------------------------------------------------
    def sync(self, rounds=8):
        for _ in range(rounds):
            self.put(SYNC_TOKEN + bytes([CMD_ECHO_A, CMD_NOOP, CMD_ECHO_B]))
            time.sleep(0.03)
            self.drain(0.04)
        self.drain(0.1)
        # 0xC4 がエコーされるかで成立判定
        for _ in range(4):
            self.put(bytes([CMD_ECHO_A]))
            got = self.get(1, 0.8)
            if got == bytes([CMD_ECHO_A]):
                self.get(2, 0.8)   # 付随する status 0
                self.drain(0.05)
                return True
            time.sleep(0.1)
        return False

    # -- トランザクション ---------------------------------------------
    def xact(self, cmd, payload=b"", expect_status=True, timeout=2.0):
        self.put(bytes([cmd]))
        echo = self.get(1, timeout)
        if echo != bytes([cmd]):
            raise IOError("cmd 0x%02X echo %r" % (cmd, echo))
        if payload:
            self.put(payload)
        if not expect_status:
            return None
        st = self.get(2, timeout)
        if len(st) < 2:
            raise IOError("cmd 0x%02X status timeout" % cmd)
        return struct.unpack("<H", st)[0]

    # -- 読み ---------------------------------------------------------
    def read32(self, addr, count=1, checked=True):
        cmd = CMD_RD32_CHK if checked else CMD_RD32
        st = self.xact(cmd, struct.pack("<II", addr, count))
        if st != ST_OK:
            raise IOError("read32 0x%08X status 0x%04X" % (addr, st))
        out = []
        for _ in range(count):
            d = self.get(4, 3.0)
            if len(d) < 4:
                raise IOError("read32 data short")
            out.append(struct.unpack("<I", d)[0])
        tail = self.get(2, 2.0)
        if len(tail) == 2 and struct.unpack("<H", tail)[0] not in ST_TOLERATED:
            raise IOError("read32 tail 0x%04X" % struct.unpack("<H", tail)[0])
        return out

    def read32_one(self, addr):
        return self.read32(addr, 1, checked=True)[0]

    # -- 書き (0xC7 / 幅 2 通り) --------------------------------------
    def wr16(self, addr, value, wide=False):
        if wide:
            payload = struct.pack("<II", addr & 0xFFFFFFFF, value & 0xFFFF)
            echo_n = 4
        else:
            payload = struct.pack("<HH", addr & 0xFFFF, value & 0xFFFF)
            echo_n = 2
        self.put(bytes([CMD_WR16]))
        if self.get(1, 1.5) != bytes([CMD_WR16]):
            raise IOError("wr16 echo")
        self.put(payload[:echo_n])
        e1 = self.get(echo_n, 1.5)
        self.put(payload[echo_n:])
        e2 = self.get(echo_n, 1.5)
        st = self.get(2, 1.5)
        if len(st) < 2:
            raise IOError("wr16 status timeout")
        return struct.unpack("<H", st)[0], e1 + e2

    # -- 0xD7 ---------------------------------------------------------
    def send_da(self, addr, blob, chunk=0x4000):
        if len(blob) > 0x40000:
            raise ValueError("payload > 0x40000")
        st = self.xact(CMD_SEND_DA, struct.pack("<III", addr, len(blob), 0))
        if st != ST_OK:
            raise IOError("send_da header 0x%04X" % st)
        for off in range(0, len(blob), chunk):
            self.put(blob[off:off + chunk])
        cs = 0
        for i in range(0, len(blob) - 1, 2):
            cs ^= struct.unpack("<H", blob[i:i + 2])[0]
        if len(blob) & 1:
            cs ^= blob[-1]
        dev = self.get(2, 10.0)
        if len(dev) < 2:
            raise IOError("send_da checksum timeout")
        dev = struct.unpack("<H", dev)[0]
        if dev != cs:
            raise IOError("send_da checksum dev=0x%04X local=0x%04X"
                          % (dev, cs))
        st = self.get(2, 12.0)
        if len(st) < 2:
            raise IOError("send_da status timeout")
        return struct.unpack("<H", st)[0]

    # -- 0xD5 ---------------------------------------------------------
    def jump(self, addr=0):
        return self.xact(CMD_JUMP, struct.pack("<I", addr))

    def conn_state(self):
        st = self.xact(CMD_CONN)
        d = self.get(4, 2.0)
        return st, (struct.unpack("<I", d)[0] if len(d) == 4 else None)


# ---------------------------------------------------------------- BROM
class Brom:
    def __init__(self, port, baud=115200):
        self.port = port
        self.baud = baud
        self.s = None
        self.buf = b""

    def open(self, tries=20):
        last = None
        for _ in range(tries):
            try:
                self.s = serial.Serial(self.port, self.baud, timeout=0.4,
                                       write_timeout=8, exclusive=True)
                try:
                    self.s.dtr = True
                    self.s.rts = True
                except Exception:
                    pass
                self.s.reset_input_buffer()
                return
            except Exception as exc:
                last = exc
                time.sleep(0.25)
        raise IOError("open BROM %s failed: %s" % (self.port, last))

    def close(self):
        if self.s and self.s.is_open:
            try:
                self.s.close()
            except Exception:
                pass
        self.s = None

    def _put(self, data):
        self.s.write(data)
        self.s.flush()

    def _read(self, n, timeout=2.0):
        if self.buf:
            take, self.buf = self.buf[:n], self.buf[n:]
            if len(take) == n:
                return take
        self.s.timeout = timeout
        buf = take
        while len(buf) < n:
            chunk = self.s.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _cmd(self, code, expect_echo=True, timeout=2.0):
        self._put(bytes([0xFE, code]))
        if not expect_echo:
            return True
        got = self._read(1, timeout)
        return got == bytes([code])

    def handshake(self, tries=1, byte_timeout=1.2):
        """バイト単位エコー確認 (A0->5F, 0A->F5, 50->AF, 05->FA)"""
        pattern = ((0xA0, 0x5F), (0x0A, 0xF5), (0x50, 0xAF), (0x05, 0xFA))
        for _ in range(tries):
            good = True
            for tx, rx in pattern:
                self._put(bytes([tx]))
                if self._read(1, byte_timeout) != bytes([rx]):
                    good = False
                    break
            if good:
                return True
            time.sleep(0.3)
        return False

    def write32(self, addr, value):
        if not (BROM_WRITE_WINDOW[0] <= addr < BROM_WRITE_WINDOW[1]):
            raise ValueError("addr 0x%08X outside BROM write window" % addr)
        if not self._cmd(B_WRITE32):
            raise IOError("write32 echo")
        self._put(struct.pack(">I", addr))
        if self._read(1, 1.5) != bytes([B_WRITE32]):
            raise IOError("write32 addr echo")
        self._put(struct.pack(">I", value))
        if self._read(1, 1.5) != bytes([B_WRITE32]):
            raise IOError("write32 value echo")
        tail = self._read(4, 1.5)
        if len(tail) < 4:
            raise IOError("write32 status timeout")
        cs, st = struct.unpack(">HH", tail)
        want = ((addr >> 16) ^ (addr & 0xFFFF)
                ^ (value >> 16) ^ (value & 0xFFFF))
        if cs != want:
            raise IOError("write32 checksum 0x%04X != 0x%04X" % (cs, want))
        return st

    def read32(self, addr, count=1):
        if not self._cmd(B_READ32):
            raise IOError("read32 echo")
        self._put(struct.pack(">II", addr, count))
        if self._read(1, 1.5) != bytes([B_READ32]):
            raise IOError("read32 addr echo")
        if self._read(1, 1.5) != bytes([B_READ32]):
            raise IOError("read32 count echo")
        st = struct.unpack(">H", self._read(2, 1.5))[0]
        if st != 0:
            raise IOError("read32 status 0x%04X" % st)
        out = []
        for _ in range(count):
            d = self._read(4, 3.0)
            if len(d) < 4:
                raise IOError("read32 data short")
            out.append(struct.unpack(">I", d)[0])
        tail = self._read(4, 2.0)
        if len(tail) >= 4:
            _cs, st2 = struct.unpack(">HH", tail)
            if st2 != 0:
                raise IOError("read32 tail 0x%04X" % st2)
        return out

    def target_config(self):
        if not self._cmd(B_TARGET_CONFIG):
            return None
        self._put(b"\xFE")
        d = self._read(8, 3.0)
        if len(d) < 8:
            return None
        return struct.unpack(">HHHH", d)

    def kick(self):
        try:
            self.write32(WDT_RESTART, WDT_KEY)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------- 手順
def detect_base(pr, override):
    if override:
        return override, "override"
    for base in BASE_CANDIDATES:
        try:
            word = pr.read32_one(base + BASE_SIG_OFF)
        except Exception:
            continue
        if word == BASE_SIGNATURE:
            return base, "signature@%#x" % (base + BASE_SIG_OFF)
    return DEFAULT_BASE, "fallback"


def probe_write(pr, addr, blob):
    """0xD7 で書き、0xD1 で読み戻す。True = 書き込みプリミティブ成立。"""
    st = pr.send_da(addr, blob)
    if st not in ST_TOLERATED:
        warn("0xD7 status 0x%04X (期待 0x0000/0x2001)" % st)
    time.sleep(0.03)
    words = (len(blob) + 3) // 4
    got = pr.read32(addr, words, checked=True)
    raw = b"".join(struct.pack("<I", w) for w in got)[:len(blob)]
    return raw == blob, st, raw


def patch_verify(pr, base):
    targets = ((VERIFY_FN_SIG - DEFAULT_BASE) + base, "署名検証 0x17448"),
    targets += ((VERIFY_FN_HDR - DEFAULT_BASE) + base, "ヘッダ検証 0x17458"),
    done = 0
    for addr, name in targets:
        try:
            before = pr.read32(addr, 1, checked=False)[0]
            st = pr.send_da(addr, PATCH_RET0)
            after = pr.read32(addr, 1, checked=False)[0]
            good = (after & 0xFFFF) == 0x2000 and (after >> 16) == 0x4770
            if good:
                ok("%s @ %#010x 無力化 (旧 %#010x, status 0x%04X)"
                   % (name, addr, before, st))
                done += 1
            else:
                warn("%s @ %#010x 読み戻し不一致 %#010x" % (name, addr, after))
        except Exception as exc:
            warn("%s @ %#010x 失敗: %s" % (name, addr, exc))
    return done


def scan_brom_api(pr):
    hits = []
    addr = SRAM_SCAN_LO
    while addr < SRAM_SCAN_HI:
        try:
            v = pr.read32(addr, 2, checked=False)
        except Exception:
            addr += 0x200
            continue
        if struct.pack("<I", v[0]) == BROM_API_MAGIC:
            hits.append(addr)
            info("brom_api 候補 %#010x" % addr)
        addr += 0x200
    return hits


def brom_entries(pr, api):
    try:
        vals = pr.read32(api, 12, checked=False)
    except Exception:
        return []
    info("brom_api[0:12] = %s" % [hex(v) for v in vals])
    return [v for v in vals if BROM_LO <= v < BROM_HI]


def hold_brom(brom, seconds):
    if seconds <= 0:
        return
    info("BROM 保持: %d 秒間 0xD4 キック" % seconds)
    end = time.monotonic() + seconds
    misses = 0
    while time.monotonic() < end:
        if brom.kick():
            misses = 0
        else:
            misses += 1
            if misses >= 12:
                warn("キック連続失敗 - 保持を終了")
                return
        time.sleep(KICK_INTERVAL)


# ---------------------------------------------------------------- 本体
def main():
    global LOG
    ap = argparse.ArgumentParser(
        description="MT8167 preloader -> BROM (0E8D:0003) 決定的エスケープ")
    ap.add_argument("-p", "--port")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--route", default="auto",
                    choices=["auto", "jump", "stub", "patch", "wdt"])
    ap.add_argument("--base", type=lambda x: int(x, 0))
    ap.add_argument("--flag-addr", type=lambda x: int(x, 0))
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("--keep", type=float, default=0.0)
    ap.add_argument("--wait-brom", type=float, default=25.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-sync", action="store_true")
    ap.add_argument("--log", default=None)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    LOG = Log(args.log, args.quiet)

    info("=== MT8167 preloader -> BROM escape ===")
    info("route=%s base=%s keep=%.1fs"
         % (args.route, args.base or "auto", args.keep))

    port = args.port or wait_port(VID_MTK, PID_PRELOADER, args.timeout)
    if not port:
        brom = list_ports_for(VID_MTK, PID_BROM)
        if brom:
            info("preloader 不在 / BROM は既に存在: %s" % brom[0])
            port = brom[0]
        else:
            err("0E8D:2000 も 0E8D:0003 も見つからない")
            return 1

    already_brom = port in list_ports_for(VID_MTK, PID_BROM)

    pr = None
    brom_port = None

    if not already_brom:
        pr = Preloader(port, args.baud)
        try:
            pr.open()
        except Exception as exc:
            err("preloader を開けない: %s" % exc)
            return 1
        info("preloader ポート %s" % port)

        if not args.no_sync:
            if not pr.sync():
                err("同期失敗（トークン不一致 or preloader 停止）")
                pr.close()
                return 1
            ok("同期確立")
        try:
            st, bits = pr.conn_state()
            info("0xD8 status=0x%04X bits=%#010x" % (st, bits or 0))
        except Exception as exc:
            warn("0xD8 失敗: %s" % exc)

        base, how = detect_base(pr, args.base)
        info("基底 = %#010x (%s)" % (base, how))
        if how == "fallback":
            warn("シグネチャ不一致。基底は推定値")

        if args.dry_run:
            for label, addr in (("sig", base + BASE_SIG_OFF),
                                ("probe", SCRATCH_PROBE)):
                try:
                    info("%s %#010x = %#010x" % (label, addr, pr.read32_one(addr)))
                except Exception as exc:
                    warn("%s 読み出し失敗: %s" % (label, exc))
            pr.close()
            return 0

        # ---- 書き込みプリミティブ検証 ------------------------------
        write_ok = False
        try:
            good, st, raw = probe_write(pr, SCRATCH_MARK, MARKER)
            if good:
                ok("書き込みプリミティブ成立 (0xD7 status 0x%04X)" % st)
                write_ok = True
            else:
                warn("読み戻し不一致: 期待 %s / 実測 %s"
                     % (MARKER.hex(), raw.hex()))
        except Exception as exc:
            warn("書き込み検証失敗: %s" % exc)

        # ---- 検証関数パッチ ----------------------------------------
        if write_ok and args.route in ("auto", "patch", "stub"):
            n = patch_verify(pr, base)
            if n == 2:
                ok("検証関数 2 本を無力化 - 以降の 0xD7 は必ず通る")
            elif n == 0:
                warn("パッチ 0 本。0x2001 許容のまま続行")

        # ---- フラグ手動設定（任意） --------------------------------
        if args.flag_addr:
            for wide in (True, False):
                try:
                    st, _ = pr.wr16(args.flag_addr, 1, wide=wide)
                    ok("フラグ %#010x <- 1 (wide=%s, status 0x%04X)"
                       % (args.flag_addr, wide, st))
                    break
                except Exception as exc:
                    warn("フラグ設定 wide=%s 失敗: %s" % (wide, exc))

        # ---- 経路 1: 0xD5 単独（引数無視型の判定を兼ねる） --------
        def try_jump(addr, label):
            try:
                st = pr.jump(addr)
                info("%s: 0xD5(%#010x) status 0x%04X" % (label, addr, st))
                return st
            except Exception as exc:
                info("%s: 0xD5(%#010x) 応答なし (%s) - 再列挙の可能性"
                     % (label, addr, exc))
                return None

        def await_brom(t):
            p = wait_enum_change(t, port)
            if p:
                ok("BROM 再列挙 %s" % p)
            return p

        # 0xD7 を 1 回打っておけばフラグ（0x18CC）は開く
        if write_ok:
            try:
                pr.send_da(SCRATCH_MARK, MARKER)
            except Exception:
                pass

        if args.route in ("auto", "jump", "patch", "stub"):
            try_jump(0, "経路1 引数0")
            brom_port = await_brom(3.0)

        if not brom_port and args.route in ("auto", "jump"):
            for api in scan_brom_api(pr):
                for ent in brom_entries(pr, api):
                    try_jump(ent, "経路2 brom_api")
                    brom_port = await_brom(2.5)
                    if brom_port:
                        break
                if brom_port:
                    break

        # ---- 経路 3: スタブ実行 ------------------------------------
        if not brom_port and write_ok and args.route in ("auto", "stub"):
            target = 0
            apis = scan_brom_api(pr)
            for api in apis:
                ents = brom_entries(pr, api)
                if ents:
                    target = ents[0]
                    break
            if target:
                info("BROM スタブ: MMU off -> %#010x" % target)
                stub = build_brom_stub(target)
                try:
                    st = pr.send_da(SCRATCH_STUB, stub)
                    ok("スタブ %d バイト設置 (status 0x%04X)" % (len(stub), st))
                    try_jump(SCRATCH_STUB, "経路3 スタブ")
                    brom_port = await_brom(args.wait_brom)
                except Exception as exc:
                    warn("スタブ経路失敗: %s" % exc)
            else:
                warn("スタブ経路: brom_api 未発見のためスキップ")

        # ---- 経路 4: プローブ + WDT ---------------------------------
        if not brom_port and write_ok and args.route in ("auto", "stub", "wdt"):
            info("経路4: WDT プローブ")
            try:
                st = pr.send_da(SCRATCH_PROBE, build_probe())
                ok("プローブ設置 (status 0x%04X)" % st)
                try_jump(SCRATCH_PROBE, "経路4 プローブ")
            except Exception as exc:
                warn("プローブ設置失敗: %s" % exc)
            brom_port = await_brom(args.wait_brom)

        # ---- 経路 5: 0xC7 で直接 WDT -------------------------------
        if not brom_port and args.route in ("auto", "wdt"):
            info("経路5: 0xC7 直接 WDT")
            for wide in (True, False):
                for reg, val in ((WDT_MODE, WDT_ENABLE),
                                 (WDT_LENGTH, 0x1000),
                                 (WDT_RESTART, WDT_KEY),
                                 (WDT_SWRST, WDT_KEY)):
                    try:
                        st, _ = pr.wr16(reg, val, wide=wide)
                        info("wr16 %#010x <- %#06x status 0x%04X (wide=%s)"
                             % (reg, val, st, wide))
                    except Exception as exc:
                        warn("wr16 %#010x 失敗: %s" % (reg, exc))
                brom_port = await_brom(6.0)
                if brom_port:
                    break

        if not brom_port:
            err("BROM へ移行できなかった")
            try:
                pr.sync()
            except Exception:
                pass
            pr.close()
            return 1

        pr.close()
        time.sleep(0.4)
    else:
        brom_port = port
        info("BROM に直結済み: %s" % brom_port)

    # ---- BROM 側 ---------------------------------------------------
    brom = Brom(brom_port)
    try:
        brom.open()
    except Exception as exc:
        err("BROM ポートを開けない: %s" % exc)
        return 2

    try:
        if not brom.handshake(tries=4):
            warn("ハンドシェイク不成立 - 0xD8 で生存確認")
            cfg = brom.target_config()
            if cfg is None:
                err("BROM 無応答")
                return 2
        else:
            ok("BROM ハンドシェイク成立 (5F F5 AF FA)")

        brom.kick()
        cfg = brom.target_config()
        if cfg:
            info("hw_code=%#06x hw_sub=%#06x hw_ver=%#06x sw_ver=%#06x" % cfg)
            if cfg[0] == 0x8167:
                ok("MT8167 を確認")
            else:
                warn("hw_code が 8167 ではない (%#06x)" % cfg[0])

        words = brom.read32(0x0, 4)
        info("BROM @0x0 = %s" % " ".join("%08x" % w for w in words))

        hold_brom(brom, args.keep)
        ok("完了: 0E8D:0003 (BROM) で保持中")
        info("このまま mtkclient / SP Flash Tool を接続できる")
        return 0
    finally:
        brom.close()
        LOG.close()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(130)
