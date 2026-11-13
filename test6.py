#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
mode_tool.py  —  MTK preloader ブートモード切替ツール
================================================================================
対象: MT8167 / MT8135 系 preloader (0e8d:2000)

【根拠 (アセンブリ)】
  0x1B78 : ldrh r4,[r0,#0x36]  ブートタグの boot_mode を読む
  0x1C28 : cmp r4,#6           ATE 専用分岐 (6 のとき PAD/GPIO を切替)
  0x24AC : モード 0/±1/±2/±3 -> r5=1..5、r10=2/1 で PMIC 経路選択
  0x3034 : [r4+0x3C] が 1/4 で分岐する EMI/DRAM 設定
  0x35F4 : [r4+0x8] が 3/5 で分岐する EMI/PMIC/クロック初期化
  0x1E7CC/0x1E820/0x1E830 : 0xD8 ステータスの 3 プローブ
  => モードは RTC PDN1[5:0] に永続。BROM が +0x36 へ転記する。
     RTC 書き込みは BBPU 上位 16bit = 0x4300 のアンロックが必須。

【プロトコル (0x1618-0x1694)】
  handshake: pattern[i] と比較し 一致=^0xFF / 不一致=受信値+1 かつ i=0
  0xD0 READ16 / 0xD1 READ32 / 0xD2 WRITE16 / 0xD4 WRITE32
  0xD5 JUMP / 0xD7 SEND_DA / 0xD8 STATUS / 0xFC ENTRY / 0xFD BASE / 0xFE PING

【使い方】
  python mode_tool.py --list
  python mode_tool.py --read
  python mode_tool.py --mode factory
  python mode_tool.py --mode ate --no-reset
  python mode_tool.py --mode meta --method payload
  python mode_tool.py --restore
================================================================================
"""

import argparse
import datetime
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
CMD_PING = 0xFE

PATTERN_HINT = [0xA0, 0x0A, 0x50, 0x05]
HSHK_BYTE_TO = 0.35
HSHK_GAP = 0.10
HSHK_MAX = 900

BAUD = 115200
IO_TO = 1.0
WR_TO = 6.0

RTC_BASE = 0x10003000
RTC_BBPU = RTC_BASE + 0x08
RTC_PDN1 = RTC_BASE + 0x1C
RTC_PDN2 = RTC_BASE + 0x20
RTC_KEY = 0x43000000
RTC_KEY_MASK = 0xFFFF0000

WDT_MODE = 0x10007000
WDT_RESTART = 0x10007008
WDT_SWRST = 0x10007014
WDT_MODE_KEY = 0x22000000
WDT_RESTART_KEY = 0x1971
WDT_SWRST_KEY = 0x1209

MODE_MASK = 0x3F
STUB = 0x40001000
STUB_ALT = 0x40002000

LOG_PATH = "mode_tool.log"
_fh = None

MODES = {
    "normal":   (0, "通常起動。BROM が preloader をロードして lk へ渡す"),
    "meta":     (1, "META。preloader が usbdl に入り 0e8d:2000 で待受"),
    "recovery": (2, "リカバリ。lk が recovery を選択"),
    "swreboot": (3, "SW リブート。0x3034 の [r4+0x3C]=1 系 EMI 設定"),
    "factory":  (4, "ファクトリ。0x1C28 の汎用分岐、0x35F4 の [r4+0x8]=4 系"),
    "advmeta":  (5, "ADV META。0x35F4 の [r4+0x8]=5 系"),
    "ate":      (6, "ATE ファクトリ。0x1C28 が 6 で専用 PAD/GPIO に切替"),
    "fastboot": (7, "fastboot"),
}


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
# 検出 (列挙のみ / ct6 と同一)
# ================================================================
def find_mtk_ports():
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
    end = time.monotonic() + timeout if timeout else 0
    tick = 0
    while True:
        hit = find_preloader_ports()
        if hit:
            return hit[0][0]
        if timeout and time.monotonic() >= end:
            fb = fallback_ports()
            return fb[0][0] if fb else None
        tick += 1
        if tick % 30 == 0:
            log(f"preloader 探索中... MTK {len(find_mtk_ports())} 件", ".")
        time.sleep(0.1)


def dump_ports():
    log("現在のポート:", ".")
    for dev, pid, desc in find_mtk_ports():
        m = "PRE" if pid in PRE_PIDS else ("BROM" if pid in BROM_PIDS else "-")
        log(f"  {dev} 0e8d:{pid:04x} [{m}] {desc}", ".")


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
        raise LinkError(f"handshake failed prefix={[hex(x) for x in prefix]}")

    # ---- エコー ----
    def echo(self, data, tag="e", timeout=None):
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

    # ---- 0xD1 / 0xD0 ----
    def read32(self, addr, cnt, timeout=15.0):
        self.begin(CMD_READ32, addr, cnt, "read32")
        out = []
        while len(out) < cnt:
            d = self.rx(min(0x400, cnt - len(out)) * 4, timeout)
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

    def read16(self, addr, cnt):
        self.begin(CMD_READ16, addr, cnt, "read16")
        d = self.rx(cnt * 2, 8.0)
        self.rx(2, 1.0)
        n = len(d) // 2
        return list(struct.unpack(">%dH" % n, d[:n * 2]))

    # ---- 0xD4 (4 バイト整列 / 0x19FC) ----
    def write32(self, addr, vals, verify=True, timeout=8.0):
        if addr & 3:
            raise LinkError("write32: 4 バイト整列が必要")
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

    # ---- 0xD7 ----
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
        t = self.rx(2, timeout)
        return struct.unpack(">H", t)[0] if len(t) == 2 else -1

    def jump(self, addr, timeout=2.5):
        self.echo(bytes([CMD_JUMP]), "jump")
        self.echo(struct.pack(">I", addr & 0xFFFFFFFF), "jump.a")
        return struct.unpack(">H", self.rx(2, timeout))[0]

    # ---- 0xD8 ----
    def status(self):
        self.tx(bytes([CMD_STATUS]))
        r = self.rx(1, 1.0)
        if not r:
            raise LinkError("status 無応答")
        return r[0]

    def ping(self):
        self.tx(bytes([CMD_PING]))
        return self.rx(1, 0.5) == b"\x01"


# ================================================================
# RTC
# ================================================================
def rtc_unlock(l):
    cur = l.read_u32(RTC_BBPU)
    l.set32(RTC_BBPU, (cur & 0xFFFF) | RTC_KEY)


def rtc_lock(l):
    cur = l.read_u32(RTC_BBPU)
    l.set32(RTC_BBPU, cur & ~RTC_KEY_MASK & 0xFFFFFFFF)


def read_mode(l):
    pdn1 = l.read_u32(RTC_PDN1)
    pdn2 = l.read_u32(RTC_PDN2)
    return pdn1, pdn2


def set_mode_rtc(l, mode, pdn2_bits=None):
    """PDN1[5:0] = mode。アンロック -> RMW -> 検証 -> ロック。"""
    rtc_unlock(l)
    try:
        cur = l.read_u32(RTC_PDN1)
        new = (cur & ~MODE_MASK & 0xFFFFFFFF) | (mode & MODE_MASK)
        l.set32(RTC_PDN1, new, verify=False)
        back = l.read_u32(RTC_PDN1)
        if (back & MODE_MASK) != (mode & MODE_MASK):
            raise LinkError(f"PDN1 反映失敗 {back:#010x} (要求 mode={mode})")
        if pdn2_bits is not None:
            cur2 = l.read_u32(RTC_PDN2)
            l.set32(RTC_PDN2, (cur2 | pdn2_bits) & 0xFFFFFFFF, verify=False)
    finally:
        rtc_lock(l)


def write_tag(l, tag_addr, mode):
    """ブートタグ +0x36 (0x1B78 / 0x1C28 が読む位置) を直接更新。"""
    if not tag_addr:
        return
    addr = tag_addr + 0x36
    base = addr & ~3
    off = addr & 3
    w = l.read32(base, 1)[0]
    shift = off * 8
    w = (w & ~(0xFFFF << shift) & 0xFFFFFFFF) | ((mode & 0xFFFF) << shift)
    l.set32(base, w, verify=False)


def swrst(l):
    try:
        l.set32(WDT_MODE, WDT_MODE_KEY | 0x14, verify=False)
        l.set32(WDT_RESTART, WDT_RESTART_KEY, verify=False)
        l.set32(WDT_SWRST, WDT_SWRST_KEY, verify=False)
        return True
    except LinkError:
        return True


# ================================================================
# ペイロード法
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


def build(pairs):
    w = []
    for a, v in pairs:
        w += [_movw(0, a), _movt(0, a), _movw(1, v), _movt(1, v), _str(1, 0)]
    w.append(B_SELF)
    return b"".join(struct.pack("<I", x) for x in w)


def payload_for_mode(mode):
    """RTC アンロック -> PDN1 下位6bit を mode に -> ロック -> WDT SWRST。"""
    pairs = [
        (RTC_BBPU, RTC_KEY),                  # アンロック
        (RTC_PDN1, mode & MODE_MASK),         # 下位6bit を設定 (他bit は 0 になる)
        (RTC_BBPU, 0),                        # ロック
        (WDT_MODE, WDT_MODE_KEY | 0x14),
        (WDT_RESTART, WDT_RESTART_KEY),
        (WDT_SWRST, WDT_SWRST_KEY),
    ]
    return build(pairs)


def words(p):
    pad = (-len(p)) % 4
    return list(struct.unpack("<%dI" % ((len(p) + pad) // 4), p + b"\x00" * pad))


# ================================================================
# 実行
# ================================================================
def do_mode(port, mode, method, reset, tag_addr, pdn2_bits):
    try:
        l = Link(port).open()
    except Exception as e:
        log(f"open 失敗: {e}", "!")
        return False
    try:
        pat = l.handshake()
        log(f"handshake OK {[hex(x) for x in pat]}", "+")

        pdn1, pdn2 = read_mode(l)
        log(f"現在 PDN1=0x{pdn1:08X} mode={pdn1 & MODE_MASK} / PDN2=0x{pdn2:08X}")
        try:
            log(f"status=0x{l.status():02X}")
        except LinkError:
            pass

        if method == "rtc":
            set_mode_rtc(l, mode, pdn2_bits)
            log(f"PDN1 更新 -> mode={mode}", "+")
        elif method == "payload":
            data = payload_for_mode(mode)
            log(f"payload {len(data)}B を 0x{STUB:08X} へ", ".")
            st = l.send_da(data, STUB)
            if st & 0xFF:
                log(f"send_da 失敗 0x{st:04X}", "!")
                return False
            l.send_da(b"\x00\x00\x00\x00", STUB)   # 準備フラグ (0x18D4)
            js = l.jump(STUB)
            log(f"jump=0x{js:04X}", ".")
            if reset:
                return True                      # payload 内で SWRST 済み
        elif method == "tag":
            set_mode_rtc(l, mode, pdn2_bits)
            write_tag(l, tag_addr, mode)
            log(f"PDN1 とタグ +0x36 を更新", "+")

        if tag_addr and method != "tag":
            write_tag(l, tag_addr, mode)

        # 反映確認
        back = l.read_u32(RTC_PDN1)
        if (back & MODE_MASK) != (mode & MODE_MASK):
            log(f"反映確認失敗 PDN1=0x{back:08X}", "!")
            return False
        log(f"反映確認 PDN1=0x{back:08X} mode={back & MODE_MASK}", "+")

        if reset:
            swrst(l)
            log("WDT_SWRST 発行", "+")
        return True
    except LinkError as e:
        log(f"失敗: {e}", "!")
        return False
    finally:
        try:
            l.close()
        except Exception:
            pass


def main(argv=None):
    global _fh
    ap = argparse.ArgumentParser(description="preloader ブートモード切替")
    ap.add_argument("--mode", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--read", action="store_true")
    ap.add_argument("--restore", action="store_true", help="normal に戻す")
    ap.add_argument("--method", choices=("rtc", "payload", "tag"), default="rtc")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--pdn2", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--tag-addr", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--port", default=None)
    ap.add_argument("--wait", type=float, default=90.0)
    ap.add_argument("--ports", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    if not HAS_SERIAL:
        print("pip install pyserial")
        return 2
    try:
        _fh = open(LOG_PATH, "w", encoding="utf-8")
    except Exception:
        _fh = None

    try:
        if a.list:
            print("モード一覧:")
            for k, (v, note) in MODES.items():
                print(f"  {k:9s} = {v}  {note}")
            return 0

        if a.ports:
            dump_ports()
            return 0

        if not (a.mode or a.read or a.restore):
            print("--mode / --read / --restore / --list のいずれかを指定")
            return 2

        name = "normal" if a.restore else a.mode
        if name is None:
            mode = None
        elif name in MODES:
            mode = MODES[name][0]
        else:
            try:
                mode = int(name, 0)
            except ValueError:
                print(f"不明なモード: {name}")
                return 2

        port = a.port or wait_preloader(a.wait)
        if not port:
            log("preloader 未検出", "!")
            dump_ports()
            return 2
        log(f"port: {port}", "+")

        if a.read:
            with Link(port) as l:
                l.handshake()
                pdn1, pdn2 = read_mode(l)
                print(f"RTC_PDN1 = 0x{pdn1:08X}  boot_mode = {pdn1 & MODE_MASK}")
                print(f"RTC_PDN2 = 0x{pdn2:08X}")
                for k, (v, note) in MODES.items():
                    if v == (pdn1 & MODE_MASK):
                        print(f"該当: {k} ({note})")
                try:
                    print(f"status   = 0x{l.status():02X}")
                except LinkError:
                    pass
            return 0

        if a.dry_run:
            print(f"mode={name}({mode}) method={a.method} reset={not a.no_reset}")
            return 0

        ok = do_mode(port, mode, a.method, not a.no_reset, a.tag_addr, a.pdn2)
        if not ok:
            return 1

        if not a.no_reset:
            log("リセット後の再列挙を待機...", ".")
            time.sleep(1.0)
            end = time.monotonic() + 12
            seen = None
            while time.monotonic() < end:
                for dev, pid, desc in find_mtk_ports():
                    seen = (dev, pid)
                    break
                if seen:
                    break
                time.sleep(0.2)
            if seen:
                log(f"再列挙: {seen[0]} 0e8d:{seen[1]:04x}", "+")
                if seen[1] in PRE_PIDS:
                    log("preloader 復帰。モードは反映済み (--read で確認)", "+")
            else:
                log("再列挙なし。ケーブルを挿し直して --read で確認", "!")
        return 0
    finally:
        if _fh:
            try:
                _fh.close()
            finally:
                _fh = None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中断")
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
