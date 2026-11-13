#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
mtk_brom_forge.py  v4  —  preloader(0e8d:2000) -> BROM(0e8d:0003/0006) 強制移行
================================================================================
■ 前提の修正（v3 までの誤りを全面訂正）
  * 0e8d:2000 は BROM ではなく preloader USBDL。BROM は 0003 / 0006。
  * ハンドシェイクは 1 バイト 0xA0 ではなく 4 バイト反転列:
        A0 -> 5F / 0A -> F5 / 50 -> AF / 05 -> FA
    全コマンドはエコー検証必須（echo mismatch は即失敗ではなく要分類）。
  * アドレスはビッグエンディアン u32、ステータスは BE u16（下位バイト 0 = OK）。
  * 0xD1=READ32 / 0xD2=WRITE16 / 0xD3=WRITE16(no echo) / 0xD4=WRITE32
    0xD5=JUMP / 0xD7=SEND_DA / 0xD8=WRITE8

■ 移行の物理原理
  BROM は warm reset 後に SRAMROM_USBDL(0x10209050) を検査し、
  0x444CFFFD が立っていれば preloader をロードせず自分で USBDL に入る。
  -> 「USBDL マジックを立てる」＋「WDT_SWRST」で落とす、が本質。
  RTC PDN1 のブートモード操作は補助（BROM 側の分岐を確実化する）。

■ 実行モード（12）
  M1  SEND_DA + JUMP
  M2  WRITE32 + JUMP
  M3  WRITE32 + RVBADDRESS + SWRST
  M4  WRITE32 + RVBADDRESS + SWRST (chunk 小)
  M5  WRITE8 + JUMP
  M6  SEND_DA(別アドレス) + JUMP
  M7  SEND_DA + tolerant JUMP (echo 欠落を成功許容)
  M8  WRITE32 + 読み戻し検証 + JUMP
  M9  WRITE32 + 読み戻し検証 + RVBADDRESS + SWRST
  M10 ペイロード無し: レジスタ直叩き (USBDL + RTC + WDT アーム + SWRST)
  M11 ペイロード無し: USBDL + SWRST のみ
  M12 SEND_DA + RVBADDRESS + SWRST

■ 判定
  リセット後に 0003/0006 が現れれば SUCCESS。
  同じ preloader PID が戻れば REBOOTED_PRELOADER（失敗・次へ）。
  echo 欠落は LIKELY として成功待機に回す。

■ サブコマンド
  analyze   … レジスタスナップショット / メモリスキャン / ディスパッチャ探索
  snapshot  … 重要レジスタの読み出しとデコード
  scan      … SRAM 候補域を走査し USBDL ディスパッチャと文字列を同定
  read/write/dump … 生メモリアクセス
  forge     … 攻撃プラン実行（既定）
  plan      … プラン一覧
================================================================================
"""

import argparse
import binascii
import datetime
import json
import os
import platform
import struct
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

# =============================================================================
# 定数
# =============================================================================
MTK_VID = 0x0E8D
PRELOADER_PIDS = (0x2000, 0x2001, 0x201C, 0x3000, 0x201D, 0x2003)
BROM_PIDS = (0x0003, 0x0006, 0x0007)

HSHK_PRELOADER = ((0xA0, 0x5F), (0x0A, 0xF5), (0x50, 0xAF), (0x05, 0xFA))
HSHK_BROM = ((0xA0, 0x5F),)

CMD_READ32 = 0xD1
CMD_WRITE16 = 0xD2
CMD_WRITE16_NECHO = 0xD3
CMD_WRITE32 = 0xD4
CMD_JUMP = 0xD5
CMD_SEND_DA = 0xD7
CMD_WRITE8 = 0xD8

SER_BAUD = 115200
SER_TIMEOUT = 1.0
SER_WRITE_TIMEOUT = 6.0
HSHK_BYTE_TIMEOUT = 0.35
HSHK_TRIES = 24
JUMP_ECHO_TIMEOUT = 0.5
ST_READ_TIMEOUT = 30.0

BROM_WAIT_SEC = 22.0
PRELOADER_WAIT_SEC = 5.0
COOLDOWN_SEC = 2.0
RESET_SETTLE_SEC = 1.2


# =============================================================================
# SoC プロファイル
# =============================================================================
@dataclass(frozen=True)
class SocProfile:
    name: str
    usbdl_flag: Optional[int]
    usbdl_value: int
    misc_lock: Optional[int]
    misc_lock_key: int
    rst_con: Optional[int]
    wdt_mode: int
    wdt_length: int
    wdt_restart: int
    wdt_swrst: int
    wdt_swsysrst: int
    wdt_nonrst: int
    rvbad_cpu0: Optional[int]
    stub_addr: int
    stub_alt: int
    rtc_base: int
    rtc_bbpu_ofs: int
    rtc_pdn1_ofs: int
    rtc_key: int
    brom_check2: Optional[int]
    brom_check2_fb: Optional[int]
    brom_rgu40: Optional[int]
    scan_bases: Tuple[int, ...]


WDT_MODE_KEY = 0x22000000
WDT_MODE_AUTO_RESTART = 1 << 4
WDT_MODE_EXTEN = 1 << 2
WDT_RESTART_KEY = 0x1971
WDT_SWRST_KEY = 0x1209
WDT_SWSYS_RST_KEY = 0x88000000
WDT_SWSYS_RST_MD_RST = 1 << 7
WDT_NONRST_MASK = 0xFFFFFFFF
BROM_RGU40_KEY = 0x59000000
BROM_CHECK2_MAGIC = 0x504D454D  # "MEMP"
BROM_ENTRY_WDT_MODE = 0x22000095
BROM_ENTRY_WDT_PRESET = 0x00008008
BROM_ENTRY_WDT_LENGTH = 0x00001008

BOOTMODE_NORMAL = 0
BOOTMODE_META = 1
BOOTMODE_RECOVERY = 2
BOOTMODE_FACTORY = 4
BOOTMODE_ATE = 6

PROFILES: Dict[str, SocProfile] = {
    "mt8167": SocProfile(
        name="mt8167",
        usbdl_flag=0x10209050,
        usbdl_value=0x444CFFFD,
        misc_lock=0x10209070,
        misc_lock_key=0x0000AD98,
        rst_con=0x10209078,
        wdt_mode=0x10007000,
        wdt_length=0x10007004,
        wdt_restart=0x10007008,
        wdt_swrst=0x10007014,
        wdt_swsysrst=0x10007018,
        wdt_nonrst=0x10007020,
        rvbad_cpu0=0x10200038,
        stub_addr=0x40001000,
        stub_alt=0x40002000,
        rtc_base=0x10003000,
        rtc_bbpu_ofs=0x08,
        rtc_pdn1_ofs=0x1C,
        rtc_key=0x43000000,
        brom_check2=0x0010303C,
        brom_check2_fb=0x1021405C,
        brom_rgu40=0x10007040,
        scan_bases=(0x00200000, 0x00201000, 0x00100000, 0x40000000),
    ),
    # 旧 MT8135/MT81367 系。USBDL フラグ未同定のため RTC/WDT 経路主体。
    "mt8135": SocProfile(
        name="mt8135",
        usbdl_flag=None,
        usbdl_value=0,
        misc_lock=None,
        misc_lock_key=0,
        rst_con=None,
        wdt_mode=0x10007000,
        wdt_length=0x10007004,
        wdt_restart=0x10007008,
        wdt_swrst=0x10007014,
        wdt_swsysrst=0x10007018,
        wdt_nonrst=0x10007020,
        rvbad_cpu0=None,
        stub_addr=0x00100000,
        stub_alt=0x00110000,
        rtc_base=0x10003000,
        rtc_bbpu_ofs=0x08,
        rtc_pdn1_ofs=0x1C,
        rtc_key=0x43000000,
        brom_check2=None,
        brom_check2_fb=None,
        brom_rgu40=None,
        scan_bases=(0x00100000, 0x00200000, 0x00010000),
    ),
}


# =============================================================================
# ログ
# =============================================================================
class Log:
    def __init__(self, path: Optional[str]):
        self.fh = None
        self.records: List[dict] = []
        if path:
            self.fh = open(path, "w", encoding="utf-8")
            self._raw("=" * 78)
            self._raw("mtk_brom_forge v4")
            self._raw(f"start={datetime.datetime.now().isoformat()}")
            self._raw(f"os={platform.platform()} py={sys.version.split()[0]}")

    def _raw(self, line: str) -> None:
        if self.fh:
            self.fh.write(line + "\n")
            self.fh.flush()

    def __call__(self, msg: str, tag: str = "*") -> None:
        line = f"[{tag}] {msg}"
        try:
            print(line)
        except Exception:
            pass
        self._raw(line)

    def event(self, kind: str, **kw) -> None:
        rec = {"t": datetime.datetime.now().isoformat(), "kind": kind, **kw}
        self.records.append(rec)

    def close(self) -> None:
        if self.fh:
            self._raw(f"end={datetime.datetime.now().isoformat()}")
            try:
                self.fh.close()
            finally:
                self.fh = None


LOG: Log = Log(None)


# =============================================================================
# 例外
# =============================================================================
class LinkError(Exception):
    pass


class EchoMismatch(LinkError):
    def __init__(self, sent: bytes, got: bytes):
        super().__init__(f"echo mismatch sent={sent.hex()} got={got.hex()}")
        self.sent = sent
        self.got = got


class StatusError(LinkError):
    def __init__(self, op: str, status: int):
        super().__init__(f"{op} status=0x{status:04X}")
        self.status = status


class VerifyError(LinkError):
    pass


# =============================================================================
# リンク層
# =============================================================================
class MtkLink:
    def __init__(self, port: str, profile: SocProfile,
                 timeout: float = SER_TIMEOUT, write_timeout: float = SER_WRITE_TIMEOUT):
        self.port = port
        self.profile = profile
        self.timeout = timeout
        self.write_timeout = write_timeout
        self.ser: Optional[serial.Serial] = None
        self.hshk_kind: str = "none"

    # -- 生 IO ------------------------------------------------------------

    def open(self) -> "MtkLink":
        self.ser = serial.Serial(
            self.port, SER_BAUD, timeout=self.timeout, write_timeout=self.write_timeout)
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass
        for attr in ("dtr", "rts"):
            try:
                setattr(self.ser, attr, True)
            except Exception:
                pass
        return self

    def close(self) -> None:
        if self.ser is not None:
            try:
                self.ser.close()
            finally:
                self.ser = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    def drain(self) -> None:
        if self.ser is None:
            return
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass

    def read_exact(self, n: int, timeout: Optional[float] = None) -> bytes:
        if self.ser is None:
            raise LinkError("port closed")
        if n == 0:
            return b""
        limit = self.timeout if timeout is None else timeout
        end = time.monotonic() + limit
        buf = bytearray()
        while len(buf) < n:
            left = end - time.monotonic()
            if left <= 0:
                break
            try:
                self.ser.timeout = min(left, 0.5)
                chunk = self.ser.read(n - len(buf))
            except serial.SerialException as e:
                raise LinkError(f"read: {e}")
            if chunk:
                buf += chunk
        return bytes(buf)

    def write(self, data: bytes) -> None:
        if self.ser is None:
            raise LinkError("port closed")
        try:
            self.ser.write(data)
            self.ser.flush()
        except serial.SerialException as e:
            raise LinkError(f"write: {e}")

    # -- ハンドシェイク ---------------------------------------------------

    def handshake(self, tries: int = HSHK_TRIES) -> str:
        """preloader 4 バイト列 -> BROM 1 バイト列 の順で試す。"""
        last = "no-attempt"
        for label, seq in (("preloader", HSHK_PRELOADER), ("brom", HSHK_BROM)):
            for _ in range(max(1, tries // 3)):
                self.drain()
                ok = True
                for val, exp in seq:
                    try:
                        self.write(bytes([val]))
                    except LinkError as e:
                        ok = False
                        last = f"{label}: write {e}"
                        break
                    got = self.read_exact(1, HSHK_BYTE_TIMEOUT)
                    if got != bytes([exp]):
                        ok = False
                        last = f"{label}: 0x{val:02X} -> {got.hex() or 'none'}"
                        break
                if ok:
                    self.hshk_kind = label
                    return label
                time.sleep(0.12)
        raise LinkError(f"handshake failed ({last})")

    # -- エコー付きコマンド ----------------------------------------------

    def _echo(self, payload: bytes, what: str, timeout: Optional[float] = None) -> None:
        self.write(payload)
        got = self.read_exact(len(payload), timeout)
        if got != payload:
            raise EchoMismatch(payload, got)

    def _cmd_begin(self, op: int, addr: int, count: int, what: str,
                   timeout: Optional[float] = None) -> None:
        self._echo(bytes([op]), what, timeout)
        self._echo(struct.pack(">I", addr & 0xFFFFFFFF), what + ":addr", timeout)
        self._echo(struct.pack(">I", count & 0xFFFFFFFF), what + ":len", timeout)
        st = struct.unpack(">H", self.read_exact(2, timeout or self.timeout))[0]
        if st & 0xFF:
            raise StatusError(what, st)

    # -- 公開プリミティブ ------------------------------------------------

    def read32(self, addr: int, count: int, chunk: int = 0x1000,
               timeout: float = ST_READ_TIMEOUT) -> List[int]:
        self._cmd_begin(CMD_READ32, addr, count, "read32")
        out: List[int] = []
        while len(out) < count:
            want = min(chunk, count - len(out))
            raw = self.read_exact(want * 4, timeout)
            nw = len(raw) // 4
            if nw == 0:
                break
            out.extend(struct.unpack(">%dI" % nw, raw[:nw * 4]))
        if len(out) == count:
            self.read_exact(2, 1.0)
        if len(out) != count:
            raise LinkError(f"read32 short: {len(out)}/{count}")
        return out

    def read_u32(self, addr: int) -> int:
        return self.read32(addr, 1, timeout=4.0)[0]

    def write32(self, addr: int, values: List[int], chunk: int = 32,
                timeout: float = 8.0, verify: bool = True) -> None:
        self._cmd_begin(CMD_WRITE32, addr, len(values), "write32")
        buf = bytearray()
        for v in values:
            buf += struct.pack(">I", v & 0xFFFFFFFF)
            if len(buf) >= chunk * 4:
                self._echo(bytes(buf), "write32:data", timeout)
                buf.clear()
        if buf:
            self._echo(bytes(buf), "write32:data", timeout)
        if values:
            self.read_exact(2, timeout)
        if verify:
            back = self.read32(addr, len(values), timeout=6.0)
            if back != [v & 0xFFFFFFFF for v in values]:
                for i, (a, b) in enumerate(zip(values, back)):
                    if (a & 0xFFFFFFFF) != b:
                        raise VerifyError(
                            f"write32 検証不一致 @{addr + i * 4:#x} "
                            f"wrote={a & 0xFFFFFFFF:#010x} read={b:#010x}")
                raise VerifyError("write32 検証不一致")

    def write8(self, addr: int, values: List[int], chunk: int = 64,
               timeout: float = 8.0, verify: bool = False) -> None:
        self._cmd_begin(CMD_WRITE8, addr, len(values), "write8")
        buf = bytearray()
        for v in values:
            buf.append(v & 0xFF)
            if len(buf) >= chunk:
                self._echo(bytes(buf), "write8:data", timeout)
                buf.clear()
        if buf:
            self._echo(bytes(buf), "write8:data", timeout)
        if values:
            self.read_exact(2, timeout)
        if verify:
            words = self.read32(addr & ~3, (len(values) + 3) // 4 + 1, timeout=6.0)
            blob = b"".join(struct.pack(">I", w) for w in words)
            off = addr & 3
            if blob[off:off + len(values)] != bytes(v & 0xFF for v in values):
                raise VerifyError("write8 検証不一致")

    def send_da(self, data: bytes, addr: int, timeout: float = 6.0) -> int:
        self._echo(bytes([CMD_SEND_DA]), "send_da")
        self._echo(struct.pack(">I", addr & 0xFFFFFFFF), "send_da:addr")
        self._echo(struct.pack(">I", len(data)), "send_da:len")
        self._echo(struct.pack(">I", 0), "send_da:sig")
        st = struct.unpack(">H", self.read_exact(2, timeout))[0]
        if st & 0xFF:
            return st
        self.write(data)
        rep = self.read_exact(4, timeout)
        if len(rep) == 4:
            return struct.unpack(">H", rep[2:4])[0]
        return -1

    def jump(self, addr: int, timeout: float = 3.0) -> int:
        self._echo(bytes([CMD_JUMP]), "jump")
        self._echo(struct.pack(">I", addr & 0xFFFFFFFF), "jump:addr")
        return struct.unpack(">H", self.read_exact(2, timeout))[0]

    def jump_tolerant(self, addr: int, timeout: float = JUMP_ECHO_TIMEOUT) -> Tuple[str, int]:
        """(判定, status)。'NO_ECHO' は即ジャンプ＝成功の可能性大。"""
        try:
            self.write(bytes([CMD_JUMP]))
            if not self.read_exact(1, timeout):
                return ("NO_ECHO", -1)
            if self.read_exact(0) != b"":
                pass
        except LinkError:
            return ("EXC", -1)
        # 既に opcode を送っているので、続きだけ緩く読む
        try:
            self.write(struct.pack(">I", addr & 0xFFFFFFFF))
            got = self.read_exact(4, timeout)
            if len(got) < 4:
                return ("ADDR_ECHO_SHORT", -1)
            st_raw = self.read_exact(2, timeout)
            if len(st_raw) < 2:
                return ("NO_STATUS", -1)
            st = struct.unpack(">H", st_raw)[0]
            return (("OK", 0) if st == 0 else ("NONZERO", st))
        except LinkError:
            return ("EXC_AFTER_ECHO", -1)


# =============================================================================
# ポート探索・分類
# =============================================================================
@dataclass
class PortInfo:
    device: str
    pid: int
    desc: str

    def __str__(self) -> str:
        return f"{self.device} 0e8d:{self.pid:04x} {self.desc}"


def list_mtk() -> List[PortInfo]:
    out: List[PortInfo] = []
    if not HAS_SERIAL:
        return out
    try:
        for p in serial.tools.list_ports.comports():
            if p.vid == MTK_VID and p.pid is not None:
                out.append(PortInfo(p.device, p.pid, p.description or ""))
    except Exception:
        pass
    return out


def wait_pid(pids: Tuple[int, ...], timeout: float) -> Optional[PortInfo]:
    end = time.monotonic() + timeout
    while True:
        for info in list_mtk():
            if info.pid in pids:
                return info
        if time.monotonic() >= end:
            return None
        time.sleep(0.15)


def classify(info: PortInfo, profile: SocProfile) -> Tuple[str, str]:
    """('brom'|'preloader'|'unknown', 詳細)。ハンドシェイク種別で確定。"""
    try:
        with MtkLink(info.device, profile) as link:
            kind = link.handshake(tries=9)
    except LinkError as e:
        return ("unknown", str(e))
    if kind == "brom" or info.pid in BROM_PIDS:
        return ("brom", f"handshake={kind}")
    return ("preloader", f"handshake={kind}")


# =============================================================================
# ARM32 ペイロード生成（AArch32）
# =============================================================================
B_SELF = 0xEAFFFFFE


def _movw(rd: int, imm16: int) -> int:
    return 0xE3000000 | (((imm16 >> 12) & 0xF) << 16) | ((rd & 0xF) << 12) | (imm16 & 0xFFF)


def _movt(rd: int, imm16: int) -> int:
    return 0xE3400000 | (((imm16 >> 12) & 0xF) << 16) | ((rd & 0xF) << 12) | (imm16 & 0xFFF)


def _str(rt: int, rn: int) -> int:
    return 0xE5800000 | ((rn & 0xF) << 16) | ((rt & 0xF) << 12)


def _ldr(rt: int, rn: int) -> int:
    return 0xE5900000 | ((rn & 0xF) << 16) | ((rt & 0xF) << 12)


def _write_pair(addr: int, value: int) -> List[int]:
    return [_movw(0, addr), _movt(0, addr), _movw(1, value), _movt(1, value), _str(1, 0)]


def build_payload(program: List[Tuple[int, int]], spin: bool = True) -> bytes:
    words: List[int] = []
    for addr, value in program:
        words.extend(_write_pair(addr, value))
    if spin:
        words.append(B_SELF)
    return b"".join(struct.pack("<I", w) for w in words)


def decode_payload(payload: bytes) -> List[Tuple[int, int]]:
    n = len(payload) // 4
    words = struct.unpack("<%dI" % n, payload)
    out: List[Tuple[int, int]] = []
    i = 0
    while i + 5 <= n:
        w = words[i:i + 5]
        if ((w[0] & 0xFFF00000) == 0xE3000000 and (w[1] & 0xFFF00000) == 0xE3400000
                and (w[2] & 0xFFF00000) == 0xE3000000 and (w[3] & 0xFFF00000) == 0xE3400000
                and (w[4] & 0x0FF00000) == 0x05800000):
            addr = (((w[0] >> 16) & 0xF) << 12 | (w[0] & 0xFFF)) | \
                   ((((w[1] >> 16) & 0xF) << 12 | (w[1] & 0xFFF)) << 16)
            val = (((w[2] >> 16) & 0xF) << 12 | (w[2] & 0xFFF)) | \
                  ((((w[3] >> 16) & 0xF) << 12 | (w[3] & 0xFFF)) << 16)
            out.append((addr & 0xFFFFFFFF, val & 0xFFFFFFFF))
            i += 5
        else:
            i += 1
    return out


def payload_crc(payload: bytes) -> str:
    return binascii.crc32(payload) & 0xFFFFFFFF


# =============================================================================
# ペイロード定義
# =============================================================================
def _p_usbdl(p: SocProfile) -> List[Tuple[int, int]]:
    return [(p.usbdl_flag, p.usbdl_value)] if p.usbdl_flag is not None else []


def _p_misc(p: SocProfile) -> List[Tuple[int, int]]:
    if p.misc_lock is None or p.rst_con is None:
        return []
    return [(p.misc_lock, p.misc_lock_key), (p.rst_con, 1), (p.misc_lock, 0)]


def _p_wdt_arm(p: SocProfile) -> List[Tuple[int, int]]:
    return [
        (p.wdt_restart, WDT_RESTART_KEY),
        (p.wdt_mode, WDT_MODE_KEY | WDT_MODE_AUTO_RESTART | WDT_MODE_EXTEN),
    ]


def _p_swrst(p: SocProfile) -> List[Tuple[int, int]]:
    return [(p.wdt_swrst, WDT_SWRST_KEY)]


def _p_rtc(p: SocProfile, mode: int) -> List[Tuple[int, int]]:
    # PDN1 の下位 6bit だけ落としてモードを入れる（RMW はペイロードでは省略し、
    # 直後に読戻しで検証する。全ビット上書きを避けるためマスクは呼び出し側でなく
    # レジスタ直叩きモードで行う）
    return [(p.rtc_base + p.rtc_bbpu_ofs, p.rtc_key),
            (p.rtc_base + p.rtc_pdn1_ofs, mode)]


PAYLOADS = {
    "P1": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + _p_wdt_arm(p) + _p_swrst(p)),
    "P2": lambda p: build_payload(_p_usbdl(p) + _p_wdt_arm(p) + _p_swrst(p)),
    "P3": lambda p: build_payload(
        [(p.brom_check2, BROM_CHECK2_MAGIC)] if p.brom_check2 else []),
    "P3B": lambda p: build_payload(
        [(p.brom_check2_fb, BROM_CHECK2_MAGIC)] if p.brom_check2_fb else []),
    "P4": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + (
        [(p.rvbad_cpu0, 0xDEADBEEF), (p.rvbad_cpu0 + 8, 0xFFFFFFFF)]
        if p.rvbad_cpu0 else []) + _p_wdt_arm(p) + _p_swrst(p)),
    "P5": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + [
        (p.wdt_swsysrst, WDT_SWSYS_RST_KEY | WDT_SWSYS_RST_MD_RST),
        (p.wdt_swsysrst, WDT_SWSYS_RST_KEY)] + _p_wdt_arm(p) + _p_swrst(p)),
    "P6": lambda p: build_payload(_p_usbdl(p)),
    "P7": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + [
        (p.wdt_nonrst, WDT_NONRST_MASK), (p.wdt_nonrst + 4, WDT_NONRST_MASK)]
        + _p_wdt_arm(p) + _p_swrst(p)),
    "P8": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + _p_rtc(p, BOOTMODE_META)
                                  + _p_wdt_arm(p) + _p_swrst(p)),
    "P9": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + _p_rtc(p, BOOTMODE_FACTORY)
                                  + _p_wdt_arm(p) + _p_swrst(p)),
    "P10": lambda p: build_payload(_p_misc(p) + _p_usbdl(p) + [
        (p.wdt_mode, BROM_ENTRY_WDT_MODE),
        (p.wdt_length, BROM_ENTRY_WDT_PRESET),
        (p.wdt_restart, BROM_ENTRY_WDT_RESTART),
        (p.wdt_length, BROM_ENTRY_WDT_LENGTH),
        (p.wdt_restart, BROM_ENTRY_WDT_RESTART)]),
}


def payload_bytes(pid: str, profile: SocProfile) -> bytes:
    data = PAYLOADS[pid](profile)
    if not data:
        raise ValueError(f"{pid} は {profile.name} で未定義")
    return data


# =============================================================================
# 実行モード
# =============================================================================
@dataclass
class ModeOutcome:
    tag: str
    detail: str = ""
    reset_likely: bool = True
    success_likely: bool = False


def _words(payload: bytes) -> List[int]:
    pad = (-len(payload)) % 4
    return list(struct.unpack("<%dI" % ((len(payload) + pad) // 4), payload + b"\x00" * pad))


def m_send_jump(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    st = link.send_da(payload, addr)
    if st & 0xFF:
        return ModeOutcome("SEND_DA_FAIL", f"status=0x{st:04X}", False)
    try:
        js = link.jump(addr)
    except EchoMismatch as e:
        return ModeOutcome("JUMP_ECHO_LOST", str(e), True, True)
    except LinkError as e:
        return ModeOutcome("JUMP_EXC", str(e), True, True)
    if js == 0:
        return ModeOutcome("JUMP_OK", "", True, True)
    return ModeOutcome("JUMP_NONZERO", f"status=0x{js:04X}", True, False)


def m_send_tolerant(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    st = link.send_da(payload, addr)
    if st & 0xFF:
        return ModeOutcome("SEND_DA_FAIL", f"status=0x{st:04X}", False)
    verdict, js = link.jump_tolerant(addr)
    if verdict in ("NO_ECHO", "NO_STATUS", "OK"):
        return ModeOutcome(f"JUMP_{verdict}", f"st={js}", True, True)
    return ModeOutcome(f"JUMP_{verdict}", f"st={js}", True, False)


def m_write_jump(link: MtkLink, payload: bytes, p: SocProfile, addr: int,
                 verify: bool = True, chunk: int = 32) -> ModeOutcome:
    link.write32(addr, _words(payload), chunk=chunk, verify=verify)
    try:
        js = link.jump(addr)
    except EchoMismatch:
        return ModeOutcome("JUMP_ECHO_LOST", "", True, True)
    except LinkError as e:
        return ModeOutcome("JUMP_EXC", str(e), True, True)
    return ModeOutcome("JUMP_OK" if js == 0 else "JUMP_NONZERO", f"st=0x{js:04X}", True, js == 0)


def m_write8_jump(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    link.write8(addr, list(payload), verify=True)
    try:
        js = link.jump(addr)
    except (EchoMismatch, LinkError):
        return ModeOutcome("JUMP_ECHO_LOST", "", True, True)
    return ModeOutcome("JUMP_OK" if js == 0 else "JUMP_NONZERO", f"st=0x{js:04X}", True, js == 0)


def _need_rvbad(p: SocProfile) -> int:
    if p.rvbad_cpu0 is None:
        raise LinkError("RVBADDRESS 未定義の SoC です")
    return p.rvbad_cpu0


def m_write_rvbad_swrst(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    link.write32(addr, _words(payload), verify=True)
    link.write32(_need_rvbad(p), [addr])
    try:
        link.write32(p.wdt_swrst, [WDT_SWRST_KEY], verify=False)
    except LinkError:
        return ModeOutcome("SWRST_ISSUED", "切断", True, True)
    return ModeOutcome("SWRST_ISSUED", "", True, True)


def m_send_rvbad_swrst(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    st = link.send_da(payload, addr)
    if st & 0xFF:
        return ModeOutcome("SEND_DA_FAIL", f"status=0x{st:04X}", False)
    link.write32(_need_rvbad(p), [addr])
    try:
        link.write32(p.wdt_swrst, [WDT_SWRST_KEY], verify=False)
    except LinkError:
        return ModeOutcome("SWRST_ISSUED", "切断", True, True)
    return ModeOutcome("SWRST_ISSUED", "", True, True)


def m_regs_only(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    """ペイロードを使わず USBDL + RTC PDN1(RMW) + WDT アーム + SWRST。"""
    if p.usbdl_flag is not None:
        link.write32(p.usbdl_flag, [p.usbdl_value])
    if p.misc_lock is not None:
        link.write32(p.misc_lock, [p.misc_lock_key])
        link.write32(p.rst_con, [1])
        link.write32(p.misc_lock, [0])
    pdn1 = p.rtc_base + p.rtc_pdn1_ofs
    link.write32(p.rtc_base + p.rtc_bbpu_ofs, [p.rtc_key])
    cur = link.read_u32(pdn1)
    link.write32(pdn1, [(cur & 0xFFFFFFC0) | BOOTMODE_META])
    link.write32(p.rtc_base + p.rtc_bbpu_ofs, [p.rtc_key])
    link.write32(p.wdt_mode, [WDT_MODE_KEY | WDT_MODE_AUTO_RESTART | WDT_MODE_EXTEN])
    link.write32(p.wdt_restart, [WDT_RESTART_KEY])
    try:
        link.write32(p.wdt_swrst, [WDT_SWRST_KEY], verify=False)
    except LinkError:
        return ModeOutcome("SWRST_ISSUED", "切断", True, True)
    return ModeOutcome("SWRST_ISSUED", "", True, True)


def m_usbdl_swrst(link: MtkLink, payload: bytes, p: SocProfile, addr: int) -> ModeOutcome:
    if p.usbdl_flag is not None:
        link.write32(p.usbdl_flag, [p.usbdl_value])
    try:
        link.write32(p.wdt_swrst, [WDT_SWRST_KEY], verify=False)
    except LinkError:
        return ModeOutcome("SWRST_ISSUED", "切断", True, True)
    return ModeOutcome("SWRST_ISSUED", "", True, True)


MODES: Dict[str, dict] = {
    "M1":  {"desc": "SEND_DA + JUMP", "fn": m_send_jump, "needs_payload": True},
    "M2":  {"desc": "WRITE32 + JUMP", "fn": m_write_jump, "needs_payload": True},
    "M3":  {"desc": "WRITE32 + RVBAD + SWRST", "fn": m_write_rvbad_swrst, "needs_payload": True},
    "M4":  {"desc": "WRITE32(chunk8) + RVBAD + SWRST",
            "fn": lambda l, d, p, a: m_write_jump.__wrapped__(l, d, p, a) if False else
            (lambda: None)() or m_write_rvbad_swrst(l, d, p, a), "needs_payload": True},
    "M5":  {"desc": "WRITE8 + JUMP", "fn": m_write8_jump, "needs_payload": True},
    "M6":  {"desc": "SEND_DA(alt) + JUMP", "fn": m_send_jump, "needs_payload": True, "alt": True},
    "M7":  {"desc": "SEND_DA + tolerant JUMP", "fn": m_send_tolerant, "needs_payload": True},
    "M8":  {"desc": "WRITE32 + 検証 + JUMP", "fn": m_write_jump, "needs_payload": True},
    "M9":  {"desc": "WRITE32 + 検証 + RVBAD + SWRST", "fn": m_write_rvbad_swrst, "needs_payload": True},
    "M10": {"desc": "レジスタ直叩き (USBDL+RTC+WDT+SWRST)", "fn": m_regs_only, "needs_payload": False},
    "M11": {"desc": "USBDL + SWRST のみ", "fn": m_usbdl_swrst, "needs_payload": False},
    "M12": {"desc": "SEND_DA + RVBAD + SWRST", "fn": m_send_rvbad_swrst, "needs_payload": True},
}


# =============================================================================
# プラン
# =============================================================================
@dataclass
class Step:
    payload: str
    mode: str
    note: str
    score: int

    @property
    def key(self) -> str:
        return f"{self.payload}+{self.mode}"


def build_plan(profile: SocProfile) -> List[Step]:
    raw = [
        # 第1波: 正規ルート（JUMP あり）
        ("P1", "M1", "USBDL+MISCLOCK+WDT/SWRST を SEND_DA で投入", 100),
        ("P1", "M7", "同・JUMP echo 欠落許容", 98),
        ("P2", "M1", "USBDL+WDT/SWRST を SEND_DA で投入", 95),
        ("P8", "M1", "USBDL+RTC(META)+WDT/SWRST", 92),
        ("P4", "M1", "USBDL+RVBAD+WDT/SWRST", 90),
        # 第2波: WRITE32 直書き
        ("P1", "M2", "WRITE32 で STUB へ + JUMP", 88),
        ("P1", "M8", "WRITE32 検証付き + JUMP", 87),
        ("P2", "M2", "USBDL のみ WRITE32 + JUMP", 85),
        ("P4", "M2", "USBDL+RVBAD WRITE32 + JUMP", 84),
        ("P1", "M5", "WRITE8 で 1 バイトずつ + JUMP", 80),
        # 第3波: JUMP を使わない（RVBAD 経由）
        ("P1", "M3", "WRITE32 + RVBAD + SWRST", 78),
        ("P1", "M9", "WRITE32 検証 + RVBAD + SWRST", 77),
        ("P2", "M3", "USBDL WRITE32 + RVBAD + SWRST", 76),
        ("P8", "M3", "USBDL+RTC WRITE32 + RVBAD + SWRST", 75),
        ("P1", "M12", "SEND_DA + RVBAD + SWRST", 74),
        ("P5", "M3", "MD リセット併用 + RVBAD + SWRST", 72),
        # 第4波: ペイロード無し・レジスタのみ
        ("-", "M10", "USBDL+RTC PDN1(META)+WDT アーム+SWRST", 70),
        ("-", "M11", "USBDL + SWRST のみ", 66),
        # 第5波: BROM Check2 / RGU40
        ("P3", "M1", "Check2 MEMP + SEND_DA/JUMP", 64),
        ("P3B", "M1", "Check2 fallback + SEND_DA/JUMP", 62),
        ("P3", "M2", "Check2 + WRITE32/JUMP", 60),
        ("P10", "M1", "WDT プリセット + SEND_DA/JUMP", 58),
        # 第6波: NONRST 汚染 / 工場モード
        ("P7", "M1", "NONRST 汚染 + SEND_DA/JUMP", 55),
        ("P9", "M1", "RTC FACTORY + SEND_DA/JUMP", 52),
        ("P6", "M1", "USBDL のみ + SEND_DA/JUMP", 50),
        ("P6", "M7", "USBDL のみ + tolerant JUMP", 48),
        # 第7波: 代替アドレス
        ("P1", "M6", "代替アドレスへ SEND_DA", 45),
        ("P2", "M6", "代替アドレスへ USBDL", 43),
    ]
    plan: List[Step] = []
    for pid, mid, note, score in raw:
        if pid != "-" and PAYLOADS[pid](profile) == b"":
            continue
        plan.append(Step(pid, mid, note, score))
    plan.sort(key=lambda s: -s.score)
    return plan


# =============================================================================
# 解析
# =============================================================================
SIG_OPCODES = bytes([CMD_READ32, CMD_WRITE16, CMD_WRITE16_NECHO,
                     CMD_WRITE32, CMD_JUMP, CMD_SEND_DA, CMD_WRITE8])
SIG_STRINGS = (b"AND_ROM_INFO", b"MT8167", b"MT8163", b"MT8135", b"preloader",
               b"AND_SECCTRL", b"secro")


def snap_regs(link: MtkLink, p: SocProfile) -> Dict[str, Optional[int]]:
    addrs = {
        "usbdl_flag": p.usbdl_flag,
        "misc_lock": p.misc_lock,
        "rst_con": p.rst_con,
        "wdt_mode": p.wdt_mode,
        "wdt_length": p.wdt_length,
        "wdt_restart": p.wdt_restart,
        "wdt_swrst": p.wdt_swrst,
        "wdt_swsysrst": p.wdt_swsysrst,
        "rvbad_cpu0": p.rvbad_cpu0,
        "rtc_bbpu": p.rtc_base + p.rtc_bbpu_ofs,
        "rtc_pdn1": p.rtc_base + p.rtc_pdn1_ofs,
    }
    out: Dict[str, Optional[int]] = {}
    for name, addr in addrs.items():
        if addr is None:
            out[name] = None
            continue
        try:
            out[name] = link.read_u32(addr)
        except LinkError:
            out[name] = None
    return out


def decode_snapshot(snap: Dict[str, Optional[int]]) -> List[str]:
    lines: List[str] = []
    u = snap.get("usbdl_flag")
    if u is None:
        lines.append("USBDLフラグ     : (未定義 SoC)")
    elif (u & 0xFFFF0000) == 0x444C0000:
        lines.append(f"USBDLフラグ     : 0x{u:08X}  => 立っている (BROM 直行準備済)")
    else:
        lines.append(f"USBDLフラグ     : 0x{u:08X}  => 未設定")
    wm = snap.get("wdt_mode")
    if wm is None:
        lines.append("WDT_MODE        : 読めず")
    else:
        en = "EN" if wm & 1 else "off"
        ar = "AUTO_RESTART" if wm & WDT_MODE_AUTO_RESTART else "-"
        lines.append(f"WDT_MODE        : 0x{wm:08X} [{en} {ar}]")
    pd = snap.get("rtc_pdn1")
    if pd is None:
        lines.append("RTC_PDN1        : 読めず")
    else:
        lines.append(f"RTC_PDN1        : 0x{pd:08X} boot_mode={pd & 0x3F} "
                     f"({'META' if (pd & 0x3F) == 1 else 'FACTORY' if (pd & 0x3F) == 4 else 'ATE' if (pd & 0x3F) == 6 else 'NORMAL/他'})")
    rv = snap.get("rvbad_cpu0")
    if rv is not None:
        lines.append(f"RVBADDRESS_CPU0 : 0x{rv:08X}")
    return lines


def scan_preloader(link: MtkLink, p: SocProfile, span: int = 0x4000) -> List[dict]:
    """SRAM 候補域を走査し、USBDL ディスパッチャと識別文字列を探す。"""
    hits: List[dict] = []
    for base in p.scan_bases:
        try:
            words = link.read32(base, span // 4, timeout=ST_READ_TIMEOUT)
        except LinkError as e:
            hits.append({"base": base, "error": str(e)})
            continue
        blob = b"".join(struct.pack(">I", w) for w in words)
        entry = {"base": base, "size": len(blob), "strings": [], "opcode_runs": []}
        for s in SIG_STRINGS:
            off = blob.find(s)
            if off >= 0:
                entry["strings"].append({"off": base + off, "text": s.decode("ascii", "replace")})
        # 0xD1..0xD8 が 8 バイト以内に 4 個以上並ぶ箇所＝ディスパッチャ候補
        idx = blob.find(SIG_OPCODES[:3])
        while idx >= 0:
            window = blob[idx:idx + 8]
            if sum(1 for b in window if 0xD1 <= b <= 0xD8) >= 4:
                entry["opcode_runs"].append({"off": base + idx, "bytes": window.hex()})
            idx = blob.find(SIG_OPCODES[:3], idx + 1)
        hits.append(entry)
    return hits


# =============================================================================
# セッション
# =============================================================================
@dataclass
class Attempt:
    n: int
    payload: str
    mode: str
    note: str
    outcome: str = ""
    detail: str = ""
    brom_pid: Optional[int] = None
    elapsed: float = 0.0


class Forge:
    def __init__(self, profile: SocProfile, args: argparse.Namespace):
        self.p = profile
        self.a = args
        self.history: List[Attempt] = []

    # -- ポート -----------------------------------------------------------

    def acquire_preloader(self, timeout: float) -> Optional[PortInfo]:
        return wait_pid(PRELOADER_PIDS, timeout)

    def wait_brom(self, timeout: float) -> Optional[PortInfo]:
        return wait_pid(BROM_PIDS, timeout)

    def reset_verdict(self, timeout: float) -> Tuple[str, Optional[int]]:
        """リセット後の再列挙を判定。"""
        end = time.monotonic() + timeout
        seen_pre: Optional[int] = None
        while time.monotonic() < end:
            for info in list_mtk():
                if info.pid in BROM_PIDS:
                    return ("BROM", info.pid)
                if info.pid in PRELOADER_PIDS and seen_pre is None:
                    seen_pre = info.pid
            time.sleep(0.15)
        if seen_pre is not None:
            return ("PRELOADER", seen_pre)
        return ("GONE", None)

    # -- 1 試行 -----------------------------------------------------------

    def run_attempt(self, step: Step, n: int, total: int) -> Attempt:
        att = Attempt(n, step.payload, step.mode, step.note)
        t0 = time.monotonic()
        LOG(f"--- {n}/{total}  {step.key}  ({step.note})")

        info = self.acquire_preloader(PRELOADER_WAIT_SEC)
        if info is None:
            att.outcome = "NO_PRELOADER"
            att.elapsed = time.monotonic() - t0
            return att

        payload = b""
        if step.payload != "-":
            try:
                payload = payload_bytes(step.payload, self.p)
            except ValueError as e:
                att.outcome = "PAYLOAD_UNDEF"
                att.detail = str(e)
                att.elapsed = time.monotonic() - t0
                return att
            LOG(f"    ペイロード {step.payload}: {len(payload)}B crc={payload_crc(payload):08X}")
            for addr, val in decode_payload(payload):
                LOG(f"      0x{addr:08X} <- 0x{val:08X}", ".")

        mode = MODES[step.mode]
        addr = self.p.stub_alt if mode.get("alt") else self.p.stub_addr

        try:
            with MtkLink(info.device, self.p) as link:
                kind = link.handshake()
                LOG(f"    handshake={kind} on {info.device}", "+")
                if kind == "brom":
                    att.outcome = "ALREADY_BROM"
                    att.brom_pid = info.pid
                    att.elapsed = time.monotonic() - t0
                    return att
                if self.a.snapshot_before and n == 1:
                    snap = snap_regs(link, self.p)
                    for line in decode_snapshot(snap):
                        LOG("    " + line, ".")
                out = mode["fn"](link, payload, self.p, addr)
                att.outcome = out.tag
                att.detail = out.detail
        except EchoMismatch as e:
            att.outcome = "ECHO_MISMATCH"
            att.detail = str(e)
        except StatusError as e:
            att.outcome = "STATUS_ERROR"
            att.detail = str(e)
        except VerifyError as e:
            att.outcome = "VERIFY_FAIL"
            att.detail = str(e)
        except LinkError as e:
            att.outcome = "LINK_ERROR"
            att.detail = str(e)
        except Exception as e:
            att.outcome = "EXCEPTION"
            att.detail = f"{e}"
            LOG(traceback.format_exc(), "!")

        att.elapsed = time.monotonic() - t0
        LOG(f"    結果={att.outcome} {att.detail}", "*")

        likely = att.outcome in ("JUMP_OK", "JUMP_ECHO_LOST", "JUMP_NO_ECHO",
                                 "JUMP_NO_STATUS", "SWRST_ISSUED")
        if likely or att.outcome in ("LINK_ERROR", "ECHO_MISMATCH"):
            time.sleep(RESET_SETTLE_SEC)
            verdict, pid = self.reset_verdict(self.a.brom_timeout)
            LOG(f"    再列挙={verdict} pid={pid}", "*")
            if verdict == "BROM":
                att.brom_pid = pid
                att.outcome = "SUCCESS"
            elif verdict == "PRELOADER":
                att.outcome = att.outcome + ">PRELOADER"
        return att

    # -- 全体 -------------------------------------------------------------

    def run(self) -> int:
        plan = build_plan(self.p)
        if self.a.only:
            want = {s.strip().upper() for s in self.a.only.split(",") if s.strip()}
            plan = [s for s in plan if s.payload in want or s.mode in want]
        if self.a.max_attempts:
            plan = plan[:self.a.max_attempts]
        if not plan:
            LOG("実行可能なステップがありません", "-")
            return 2

        LOG(f"プラン {len(plan)} 件 / SoC={self.p.name}")

        for n, step in enumerate(plan, start=1):
            att = self.run_attempt(step, n, len(plan))
            self.history.append(att)
            LOG.event("attempt", **asdict(att))
            if att.outcome == "SUCCESS":
                self.report_success(att)
                return 0
            time.sleep(self.a.cooldown)

        final = self.wait_brom(12.0)
        if final:
            att = Attempt(len(plan) + 1, "FINAL", "-", "最終待機で BROM 出現")
            att.outcome = "SUCCESS"
            att.brom_pid = final.pid
            self.history.append(att)
            self.report_success(att)
            return 0

        self.report_failure()
        return 1

    # -- レポート ---------------------------------------------------------

    def report_success(self, att: Attempt) -> None:
        LOG("")
        LOG("=" * 70, "+")
        LOG("SUCCESS: BROM (0e8d:0003/0006) へ移行", "+")
        LOG("=" * 70, "+")
        LOG(f"成功試行 : {att.n}  {att.payload}+{att.mode}  ({att.note})", "+")
        LOG(f"BROM PID : 0x{att.brom_pid:04X}" if att.brom_pid else "BROM PID : ?", "+")
        LOG("", "+")
        LOG("履歴:", "+")
        for h in self.history:
            mark = "  <= 成功" if h is att else ""
            LOG(f"  {h.n:2d} {h.payload}+{h.mode} -> {h.outcome}{mark}", "+")
        LOG("", "+")
        LOG("次の一手:", "+")
        LOG("  1) 0e8d:0003 に対して BROM ハンドシェイク(0xA0)で接続確認", "+")
        LOG("  2) DA を SEND_DA で投入 -> JUMP で実行", "+")
        LOG("  3) ここで再度リセットすると再び preloader に戻るため DA 常駐を維持", "+")

    def report_failure(self) -> None:
        LOG("")
        LOG("=" * 70, "-")
        LOG("FAILURE: 全経路不成立", "-")
        LOG("=" * 70, "-")
        for h in self.history:
            LOG(f"  {h.n:2d} {h.payload}+{h.mode} -> {h.outcome} {h.detail}", "-")
        LOG("", "-")
        LOG("現在の MTK ポート:", "-")
        for info in list_mtk():
            LOG(f"  {info}", "-")
        LOG("", "-")
        LOG("推奨:", "-")
        LOG("  1) USB を抜き 30 秒放電", "-")
        LOG("  2) 基板キー(Vol+/Vol-/BOOT)を保持したまま接続", "-")
        LOG("  3) --soc mt8135 / --stub 0x... を変えて再試行", "-")
        LOG("  4) analyze で USBDL フラグが書けているか確認", "-")


# =============================================================================
# サブコマンド実装
# =============================================================================
def pick_port(args) -> PortInfo:
    if args.port:
        for info in list_mtk():
            if info.device.lower() == args.port.lower():
                return info
        raise SystemExit(f"ポート {args.port} が見つかりません")
    info = wait_pid(PRELOADER_PIDS, args.wait)
    if info is None:
        raise SystemExit("preloader ポートが見つかりません")
    return info


def cmd_snapshot(args, p: SocProfile) -> int:
    info = pick_port(args)
    with MtkLink(info.device, p) as link:
        LOG(f"handshake={link.handshake()} on {info.device}")
        snap = snap_regs(link, p)
    for line in decode_snapshot(snap):
        print(line)
    print()
    for k, v in snap.items():
        print(f"  {k:14s} = " + ("n/a" if v is None else f"0x{v:08X}"))
    return 0


def cmd_analyze(args, p: SocProfile) -> int:
    info = pick_port(args)
    with MtkLink(info.device, p) as link:
        kind = link.handshake()
        LOG(f"handshake={kind} on {info.device} / pid=0x{info.pid:04X}")
        snap = snap_regs(link, p)
        for line in decode_snapshot(snap):
            LOG("  " + line, ".")
        hits = scan_preloader(link, p, span=args.span)
    print()
    print("=== スキャン結果 ===")
    for h in hits:
        if "error" in h:
            print(f"  0x{h['base']:08X}: {h['error']}")
            continue
        print(f"  0x{h['base']:08X}: strings={len(h['strings'])} "
              f"opcode_runs={len(h['opcode_runs'])}")
        for s in h["strings"]:
            print(f"      str @0x{s['off']:08X} {s['text']}")
        for o in h["opcode_runs"][:6]:
            print(f"      dispatch? @0x{o['off']:08X} {o['bytes']}")
    if not any(h.get("strings") or h.get("opcode_runs") for h in hits):
        print("  有意なシグネチャなし。--span を増やす / --soc を変える。")
    return 0


def cmd_read(args, p: SocProfile) -> int:
    info = pick_port(args)
    with MtkLink(info.device, p) as link:
        link.handshake()
        words = link.read32(args.addr, args.count)
    for i, w in enumerate(words):
        print(f"0x{args.addr + i * 4:08X}: {w:08X}")
    return 0


def cmd_write(args, p: SocProfile) -> int:
    info = pick_port(args)
    with MtkLink(info.device, p) as link:
        link.handshake()
        link.write32(args.addr, args.values, verify=not args.no_verify)
        back = link.read32(args.addr, len(args.values))
    for i, w in enumerate(back):
        print(f"0x{args.addr + i * 4:08X}: {w:08X}")
    return 0


def cmd_dump(args, p: SocProfile) -> int:
    info = pick_port(args)
    with MtkLink(info.device, p) as link:
        link.handshake()
        words = link.read32(args.addr, args.count)
    blob = b"".join(struct.pack(">I", w) for w in words)
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"{len(blob)} bytes -> {args.out}")
    return 0


def cmd_plan(args, p: SocProfile) -> int:
    plan = build_plan(p)
    print(f"SoC={p.name} の優先プラン {len(plan)} 件:")
    for s in plan:
        print(f"  {s.score:3d}  {s.key:8s} {s.note}")
    return 0


def cmd_forge(args, p: SocProfile) -> int:
    ports = list_mtk()
    if not ports:
        print("MTK ポートなし", file=sys.stderr)
        return 2
    for info in ports:
        print("  " + str(info))

    pre = wait_pid(PRELOADER_PIDS, args.wait)
    if pre is None:
        print("preloader 未検出。BROM 待機に入ります...")
        brom = wait_pid(BROM_PIDS, args.brom_timeout)
        if brom:
            print(f"既に BROM: {brom}")
            return 0
        print("タイムアウト", file=sys.stderr)
        return 2

    kind, detail = classify(pre, p)
    print(f"判定: {kind} ({detail})")
    if kind == "brom":
        print("既に BROM です")
        return 0

    return Forge(p, args).run()


# =============================================================================
# CLI
# =============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="MTK preloader -> BROM 強制移行ツール v4",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--soc", choices=sorted(PROFILES), default="mt8167")
    p.add_argument("--port", default=None)
    p.add_argument("--wait", type=float, default=6.0)
    p.add_argument("--brom-timeout", type=float, default=BROM_WAIT_SEC)
    p.add_argument("--cooldown", type=float, default=COOLDOWN_SEC)
    p.add_argument("--only", default=None, help="P1,M2 のように絞り込み")
    p.add_argument("--max-attempts", type=int, default=0)
    p.add_argument("--stub", type=lambda s: int(s, 0), default=None,
                   help="STUB アドレス上書き")
    p.add_argument("--snapshot-before", action="store_true")
    p.add_argument("--log", default="mtk_brom_forge.log")
    p.add_argument("--json", default=None, help="履歴 JSON 出力先")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("forge")
    sub.add_parser("snapshot")

    a = sub.add_parser("analyze")
    a.add_argument("--span", type=lambda s: int(s, 0), default=0x4000)

    r = sub.add_parser("read")
    r.add_argument("addr", type=lambda s: int(s, 0))
    r.add_argument("count", type=lambda s: int(s, 0))

    w = sub.add_parser("write")
    w.add_argument("addr", type=lambda s: int(s, 0))
    w.add_argument("values", type=lambda s: int(s, 0), nargs="+")
    w.add_argument("--no-verify", action="store_true")

    d = sub.add_parser("dump")
    d.add_argument("addr", type=lambda s: int(s, 0))
    d.add_argument("count", type=lambda s: int(s, 0))
    d.add_argument("out")

    sub.add_parser("plan")
    return p


def main(argv=None) -> int:
    global LOG
    args = build_parser().parse_args(argv)
    profile = PROFILES[args.soc]
    if args.stub is not None:
        object.__setattr__(profile, "stub_addr", args.stub)

    LOG = Log(args.log)
    try:
        if not HAS_SERIAL:
            print("pip install pyserial", file=sys.stderr)
            return 2
        cmd = args.cmd or "forge"
        table = {
            "forge": cmd_forge,
            "snapshot": cmd_snapshot,
            "analyze": cmd_analyze,
            "read": cmd_read,
            "write": cmd_write,
            "dump": cmd_dump,
            "plan": cmd_plan,
        }
        rc = table[cmd](args, profile)
        if args.json:
            hist = getattr(getattr(args, "_forge", None), "history", None)
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump([asdict(h) for h in (hist or [])], f, ensure_ascii=False, indent=2)
        return rc
    except KeyboardInterrupt:
        print("\n中断")
        return 130
    finally:
        LOG.close()


if __name__ == "__main__":
    sys.exit(main())
