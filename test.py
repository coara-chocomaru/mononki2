#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mtk_preloader_brom_forcer.py
============================================================
MT81367 / MT8135 系 preloader から BROM(0x0e8d:0x2000) へ強制移行するツール。

前提:
  * 解析対象 preloader は BROM 互換 USBDL を実装している
    (0x1618 のディスパッチャ: 0xD0=READ16, 0xD2=WRITE16, 0xD4=WRITE32,
     0xD5=JUMP_TO_BROM, 0xD7=BLOCK+SHA/CHKSUM, 0xD8=STATUS,
     0xFC=ENTRY候補, 0xFD=BROMベース, 0xFE=PING)
  * ブートモードは RTC PDN1 下位6bit (0x1C28 / 0x24AC / 0x3034 から逆算)

使い方の例:
  python mtk_preloader_brom_forcer.py --list-routes
  python mtk_preloader_brom_forcer.py --method auto
  python mtk_preloader_brom_forcer.py --method jump-brom --brom-addr 0x08001000
  python mtk_preloader_brom_forcer.py --method da-payload --addr 0x00100000
  python mtk_preloader_brom_forcer.py --method bootmode-factory
  python mtk_preloader_brom_forcer.py --method all --timeout 25
============================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    print("pyserial が必要です: pip install pyserial", file=sys.stderr)
    raise

LOG = logging.getLogger("brom4cer")

# ----------------------------------------------------------------------------
# 定数
# ----------------------------------------------------------------------------

VID_MTK = 0x0E8D

# PID 分類（0x2000 は BROM と preloader-usbdl の両方が使う＝曖昧）
PID_TABLE = {
    0x0003: ("preloader-vcom-legacy", "preloader"),
    0x2000: ("brom-or-preloader-usbdl", "ambiguous"),
    0x2001: ("preloader-usbdl", "preloader"),
    0x2003: ("preloader-vcom", "preloader"),
    0x2007: ("meta", "meta"),
    0x2008: ("da", "da"),
    0x2009: ("da-alt", "da"),
    0x201C: ("ate-factory", "factory"),
    0x201D: ("ate-factory-alt", "factory"),
    0x0E8D: ("mtk-unknown", "unknown"),
}

HS_MAGIC = 0xA0
HS_REPLY = 0x5F

# コマンド（この preloader のディスパッチャに実在するもののみ）
CMD_READ16 = 0xD0
CMD_READ16_ALT = 0xA2
CMD_WRITE16 = 0xD2
CMD_WRITE16_ALT = 0xA1
CMD_WRITE32 = 0xD4
CMD_JUMP_TO_BROM = 0xD5
CMD_BLOCK = 0xD7
CMD_STATUS = 0xD8
CMD_PING = 0xDB
CMD_DBL32 = 0xC4
CMD_CMP = 0xC7
CMD_ENTRY_TABLE = 0xFC
CMD_BROM_BASE = 0xFD
CMD_PING2 = 0xFE

# 既定レジスタ
DEF_RTC_BASE = 0x10003000
RTC_BBPU_OFS = 0x08
RTC_PDN1_OFS = 0x1C
RTC_KEY = 0x43000000
DEF_WDT_SWRST = 0x10007014
DEF_BROM_BASE = 0x08000000
DEF_SRAM = 0x00100000

BOOTMODE = {"normal": 0, "meta": 1, "recovery": 2, "factory": 4, "advmeta": 5, "ate": 6}

ERR_DA = 0x2001
ERR_CHECKSUM = 0x2003


# ----------------------------------------------------------------------------
# 例外
# ----------------------------------------------------------------------------

class MtkError(Exception):
    pass


class HandshakeError(MtkError):
    pass


class ProtocolError(MtkError):
    pass


# ----------------------------------------------------------------------------
# ポート列挙
# ----------------------------------------------------------------------------

@dataclass
class PortInfo:
    device: str
    vid: Optional[int]
    pid: Optional[int]
    serial: Optional[str]
    desc: str

    @property
    def kind(self) -> str:
        if self.pid in PID_TABLE:
            return PID_TABLE[self.pid][1]
        return "unknown"

    def pretty(self) -> str:
        name = PID_TABLE.get(self.pid, ("?", "?"))[0] if self.pid else "no-pid"
        return f"{self.device}  {self.vid:04x}:{self.pid:04x}  [{name}]  {self.desc}"


def enumerate_mtk() -> List[PortInfo]:
    out: List[PortInfo] = []
    for p in list_ports.comports():
        if p.vid == VID_MTK:
            out.append(PortInfo(p.device, p.vid, p.pid, p.serial_number, p.description or ""))
    return out


def find_port(pid: Optional[int] = None, timeout: float = 0.0) -> Optional[PortInfo]:
    deadline = time.time() + timeout
    while True:
        for info in enumerate_mtk():
            if pid is None or info.pid == pid:
                return info
        if time.time() >= deadline:
            return None
        time.sleep(0.25)


# ----------------------------------------------------------------------------
# シリアルラッパ
# ----------------------------------------------------------------------------

class MtkLink:
    """preloader/BROM の usbdl と喋る薄いラッパ。"""

    def __init__(self, port: str, baud: int = 115200, timeout: float = 1.0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.ser: Optional[serial.Serial] = None
        self.brom_base: Optional[int] = None
        self.entry_candidates: List[int] = []
        self.status_flags: Optional[int] = None
        self.is_brom = False

    # -- 低レベル ---------------------------------------------------------

    def open(self) -> None:
        self.ser = serial.Serial(
            self.port, self.baud,
            bytesize=8, parity="N", stopbits=1,
            timeout=self.timeout, write_timeout=self.timeout,
        )
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def close(self) -> None:
        if self.ser:
            try:
                self.ser.close()
            finally:
                self.ser = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def _write(self, data: bytes) -> None:
        if not self.ser:
            raise ProtocolError("port closed")
        self.ser.write(data)
        self.ser.flush()

    def _read(self, n: int, timeout: Optional[float] = None) -> bytes:
        if not self.ser:
            raise ProtocolError("port closed")
        old = self.ser.timeout
        if timeout is not None:
            self.ser.timeout = timeout
        try:
            buf = b""
            deadline = time.time() + (timeout if timeout is not None else self.timeout)
            while len(buf) < n:
                chunk = self.ser.read(n - len(buf))
                if not chunk:
                    if time.time() >= deadline:
                        break
                    continue
                buf += chunk
            return buf
        finally:
            self.ser.timeout = old

    def _expect(self, n: int, what: str, timeout: Optional[float] = None) -> bytes:
        data = self._read(n, timeout)
        if len(data) != n:
            raise ProtocolError(f"{what}: {n} バイト期待 / {len(data)} バイト受信 ({data.hex()})")
        return data

    def _cmd(self, opcode: int, payload: bytes = b"", read: int = 0,
             timeout: Optional[float] = None) -> bytes:
        self._write(bytes([opcode]) + payload)
        if read:
            return self._expect(read, f"cmd 0x{opcode:02x}", timeout)
        return b""

    # -- ハンドシェイク ---------------------------------------------------

    def handshake(self, retries: int = 3) -> None:
        last = ""
        for i in range(retries):
            try:
                self.ser.reset_input_buffer()
                self._write(bytes([HS_MAGIC]))
                reply = self._read(1, timeout=0.6)
                if not reply:
                    last = "無応答"
                    continue
                if reply[0] not in (HS_REPLY, 0x0A, 0x5F):
                    last = f"不正応答 0x{reply[0]:02x}"
                    continue
                self._write(bytes([reply[0]]))
                time.sleep(0.05)
                return
            except (serial.SerialException, ProtocolError) as e:
                last = str(e)
                time.sleep(0.3)
        raise HandshakeError(f"ハンドシェイク失敗 ({last})")

    # -- プリミティブ -----------------------------------------------------

    def status(self) -> int:
        """0xD8: 3 ビットのステータス。"""
        raw = self._cmd(CMD_STATUS, read=1, timeout=0.8)
        self.status_flags = raw[0]
        return raw[0]

    def brom_base_query(self) -> Optional[int]:
        raw = self._cmd(CMD_BROM_BASE, read=4, timeout=0.8)
        self.brom_base = struct.unpack("<I", raw)[0]
        return self.brom_base

    def entry_table(self) -> List[int]:
        """0xFC: halfword 3 個のエントリ候補。"""
        raw = self._cmd(CMD_ENTRY_TABLE, read=6, timeout=0.8)
        self.entry_candidates = list(struct.unpack("<HHH", raw))
        return self.entry_candidates

    def read16(self, addr: int, count: int, alt: bool = False) -> List[int]:
        op = CMD_READ16_ALT if alt else CMD_READ16
        self._write(bytes([op]) + struct.pack("<II", addr, count))
        e_addr, e_len = struct.unpack("<II", self._expect(8, "read16 echo"))
        if e_addr != addr or e_len != count:
            raise ProtocolError(f"read16 エコー不一致 addr={e_addr:#x} len={e_len}")
        data = struct.unpack(f"<{count}H", self._expect(count * 2, "read16 data"))
        st = struct.unpack("<H", self._expect(2, "read16 status"))[0]
        if st:
            raise ProtocolError(f"read16 ステータス 0x{st:04x}")
        return list(data)

    def read32(self, addr: int, count: int = 1) -> List[int]:
        """READ16 を 32bit 単位で束ねる。"""
        words = self.read16(addr, count * 2)
        return [(words[i * 2] | (words[i * 2 + 1] << 16)) for i in range(count)]

    def write16(self, addr: int, words: List[int], alt: bool = False) -> None:
        op = CMD_WRITE16_ALT if alt else CMD_WRITE16
        self._write(bytes([op]) + struct.pack("<II", addr, len(words)))
        self._expect(8, "write16 echo")
        for w in words:
            self._write(struct.pack("<H", w & 0xFFFF))
            self._expect(2, "write16 ack")
        st = struct.unpack("<H", self._expect(2, "write16 status"))[0]
        if st:
            raise ProtocolError(f"write16 ステータス 0x{st:04x}")

    def write32(self, addr: int, words: List[int]) -> None:
        if addr & 3:
            raise ProtocolError("write32 は 4 バイト整列が必要")
        self._write(bytes([CMD_WRITE32]) + struct.pack("<II", addr, len(words)))
        self._expect(8, "write32 echo")
        for w in words:
            self._write(struct.pack("<I", w & 0xFFFFFFFF))
            self._expect(4, "write32 ack")
        st = struct.unpack("<H", self._expect(2, "write32 status"))[0]
        if st:
            raise ProtocolError(f"write32 ステータス 0x{st:04x}")

    def set32(self, addr: int, value: int) -> None:
        self.write32(addr, [value])

    def jump_to_brom(self, addr: int) -> int:
        """0xD5: JUMP_TO_BROM。返り値はステータス語。"""
        raw = self._cmd(CMD_JUMP_TO_BROM, struct.pack("<I", addr), read=6, timeout=1.5)
        echoed, st = struct.unpack("<IH", raw)
        if echoed != addr:
            raise ProtocolError(f"jump エコー不一致 {echoed:#x} != {addr:#x}")
        return st

    @staticmethod
    def _chksum(data: bytes) -> int:
        """0x1802 の実装に合わせた halfword XOR（奇数長は末尾バイトも XOR）。"""
        ck = 0
        n = len(data) & ~1
        for i in range(0, n, 2):
            ck ^= data[i] | (data[i + 1] << 8)
        if len(data) & 1:
            ck ^= data[-1]
        return ck & 0xFFFF

    def block_transfer(self, addr: int, data: bytes, sig_len: int = 0) -> int:
        """0xD7: ブロック受信＋チェックサム検証＋書き込み。"""
        if not data:
            raise ProtocolError("空ブロック")
        self._write(bytes([CMD_BLOCK]) + struct.pack("<III", addr, len(data), sig_len))
        self._expect(12, "block echo")
        ack = self._expect(2, "block ack")
        if ack != b"\x00\x00":
            raise ProtocolError(f"block ack 異常 {ack.hex()}")
        self._write(data)
        echoed = struct.unpack("<H", self._expect(2, "block chksum"))[0]
        mine = self._chksum(data)
        if echoed != mine:
            raise ProtocolError(f"チェックサム不一致 dev=0x{echoed:04x} host=0x{mine:04x}")
        st = struct.unpack("<H", self._expect(2, "block status", timeout=3.0))[0]
        return st

    def jump_raw(self, addr: int) -> None:
        self._write(bytes([CMD_JUMP_TO_BROM]) + struct.pack("<I", addr))
        self._read(6, timeout=0.5)


# ----------------------------------------------------------------------------
# ペイロード生成（Thumb-2 / Cortex-A7）
# ----------------------------------------------------------------------------

def _movw(rd: int, imm16: int) -> bytes:
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    return struct.pack("<HH", 0xF240 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)


def _movt(rd: int, imm16: int) -> bytes:
    imm4 = (imm16 >> 12) & 0xF
    i = (imm16 >> 11) & 1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    return struct.pack("<HH", 0xF2C0 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)


def _mov32(rd: int, value: int) -> bytes:
    return _movw(rd, value & 0xFFFF) + _movt(rd, (value >> 16) & 0xFFFF)


STR = lambda rt, rn: struct.pack("<H", 0x6000 | ((rn & 7) << 3) | (rt & 7))
LDR = lambda rt, rn: struct.pack("<H", 0x6800 | ((rn & 7) << 3) | (rt & 7))
MOVS = lambda rd, imm8: struct.pack("<H", 0x2000 | ((rd & 7) << 8) | (imm8 & 0xFF))
ANDS = lambda rdn, rm: struct.pack("<H", 0x4000 | ((rm & 7) << 3) | (rdn & 7))
ORRS = lambda rdn, rm: struct.pack("<H", 0x4300 | ((rm & 7) << 3) | (rdn & 7))
B_SELF = b"\xFE\xE7"
NOP16 = b"\x00\xBF"


def build_payload(boot_mode: int, rtc_base: int, wdt_swrst: int) -> bytes:
    """
    RTC PDN1 の下位 6bit を boot_mode に書き換え、WDT_SWRST で即リセットする。
    r4=key / r6=BBPU / r7=PDN1 / r5=WDT_SWRST
    """
    code = b"".join([
        _mov32(4, RTC_KEY),
        _mov32(6, rtc_base + RTC_BBPU_OFS),
        _mov32(7, rtc_base + RTC_PDN1_OFS),
        _mov32(5, wdt_swrst),
        STR(4, 6),                       # RTC アンロック
        LDR(0, 7),                       # PDN1 読み出し
        _mov32(1, 0xFFFFFFC0),
        ANDS(0, 1),
        MOVS(1, boot_mode),
        ORRS(0, 1),
        STR(0, 7),                       # モード書き込み
        STR(4, 6),                       # RTC ロック
        MOVS(0, 1),
        STR(0, 5),                       # WDT_SWRST
        B_SELF,
    ])
    if len(code) & 3:
        code += NOP16 * (2 if (len(code) & 3) == 2 else 0)
    return code


# ----------------------------------------------------------------------------
# ルート定義
# ----------------------------------------------------------------------------

@dataclass
class Route:
    rid: str
    desc: str
    needs_brom_cmd: bool
    fn: Callable[["Runner"], bool]
    resets: bool = True


@dataclass
class Result:
    rid: str
    ok: bool
    detail: str = ""
    elapsed: float = 0.0


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.link: Optional[MtkLink] = None
        self.results: List[Result] = []

    # -- 接続管理 ---------------------------------------------------------

    def attach(self, pid: Optional[int] = None, timeout: float = 0.0) -> MtkLink:
        info = find_port(pid, timeout)
        if info is None:
            raise MtkError("対象ポートが見つかりません")
        LOG.info("接続: %s", info.pretty())
        link = MtkLink(info.device, timeout=self.args.io_timeout)
        link.open()
        try:
            link.handshake()
        except Exception:
            link.close()
            raise
        self.link = link
        return link

    def detach(self) -> None:
        if self.link:
            self.link.close()
            self.link = None

    def classify(self) -> str:
        """接続先が BROM か preloader かを判定。"""
        link = self.attach(self.args.pid, self.args.timeout)
        verdict = "unknown"
        try:
            try:
                st = link.status()
                LOG.info("status=0x%02x", st)
                verdict = "preloader"
            except MtkError as e:
                LOG.debug("status 不可: %s", e)
            for probe in (CMD_PING2, CMD_PING):
                try:
                    raw = link._cmd(probe, read=1, timeout=0.5)
                    LOG.info("probe 0x%02x -> %s", probe, raw.hex())
                    if probe == CMD_PING2 and raw == b"\x01":
                        verdict = "brom" if link.brom_base_query() else verdict
                except MtkError:
                    pass
            try:
                base = link.brom_base_query()
                if base == DEF_BROM_BASE:
                    LOG.info("BROM ベース確認: %#x", base)
                    verdict = "brom"
            except MtkError:
                pass
        finally:
            self.detach()
        return verdict

    def wait_brom(self, timeout: float) -> bool:
        """0x2000 が再出現し、ハンドシェイクが通るまで待つ。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            info = find_port(0x2000, timeout=min(1.0, max(0.2, deadline - time.time())))
            if info:
                try:
                    link = MtkLink(info.device, timeout=self.args.io_timeout)
                    link.open()
                    try:
                        link.handshake()
                        LOG.info("BROM 復帰を確認 (%s)", info.device)
                        return True
                    finally:
                        link.close()
                except MtkError:
                    pass
            time.sleep(0.3)
        return False

    # -- 個別ルート -------------------------------------------------------

    def r_status(self) -> bool:
        st = self.link.status()
        LOG.info("status flags = 0x%02x", st)
        return True

    def r_entry_table(self) -> bool:
        cands = self.link.entry_table()
        LOG.info("エントリ候補 = %s", [hex(c) for c in cands])
        return True

    def r_brom_base(self) -> bool:
        base = self.link.brom_base_query()
        LOG.info("BROM ベース = %#x", base)
        return True

    def r_jump_resolved(self) -> bool:
        """0xFD ベース + 0xFC 候補を合成して 0xD5。"""
        base = self.link.brom_base_query()
        cands = self.link.entry_table()
        if not cands:
            raise ProtocolError("エントリ候補が空")
        for c in cands:
            target = (base + c) & 0xFFFFFFFF
            LOG.info("JUMP_TO_BROM 試行 -> %#x (base %#x + %#x)", target, base, c)
            try:
                st = self.link.jump_to_brom(target)
            except MtkError as e:
                LOG.warning("  %s", e)
                continue
            LOG.info("  ステータス 0x%04x", st)
            if st == 0:
                return True
        return False

    def r_jump_manual(self) -> bool:
        st = self.link.jump_to_brom(self.args.brom_addr)
        LOG.info("JUMP_TO_BROM(%#x) status=0x%04x", self.args.brom_addr, st)
        return st == 0

    def _bootmode(self, mode: int, label: str) -> bool:
        rtc = self.args.rtc
        pdn1 = rtc + RTC_PDN1_OFS
        self.link.set32(rtc + RTC_BBPU_OFS, RTC_KEY)
        cur = self.link.read32(pdn1)[0]
        LOG.info("%s: PDN1 現在値 %#010x", label, cur)
        new = (cur & 0xFFFFFFC0) | (mode & 0x3F)
        self.link.set32(pdn1, new)
        self.link.set32(rtc + RTC_BBPU_OFS, RTC_KEY)
        LOG.info("%s: PDN1 -> %#010x (mode=%d)", label, new, mode)
        self.link.set32(self.args.wdt, 1)
        LOG.info("%s: WDT_SWRST 発行", label)
        return True

    def r_bootmode_meta(self) -> bool:
        return self._bootmode(BOOTMODE["meta"], "meta")

    def r_bootmode_factory(self) -> bool:
        return self._bootmode(BOOTMODE["factory"], "factory")

    def r_bootmode_ate(self) -> bool:
        return self._bootmode(BOOTMODE["ate"], "ate")

    def r_da_payload(self) -> bool:
        payload = build_payload(self.args.payload_mode, self.args.rtc, self.args.wdt)
        if len(payload) > 0x400:
            raise ProtocolError("ペイロードが大きすぎます")
        LOG.info("ペイロード %d バイト / mode=%d", len(payload), self.args.payload_mode)
        if self.args.dump_payload:
            print(payload.hex())
        addrs = [self.args.addr] + [a for a in (0x00100000, 0x00200000, 0x100000) if a != self.args.addr]
        last = ""
        for addr in addrs:
            try:
                LOG.info("転送先 %#x", addr)
                st = self.link.block_transfer(addr, payload)
                if st:
                    last = f"block status 0x{st:04x}"
                    LOG.warning("  %s", last)
                    continue
                self.link.jump_raw(addr)
                return True
            except MtkError as e:
                last = str(e)
                LOG.warning("  %s", e)
        raise ProtocolError(f"ペイロード全滅: {last}")

    def r_regs_only(self) -> bool:
        """ペイロードを使わず RTC/WDT を write32 で直接叩く。"""
        return self._bootmode(self.args.payload_mode, "regs-only")

    def r_jump0(self) -> bool:
        LOG.info("0x0 へジャンプ（フォールト→WDT→BROM 期待）")
        self.link.jump_raw(0)
        return True

    def r_watchdog(self) -> bool:
        LOG.info("WDT_SWRST のみ")
        self.link.set32(self.args.wdt, 1)
        return True

    def r_reset_only(self) -> bool:
        LOG.info("0xDB ping 後に WDT")
        try:
            self.link._cmd(CMD_PING, read=1, timeout=0.4)
        except MtkError:
            pass
        self.link.set32(self.args.wdt, 1)
        return True

    def r_physical(self) -> bool:
        print("\n--- 物理操作 ---")
        print("1. USB を抜く")
        print("2. 端末を完全に電源断")
        print("3. Vol+ と Vol- を両方押し続ける")
        print("4. 押したまま USB を挿す")
        print("5. デバイスマネージャに 0e8d:2000 が出たら離す")
        return True

    # -- 実行 -------------------------------------------------------------

    def run_route(self, route: Route) -> Result:
        t0 = time.time()
        LOG.info("=== %s : %s ===", route.rid, route.desc)
        if self.args.dry_run:
            return Result(route.rid, True, "dry-run", 0.0)
        try:
            link = self.attach(0x2000, timeout=0.5)
            if route.needs_brom_cmd:
                try:
                    link.status()
                except MtkError:
                    LOG.info("status 不可（続行）")
            ok = route.fn(self)
        except MtkError as e:
            LOG.error("失敗: %s", e)
            self.detach()
            return Result(route.rid, False, str(e), time.time() - t0)
        except serial.SerialException as e:
            self.detach()
            return Result(route.rid, False, f"serial: {e}", time.time() - t0)
        self.detach()
        elapsed = time.time() - t0

        if not ok:
            return Result(route.rid, False, "ルート内で不成立", elapsed)

        if route.resets:
            LOG.info("BROM 復帰待ち (%ss)...", self.args.timeout)
            if self.wait_brom(self.args.timeout):
                return Result(route.rid, True, "BROM 復帰確認", time.time() - t0)
            return Result(route.rid, False, "BROM 復帰せず", time.time() - t0)
        return Result(route.rid, True, "OK", elapsed)


ROUTES: List[Route] = [
    Route("status",         "0xD8 ステータス取得",              True,  Runner.r_status, False),
    Route("entry-table",    "0xFC エントリ候補取得",            True,  Runner.r_entry_table, False),
    Route("brom-base",      "0xFD BROM ベース取得",             True,  Runner.r_brom_base, False),
    Route("jump-resolved",  "0xFD+0xFC 合成 → 0xD5 ジャンプ",   True,  Runner.r_jump_resolved),
    Route("jump-brom",      "0xD5 固定アドレスへジャンプ",      True,  Runner.r_jump_manual),
    Route("da-payload",     "0xD7 ペイロード → 実行 → RTC+WDT", True,  Runner.r_da_payload),
    Route("regs-only",      "RTC/WDT を write32 直叩き",        True,  Runner.r_regs_only),
    Route("bootmode-meta",  "boot mode = META(1) → リセット",   True,  Runner.r_bootmode_meta),
    Route("bootmode-factory","boot mode = FACTORY(4) → リセット", True, Runner.r_bootmode_factory),
    Route("bootmode-ate",   "boot mode = ATE(6) → リセット",    True,  Runner.r_bootmode_ate),
    Route("jump0",          "0x0 へジャンプでフォールト",        True,  Runner.r_jump0),
    Route("watchdog",       "WDT_SWRST のみ",                   True,  Runner.r_watchdog),
    Route("reset-only",     "ping + WDT",                       True,  Runner.r_reset_only),
    Route("physical",       "物理キーコンボ案内",                False, Runner.r_physical, False),
]

ROUTE_MAP: Dict[str, Route] = {r.rid: r for r in ROUTES}

AUTO_ORDER = [
    "status", "entry-table", "brom-base", "jump-resolved",
    "jump-brom", "da-payload", "regs-only",
    "bootmode-meta", "bootmode-factory", "bootmode-ate",
    "jump0", "watchdog", "reset-only", "physical",
]


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="MTK preloader → BROM(0x0e8d:0x2000) 強制移行ツール",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="経路一覧は --list-routes。既定は auto（全経路を順に試行）。",
    )
    p.add_argument("--method", "-m", default="auto",
                   help="auto / all / 個別 ID（カンマ区切り） / list")
    p.add_argument("--list-routes", action="store_true", help="経路一覧を表示")
    p.add_argument("--pid", type=lambda s: int(s, 0), default=None,
                   help="対象 PID を明示（既定 0x2000）")
    p.add_argument("--brom-addr", type=lambda s: int(s, 0), default=DEF_BROM_BASE + 0x1000,
                   help="jump-brom 用アドレス（既定 0x08001000）")
    p.add_argument("--addr", type=lambda s: int(s, 0), default=DEF_SRAM,
                   help="ペイロード配置アドレス（既定 0x00100000）")
    p.add_argument("--payload-mode", type=int, default=BOOTMODE["meta"],
                   help="ペイロードが設定するブートモード（既定 1=META）")
    p.add_argument("--rtc", type=lambda s: int(s, 0), default=DEF_RTC_BASE,
                   help=f"RTC ベース（既定 {DEF_RTC_BASE:#x}）")
    p.add_argument("--wdt", type=lambda s: int(s, 0), default=DEF_WDT_SWRST,
                   help=f"WDT_SWRST アドレス（既定 {DEF_WDT_SWRST:#x}）")
    p.add_argument("--timeout", type=float, default=20.0, help="BROM 復帰待ち秒")
    p.add_argument("--io-timeout", type=float, default=1.5, help="シリアル I/O タイムアウト秒")
    p.add_argument("--retries", type=int, default=2, help="ルート毎の再試行回数")
    p.add_argument("--force", action="store_true", help="既に BROM でも実行")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--dump-payload", action="store_true", help="生成ペイロードの hex を表示")
    p.add_argument("--json", metavar="PATH", help="結果を JSON 保存")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p


def setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stdout)


def print_routes() -> None:
    print("経路一覧:")
    for r in ROUTES:
        print(f"  {r.rid:18s} {r.desc}")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    if args.list_routes or args.method == "list":
        print_routes()
        return 0

    # 対象検出
    ports = enumerate_mtk()
    if not ports:
        print("MTK デバイス (VID 0e8d) が見つかりません。", file=sys.stderr)
        return 2
    print("検出:")
    for p in ports:
        print("  " + p.pretty())
    target_pids = {p.pid for p in ports}
    if 0x2000 not in target_pids and not args.pid:
        print("\n0e8d:2000 が無いため、まず 2000 の出現待ちに入ります。")
        if find_port(0x2000, timeout=args.timeout) is None:
            print("タイムアウト。preloader usbdl か BROM の状態で再実行してください。",
                  file=sys.stderr)
            return 2

    runner = Runner(args)

    # 事前判定
    try:
        verdict = runner.classify()
    except MtkError as e:
        print(f"事前判定に失敗: {e}", file=sys.stderr)
        return 3
    print(f"\n判定: {verdict}")
    if verdict == "brom" and not args.force:
        print("既に BROM です。--force で強行できます。")
        return 0

    # 経路決定
    if args.method == "auto":
        order = [r for r in AUTO_ORDER if r != "physical"]
    elif args.method == "all":
        order = [r.rid for r in ROUTES]
    else:
        order = [s.strip() for s in args.method.split(",") if s.strip()]
        unknown = [s for s in order if s not in ROUTE_MAP]
        if unknown:
            print(f"不明な経路: {unknown}", file=sys.stderr)
            print_routes()
            return 2

    print("\n実行順: " + " → ".join(order) + "\n")
    success: Optional[Result] = None

    for rid in order:
        route = ROUTE_MAP[rid]
        for attempt in range(1, args.retries + 1):
            if args.retries > 1:
                LOG.info("[%s] 試行 %d/%d", rid, attempt, args.retries)
            res = runner.run_route(route)
            runner.results.append(res)
            if res.ok:
                success = res
                break
            if route.rid == "physical":
                break
        if success:
            break

    print("\n===== 結果 =====")
    for r in runner.results:
        print(f"  {'OK ' if r.ok else 'NG '} {r.rid:18s} {r.detail}  ({r.elapsed:.2f}s)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in runner.results], f, ensure_ascii=False, indent=2)
        print(f"\nJSON 保存: {args.json}")

    if success:
        print(f"\n成功: {success.rid} — BROM (0e8d:2000) に移行済み。")
        return 0

    print("\n全経路失敗。--method physical の手順を実施してください。")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n中断", file=sys.stderr)
        sys.exit(130)
