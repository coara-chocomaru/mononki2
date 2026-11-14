#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preloader_a04br3 (MT8167) -> BROM (0e8d:0003) escape tool
復元プロトコル: [cmd][echo cmd][u16 status][params...]  status 0x0000=OK
エラー: 0x2001=未ロード/検証NG, 0x2003=ヘッダ不正, 0x2006=サイズ超過
"""
import os, sys, time, struct, argparse, glob, subprocess

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    sys.exit("pip install pyserial")

VID_PRE = 0x0E8D
PID_PRE = 0x2000
PID_BROM = 0x0003

SYNC_TOKEN = b"PRELOADER"

CMD_ECHO_A   = 0xC4
CMD_ECHO_B   = 0xC5
CMD_WR16     = 0xC7
CMD_RD16     = 0xA1
CMD_RD16_E   = 0xA2
CMD_RD32     = 0xD1
CMD_RD32_CHK = 0xD4
CMD_JUMP     = 0xD5
CMD_SEND_DA  = 0xD7
CMD_CONN     = 0xD8
CMD_NOOP     = 0xDB
CMD_INFO1    = 0xFC
CMD_INFO2    = 0xFD

ST_OK   = 0x0000
ST_NOLOAD = 0x2001
ST_VERIFY = 0x2003
ST_SIZE   = 0x2006

BROM_LO, BROM_HI = 0x00000000, 0x00020000
SRAM_LO, SRAM_HI = 0x00100000, 0x00180000
BROM_API_MAGIC   = b"BRLYT"
DEFAULT_DA_ADDR  = 0x00230000


# ----------------------------------------------------------------------------
# USB デバイス探索
# ----------------------------------------------------------------------------
def find_ports(vid, pid):
    out = []
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Enum\USB")
            for i in range(winreg.QueryInfoKey(key)[0]):
                name = winreg.EnumKey(key, i)
                if f"VID_{vid:04X}&PID_{pid:04X}" in name.upper():
                    k2 = winreg.OpenKey(key, name)
                    for j in range(winreg.QueryInfoKey(k2)[0]):
                        inst = winreg.EnumKey(k2, j)
                        k3 = winreg.OpenKey(k2, inst)
                        try:
                            p = winreg.QueryValueEx(k3, "PortName")[0]
                            out.append("\\\\.\\" + p)
                        except OSError:
                            pass
        except Exception:
            pass
        return out

    for p in list_ports.comports():
        if p.vid == vid and p.pid == pid and p.device:
            out.append(p.device)

    base = "/sys/bus/usb/devices"
    if os.path.isdir(base):
        for d in glob.glob(base + "/*"):
            try:
                v = open(d + "/idVendor").read().strip()
                p_ = open(d + "/idProduct").read().strip()
            except OSError:
                continue
            if int(v, 16) != vid or int(p_, 16) != pid:
                continue
            for t in glob.glob(d + "/*/tty*") + glob.glob(d + "/tty*"):
                dev = "/dev/" + os.path.basename(t)
                if os.path.exists(dev) and dev not in out:
                    out.append(dev)
    return out


def wait_port(vid, pid, timeout=40.0, prefer=None):
    end = time.time() + timeout
    while time.time() < end:
        cand = find_ports(vid, pid)
        if prefer and prefer in cand:
            return prefer
        if cand:
            return cand[0]
        time.sleep(0.25)
    return None


# ----------------------------------------------------------------------------
# プロトコル
# ----------------------------------------------------------------------------
class Proto:
    def __init__(self, port, baud=115200, echo=True, verbose=True):
        self.port = port
        self.baud = baud
        self.echo = echo
        self.v = verbose
        self.s = None

    def log(self, *a):
        if self.v:
            print("[*]", *a)

    def open(self):
        self.s = serial.Serial(self.port, self.baud, timeout=0.6,
                               write_timeout=5, exclusive=True)
        try:
            self.s.dtr = True
            self.s.rts = True
        except Exception:
            pass
        self.s.reset_input_buffer()

    def close(self):
        if self.s and self.s.is_open:
            self.s.close()

    # -- 低レベル --------------------------------------------------------
    def put(self, data):
        self.s.write(data)
        self.s.flush()

    def get(self, n, timeout=None):
        if timeout is not None:
            self.s.timeout = timeout
        buf = b""
        while len(buf) < n:
            c = self.s.read(n - len(buf))
            if not c:
                break
            buf += c
        return buf

    def get_exact(self, n, timeout=8.0):
        return self.get(n, timeout)

    def drain(self, t=0.05):
        self.s.timeout = t
        try:
            while self.s.read(4096):
                pass
        finally:
            self.s.timeout = 0.6

    # -- 同期 ------------------------------------------------------------
    def sync(self, rounds=6):
        for i in range(rounds):
            self.put(SYNC_TOKEN + bytes([CMD_ECHO_A, CMD_NOOP]))
            time.sleep(0.02)
            self.drain(0.05)
        self.log("sync done")

    # -- トランザクション ------------------------------------------------
    def xact(self, cmd, payload=b"", rd_echo=True, rd_status=True, timeout=1.5):
        if self.echo:
            self.put(bytes([cmd]))
        else:
            self.put(bytes([0xFE, cmd]))
        if rd_echo:
            e = self.get(1, timeout)
            if not e:
                raise IOError(f"cmd 0x{cmd:02X}: echo timeout")
            if e[0] != cmd:
                raise IOError(f"cmd 0x{cmd:02X}: echo mismatch 0x{e[0]:02X}")
        if payload:
            self.put(payload)
        if not rd_status:
            return None
        st = self.get(2, timeout)
        if len(st) < 2:
            raise IOError(f"cmd 0x{cmd:02X}: status timeout")
        return struct.unpack("<H", st)[0]

    # -- レジスタ読み ----------------------------------------------------
    def read32(self, addr, count=1, checked=True):
        cmd = CMD_RD32_CHK if checked else CMD_RD32
        st = self.xact(cmd, struct.pack("<II", addr, count), rd_status=True)
        if st != ST_OK:
            raise IOError(f"read32 0x{addr:08X}: status 0x{st:04X}")
        out = []
        for _ in range(count):
            d = self.get_exact(4, 3.0)
            if len(d) < 4:
                raise IOError("read32 data short")
            out.append(struct.unpack("<I", d)[0])
        st2 = struct.unpack("<H", self.get(2, 2.0) or b"\xff\xff")[0]
        if st2 != ST_OK:
            raise IOError(f"read32 tail 0x{st2:04X}")
        return out

    def read32_one(self, addr):
        return self.read32(addr, 1, checked=True)[0]

    def read16(self, addr, count=1, echo=False):
        cmd = CMD_RD16_E if echo else CMD_RD16
        st = self.xact(cmd, struct.pack("<II", addr, count))
        if st != ST_OK:
            raise IOError(f"read16 0x{addr:08X}: 0x{st:04X}")
        out = []
        for _ in range(count):
            d = self.get_exact(2, 3.0)
            out.append(struct.unpack("<H", d)[0])
        return out

    def write16(self, addr, value):
        st = self.xact(CMD_WR16, struct.pack("<HH", addr & 0xFFFF, value & 0xFFFF))
        echo = self.get(2, 1.5)
        return st, (struct.unpack("<H", echo)[0] if len(echo) == 2 else None)

    def conn_state(self):
        st = self.xact(CMD_CONN)
        d = self.get_exact(4, 2.0)
        return st, (struct.unpack("<I", d)[0] if len(d) == 4 else None)

    # -- 0xD7: DA 送出 ---------------------------------------------------
    def send_da(self, addr, blob, sig=b"", chunk=0x8000):
        total = len(blob) + len(sig)
        if total > 0x40000:
            raise ValueError("blob too large (max 0x40000)")
        st = self.xact(CMD_SEND_DA, struct.pack("<III", addr, total, len(sig)))
        if st != ST_OK:
            raise IOError(f"send_da header status 0x{st:04X}")
        # デバイス側が XOR16 を返す → 一致しなければ即中断
        for off in range(0, total, chunk):
            self.put((blob + sig)[off:off + chunk])
        cs = 0
        buf = blob + sig
        for i in range(0, len(buf) - 1, 2):
            cs ^= struct.unpack("<H", buf[i:i + 2])[0]
        if len(buf) & 1:
            cs ^= buf[-1]
        dev_cs = struct.unpack("<H", self.get_exact(2, 8.0))[0]
        if dev_cs != cs:
            raise IOError(f"checksum mismatch dev=0x{dev_cs:04X} local=0x{cs:04X}")
        self.log(f"checksum ok 0x{cs:04X}")
        st = struct.unpack("<H", self.get_exact(2, 10.0))[0]
        if st != ST_OK:
            raise IOError(f"send_da verify status 0x{st:04X} "
                          f"({ {ST_NOLOAD:'noload', ST_VERIFY:'verify', ST_SIZE:'size'}.get(st,'?') })")
        return True

    # -- 0xD5: 実行トリガ ------------------------------------------------
    def jump(self, addr=0):
        st = self.xact(CMD_JUMP, struct.pack("<I", addr))
        return st


# ----------------------------------------------------------------------------
# BROM API 探索（経路 C）
# ----------------------------------------------------------------------------
def scan_brom_api(pr, step=0x200, progress=True):
    """SRAM を 'BRLYT' で走査して BROM API 構造体を探す"""
    hits = []
    addr = SRAM_LO
    while addr < SRAM_HI:
        try:
            v = pr.read32(addr, 2, checked=False)
        except IOError:
            addr += step
            continue
        if struct.pack("<I", v[0]) == BROM_API_MAGIC:
            hits.append(addr)
            if progress:
                print(f"[+] brom_api candidate @ 0x{addr:08X}")
        addr += step
    return hits


def brom_entries_from_api(pr, api):
    """BROM API から BROM 内アドレスを抽出（+0x04 = usb_handshake）"""
    vals = pr.read32(api, 12, checked=False)
    ents = [v for v in vals if BROM_LO <= v < BROM_HI]
    return vals, ents


# ----------------------------------------------------------------------------
# スタブ生成（経路 A）
# ----------------------------------------------------------------------------
def build_stub(target):
    """
    MMU/D-cache を落として target へ分岐する位置独立スタブ
      mrc p15,0,r0,c1,c0,0
      bic.w r0,r0,#5
      mcr p15,0,r0,c1,c0,0
      movs r0,#0
      mcr p15,0,r0,c8,c7,0     ; TLB 全破棄
      mcr p15,0,r0,c7,c5,0     ; ICIALLU
      dsb / isb
      nop
      ldr r0,[pc,#0]
      bx r0
      .word target
    """
    c = bytearray()
    c += bytes([0x10, 0x0F, 0x11, 0xEE])  # mrc p15,0,r0,c1,c0,0
    c += bytes([0x20, 0xF0, 0x05, 0x00])  # bic.w r0,r0,#5
    c += bytes([0x10, 0x0F, 0x01, 0xEE])  # mcr p15,0,r0,c1,c0,0
    c += bytes([0x00, 0x20])              # movs r0,#0
    c += bytes([0x17, 0x0F, 0x08, 0xEE])  # mcr p15,0,r0,c8,c7,0
    c += bytes([0x95, 0x0F, 0x07, 0xEE])  # mcr p15,0,r0,c7,c5,0
    c += bytes([0x4F, 0x8F, 0xBF, 0xF3])  # dsb
    c += bytes([0x6F, 0x8F, 0xBF, 0xF3])  # isb
    c += bytes([0x00, 0x00])              # nop (整列)
    assert len(c) == 32
    c += bytes([0x00, 0x48])              # ldr r0,[pc,#0]
    c += bytes([0x00, 0x47])              # bx r0
    c += struct.pack("<I", target)
    return bytes(c)


# ----------------------------------------------------------------------------
# BROM 側ハンドシェイク
# ----------------------------------------------------------------------------
def brom_handshake(port, timeout=5.0):
    s = serial.Serial(port, 115200, timeout=timeout, exclusive=True)
    try:
        s.reset_input_buffer()
        s.write(bytes([0xA0, 0x0A, 0x50, 0x05]))
        s.flush()
        r = s.read(4)
        if r == bytes([0x5F, 0xF5, 0xAF, 0xFA]):
            return True, s
        return False, s
    except Exception as e:
        print("[!] brom handshake error:", e)
        return False, s


def brom_read_chip(port):
    """0xD8 get_target_config: hw_code/hw_sub/hw_ver/sw_ver"""
    s = serial.Serial(port, 115200, timeout=3, exclusive=True)
    try:
        s.write(bytes([0xD8]))
        r = s.read(1)
        if r != bytes([0xD8]):
            return None
        s.write(bytes([0xFE]))
        d = s.read(8)
        if len(d) < 8:
            return None
        return struct.unpack("<HHHH", d)
    finally:
        s.close()


# ----------------------------------------------------------------------------
# 本体
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="preloader -> BROM escape (MT8167)")
    ap.add_argument("-p", "--port", default=None)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--route", choices=["auto", "jump", "meta", "stub", "phy", "wdt"],
                    default="auto")
    ap.add_argument("--da-addr", type=lambda x: int(x, 0), default=DEFAULT_DA_ADDR)
    ap.add_argument("--target", type=lambda x: int(x, 0), default=None,
                    help="ジャンプ先 (既定: 自動探索)")
    ap.add_argument("--flag-addr", type=lambda x: int(x, 0), default=None,
                    help="ジャンプ可フラグ byte の実アドレス")
    ap.add_argument("--no-sync", action="store_true")
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    print("=== preloader_a04br3 / MT8167 escape ===")

    port = args.port or wait_port(VID_PRE, PID_PRE, args.timeout)
    if not port:
        sys.exit("[!] 0e8d:2000 が見つかりません（BROM 直結なら 0e8d:0003 を確認）")
    print(f"[+] preloader port: {port}")

    pr = Proto(port, args.baud, echo=True, verbose=True)
    pr.open()
    try:
        if not args.no_sync:
            pr.sync()

        # ---- 偵察 ------------------------------------------------------
        try:
            st, bits = pr.conn_state()
            print(f"[+] 0xD8 status=0x{st:04X} bits=0x{bits:08X}")
        except Exception as e:
            print("[!] 0xD8 失敗:", e)

        for c in (CMD_INFO1, CMD_INFO2):
            try:
                st = pr.xact(c, rd_status=False)
                print(f"[+] 0x{c:02X} info = {pr.get_exact(2, 1.0).hex()}")
            except Exception:
                pass

        # BROM API 探索（経路 C の核）
        target = args.target
        api_hits = []
        if args.route in ("auto", "meta", "stub", "jump"):
            try:
                api_hits = scan_brom_api(pr)
            except Exception as e:
                print("[!] scan 失敗:", e)
        if api_hits and not target:
            vals, ents = brom_entries_from_api(pr, api_hits[0])
            print(f"[+] brom_api[0:12] = {[hex(v) for v in vals]}")
            if ents:
                target = ents[0]
                print(f"[+] ジャンプ先候補 = 0x{target:08X} (brom_api+0x04)")
        if not target:
            target = 0x00200200  # preloader ベクタ（BROM 未検出時の保険）
            print(f"[*] ジャンプ先を既定値 0x{target:08X} に設定")

        # ---- フラグ設定（0xD5 の 0x2001 回避） -------------------------
        if args.flag_addr:
            st, echo = pr.write16(args.flag_addr, 1)
            print(f"[+] flag 0x{args.flag_addr:08X} <- 1 (status 0x{st:04X})")

        def try_jump(addr, label):
            print(f"[*] 経路 {label}: 0xD5(0x{addr:08X})")
            try:
                st = pr.jump(addr)
            except Exception as e:
                print("    → 応答なし（再列挙の可能性）:", e)
                return True
            print(f"    → status 0x{st:04X}")
            if st == ST_OK:
                return True
            if st == ST_NOLOAD:
                print("    → 0x2001: DA 未ロード。スタブ経路へ")
            return False

        def wait_brom(t=25.0):
            p = wait_port(VID_PRE, PID_BROM, t)
            if p:
                print(f"[+] BROM 再列挙成功: {p}")
                return p
            return None

        ok = False
        brom_port = None

        if args.route in ("auto", "jump", "meta"):
            if try_jump(target, "B/jump"):
                brom_port = wait_brom(8.0)
                ok = brom_port is not None
            if not ok and api_hits:
                for ent in brom_entries_from_api(pr, api_hits[0])[1]:
                    if try_jump(ent, f"jump/0x{ent:X}"):
                        brom_port = wait_brom(6.0)
                        ok = brom_port is not None
                        if ok:
                            break

        if not ok and args.route in ("auto", "stub"):
            print(f"[*] 経路 A: スタブ注入 → 0x{target:08X}")
            stub = build_stub(target)
            print(f"    stub {len(stub)} bytes @ 0x{args.da_addr:08X}")
            pr.send_da(args.da_addr, stub, sig=b"")
            st = pr.jump(args.da_addr)
            print(f"    0xD5 -> 0x{st:04X}")
            brom_port = wait_brom(25.0)
            ok = brom_port is not None

        if not ok and args.route in ("auto", "phy"):
            print("[*] 経路 D: USB PHY 再アタッチ")
            try:
                for reg, bit in ((0x03000200, 0x01000000), (0x03000200, 0x00010000)):
                    cur = pr.read32_one(reg)
                    pr.xact(CMD_NOOP)
                    # write16 経路で落とす/上げる
                    pr.write16(reg, cur & ~bit & 0xFFFF)
                    time.sleep(0.05)
                    pr.write16(reg, cur & 0xFFFF)
                brom_port = wait_brom(15.0)
                ok = brom_port is not None
            except Exception as e:
                print("    PHY 失敗:", e)

        if not ok and args.route in ("auto", "wdt"):
            print("[*] 経路 E: WDT リセット")
            try:
                pr.write16(0x10007008 & 0xFFFF, 0x1971)
            except Exception as e:
                print("    WDT 失敗:", e)
            brom_port = wait_port(VID_PRE, PID_BROM, 20.0)

        if not brom_port:
            print("[-] 失敗。preloader 側で再同期して再試行してください")
            try:
                pr.sync()
            except Exception:
                pass
            return 1

        print("[+] BROM に到達。ハンドシェイク開始")
        hs, bs = brom_handshake(brom_port)
        bs.close()
        if not hs:
            print("[!] BROM ハンドシェイク不成立（0x0E8D:0x0003 か確認）")
            return 2
        print("[+] BROM handshake OK (5F F5 AF FA)")
        chip = brom_read_chip(brom_port)
        if chip:
            print(f"[+] hw_code=0x{chip[0]:04X} hw_sub=0x{chip[1]:04X} "
                  f"hw_ver=0x{chip[2]:04X} sw_ver=0x{chip[3]:04X}")
            if chip[0] == 0x8167:
                print("[+] MT8167 を確認")
        print("\n完了: 0x0E8D:0x0003 (BROM) へ移行済み")
        return 0
    finally:
        pr.close()


if __name__ == "__main__":
    sys.exit(main() or 0)
