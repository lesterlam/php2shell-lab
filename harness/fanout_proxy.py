#!/usr/bin/env python3
"""Minimal nginx stand-in for the reference lab.

The PoC sends nine HTTP requests in ONE sendall on ONE client connection and
then reads nine responses from that same stream. php -S cannot pipeline: it
handles one request per connection and closes. The reference lab therefore put
nginx in front, which accepts the pipelined client stream, fans each request
out to the upstream as its own connection (so the four php -S workers are all
used and the poisoned worker gets hit), and relays the responses back in order
on the single client connection.

This script does exactly that, stdlib only:

    client --9 pipelined reqs--> proxy --9 concurrent conns--> php -S :19527

Responses are re-framed with Content-Length so http.client can read nine of
them sequentially off one keep-alive socket. Backend responses are read to EOF
(php -S closes per request because we send Connection: close upstream).
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

BACKEND = ("127.0.0.1", 19527)
MAX_REQS = 16
BACKEND_TIMEOUT = 120.0


def read_requests(sock: socket.socket, max_reqs: int) -> list[bytes]:
    """Read up to max_reqs sequential HTTP requests from a client stream."""
    buf = b""
    requests: list[bytes] = []
    while len(requests) < max_reqs:
        # headers
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                chunk = b""
            if not chunk:
                if buf:
                    requests.append(buf)
                return requests
            buf += chunk
        head, buf = buf.split(b"\r\n\r\n", 1)
        head += b"\r\n\r\n"
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
                break
        while len(buf) < length:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                chunk = b""
            if not chunk:
                break
            buf += chunk
        body, buf = buf[:length], buf[length:]
        requests.append(head + body)
        # A request with Connection: close terminates the batch.
        if b"connection: close" in head.lower():
            break
        # If the buffer already holds the next request(s), parse them without
        # touching the socket: recv would block even though the batch is here.
        if buf:
            continue
        # Otherwise wait briefly for the next pipelined request; a timeout means
        # the client is waiting for this response and the batch is complete.
        sock.settimeout(2.0)
        try:
            more = sock.recv(65536)
        except socket.timeout:
            more = b""
        finally:
            sock.settimeout(300)
        if not more:
            break
        buf += more
    return requests


def forward(req: bytes) -> bytes:
    """Send one request to the backend on its own connection; read to EOF."""
    # Forward VERBATIM. The PoC's own source says "Header order ... [is] part of
    # the calibration", so rewriting Connection would shift the very heap bytes
    # we are trying to reproduce. Read the response by Content-Length instead of
    # relying on the backend closing.
    with socket.create_connection(BACKEND, timeout=BACKEND_TIMEOUT) as s:
        s.sendall(req)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(65536)
            if not chunk:
                return head
            head += chunk
        head, _, rest = head.partition(b"\r\n\r\n")
        length = None
        for ln in head.split(b"\r\n")[1:]:
            if ln.lower().startswith(b"content-length:"):
                try:
                    length = int(ln.split(b":", 1)[1].strip())
                except ValueError:
                    length = None
        body = rest
        if length is None:
            # No Content-Length (e.g. GET): read to EOF.
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                body += chunk
        else:
            while len(body) < length:
                chunk = s.recv(65536)
                if not chunk:
                    break
                body += chunk
            body = body[:length]
        return head + b"\r\n\r\n" + body

    with socket.create_connection(BACKEND, timeout=BACKEND_TIMEOUT) as s:
        s.settimeout(BACKEND_TIMEOUT)
        s.sendall(req)
        chunks = []
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def reframe(resp: bytes, keep_alive: bool) -> bytes:
    """Rewrite a backend response so the client can read it as keep-alive."""
    if not resp:
        return (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
    head, sep, body = resp.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0]
    kept = []
    for ln in lines[1:]:
        low = ln.lower()
        if (low.startswith(b"connection:") or low.startswith(b"transfer-encoding:")
                or low.startswith(b"keep-alive:") or low.startswith(b"content-length:")):
            continue
        kept.append(ln)
    kept.append(b"Content-Length: " + str(len(body)).encode())
    kept.append(b"Connection: " + (b"keep-alive" if keep_alive else b"close"))
    return status + b"\r\n" + b"\r\n".join(kept) + b"\r\n\r\n" + body


def handle(client: socket.socket, addr, pool: ThreadPoolExecutor, verbose: bool):
    client.settimeout(300)
    try:
        reqs = read_requests(client, MAX_REQS)
        if not reqs:
            return
        t0 = time.time()
        # Dispatch all requests at once so the four workers race.
        futures = [pool.submit(forward, r) for r in reqs]
        results = []
        for f in futures:
            try:
                results.append(f.result())
            except Exception as exc:  # backend died
                results.append(b"")
                if verbose:
                    print("  backend error: %r" % (exc,), file=sys.stderr)
        out = b""
        for i, resp in enumerate(results):
            out += reframe(resp, keep_alive=(i < len(results) - 1))
        client.sendall(out)
        if verbose:
            sizes = ",".join(str(len(r)) for r in results)
            print("[%s] %d reqs -> %d B in %.0f ms  [%s]" % (
                addr[1], len(reqs), len(out), (time.time() - t0) * 1000, sizes),
                file=sys.stderr, flush=True)
    except Exception as exc:
        if verbose:
            print("[%s] proxy error: %r" % (addr[1], exc), file=sys.stderr)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=19526)
    ap.add_argument("--backend-port", type=int, default=19527)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    global BACKEND
    BACKEND = ("127.0.0.1", args.backend_port)
    verbose = not args.quiet

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(16)
    print("fanout proxy 127.0.0.1:%d -> %s" % (args.port, BACKEND), flush=True)

    pool = ThreadPoolExecutor(max_workers=16)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle, args=(client, addr, pool, verbose),
                         daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
