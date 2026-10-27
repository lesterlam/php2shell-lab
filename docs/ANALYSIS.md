# Root-cause and patch analysis

Technical notes for CVE-2026-109618 / CVE-2026-109619. Verified against the CVE
records, the PHP security advisories and the source diff between PHP 8.4.26 and
8.4.27 — not against secondary reporting.

## 1. Record summary

| Field | Value |
|---|---|
| CVE-2026-109618 | "RCE via OOM corruption" |
| CVE-2026-109619 | "RCE via stale global state" |
| Nickname | "PHP2Shell" (assigned by threat analysts, not by PHP) |
| CVSS 4.0 | 9.2 CRITICAL — `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H` |
| Assigner | PHP (`security@php.net`) |
| Published | 2026-10-21 |
| Advisories | GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp |
| Fixed in | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Fix commit | `506e87fa` — "Avoid state corruption via bailout" (8.4 branch; verified ancestor of tag `php-8.4.27`). The same change also lands as `3584a98bda` on another branch. |
| Reported by | Ryan (Calif.io), Wiz, OpenAI |
| Remediation | Arnaud Le Blanc, Ilija Tovilo, Jakub Zelenka, Nora Dossche |

**Worst-affected SAPI.** Apache `mod_php` is confirmed exploitable over HTTP with
default limits and a normal prefork configuration. FPM exits a child when request
startup fails, so the application-independent sequence does not survive there,
though the advisory treats FPM as susceptible via application-specific paths.
FrankenPHP calls request shutdown unconditionally (like `mod_php`); LSAPI models
FPM.

## 2. CVE-2026-109618 — OOM corruption

PHP historically handled out-of-memory conditions by calling `longjmp()` to exit
the current context and abort request handling. That is an *early exit*: it
bypasses normal unwinding. When the OOM occurs while request memory is only
temporarily reachable — allocated but not yet fully initialised or tracked — the
early exit leaves the request scope in an invalid state. Request shutdown then
**reads or branches on that memory**. Given the right heap layout this becomes
control-flow hijack.

Ways to reach OOM while staying inside the declared limits (all attacker-controlled):

1. A multipart request without a usable declared content length can pass the
   initial `post_max_size` check and keep supplying decoded body data.
2. A multipart part can carry an unlimited number of headers; the in-memory
   representation costs substantially more than the wire representation.
3. Empty file controls do not count toward `max_file_uploads` but still allocate
   file metadata; nested field names multiply the generated array work.
4. Application-specific allocations driven by attacker input.

`mod_php` is the worst case because it invokes request shutdown unconditionally,
even when request startup failed. The OOM occurs during automatic body parsing at
startup, so the invalid state is processed entirely before any application code
runs — authorisation, nonces and upload validation are never consulted.

## 3. CVE-2026-109619 — stale global state

A producer/consumer model across requests handled by the same worker:

- **Producer** — an operation stores request-owned state in a globally reachable
  location and is then abandoned before its matching reset, by a fatal error
  (parse/compile failure, uncaught error, `require` failure, maximum execution
  time exceeded) or by OOM. The request heap is freed while the worker's global
  still refers to it.
- **Consumer** — a later request reads, frees or branches on that stale state
  before normal request initialisation resets it.

Confirmed consumers:

- Diagnostics raised while applying INI settings before executor initialisation
  (deprecated or invalid `auto_detect_line_endings`, `filter.default`,
  legacy `assert.*`/session settings, malformed `memory_limit`, `date.timezone`,
  and others). `error_reporting`, `@` and `display_errors` do not help, because
  global state is touched before PHP decides whether to report.
- **Session upload progress**, enabled by default and reachable without any call
  to `session_start()`.

The strongest demonstrated case is the PHP 8.5 `fatal_error_backtraces` path, and
it is the basis of the confirmed `mod_php` exploitation.

Reachability: with Apache, `.htaccess` and `php_value` / `php_flag` /
`php_admin_*` directives are applied before `php_request_startup()`. FPM is
conditionally exposed when a frontend sends `PHP_VALUE` / `PHP_ADMIN_VALUE`
parameters that produce a diagnostic before request initialisation.

## 4. Patch analysis (8.4.26 → 8.4.27)

Commit `506e87fa` touches several hundred files.

**`Zend/zend_alloc.c` (+527/−124).** OOM no longer `longjmp`s out of a context.
A new OOM state machine is introduced:

```c
typedef enum _zend_oom_state {
    ZEND_OOM_STATE_NONE = 0,
    ZEND_OOM_STATE_PENDING,
    ZEND_OOM_STATE_HANDLING,
    ZEND_OOM_STATE_HANDLED
} zend_oom_state;

#define ZEND_HAS_OOM() (UNEXPECTED(EG(delayed_oom).state != ZEND_OOM_STATE_NONE))
```

OOM is deferred as a **soft** condition to the next VM safe point, with an
immediate **hard** OOM exiting via `_exit()` if consumption reaches a second,
higher threshold. A *fallible* allocation API (`femalloc`, `fecalloc`,
`ferealloc`, `safe_femalloc`, …) returns `NULL` instead of unwinding, so callers
can handle exhaustion without leaving inconsistent state.

**`main/rfc1867.c` (multipart parser).** The parser stops retaining unbounded
attacker-controlled part headers:

```c
static bool php_mime_should_save_hdr(const char *name)
{
    return !strcasecmp(name, "Content-Disposition")
        || !strcasecmp(name, "Content-Type");
}
```

Only the two headers PHP actually consumes are kept; duplicates and everything
else are discarded. The registration helpers now return `bool` and report
`ZEND_HAS_OOM()`, letting the parser jump to a graceful `oom_with_param` label.
A `post_max_size` guard was added to the body read loop.

**Tests.** Hundreds of `oom_*.phpt` cases were added across roughly thirty
extensions, because every allocating code path had to be re-audited for
OOM-safety. `Zend/tests/oom_request_parsing.phpt` ("Request parsing doesn't reach
hard limit") is the regression test for this class.

## 5. Observable behaviour in this lab

With `php -S` (cli-server), `memory_limit=64M`, `post_max_size=256M`:

- Vulnerable 8.4.26 aborts during startup on a 250,000-header body and returns a
  memory-exhaustion fatal error with no application output.
- Patched 8.4.27 parses the same body normally, with peak request memory flat at
  2 MiB.
- After an aborted request on the vulnerable build, an unrelated subsequent `GET`
  reports an inflated peak (34 MiB, decaying to 18 MiB against a 2 MiB baseline)
  — evidence that the aborted request left state on the worker.

## 6. Stage 2 — what the OOM leaves behind (measured)

Section 5 shows the aborted request leaves *something* on the worker, measured
indirectly (an inflated peak on the next request). This section measures it
directly: what the next request actually receives.

### 6.1 The channel

Session upload progress is the confirmed consumer from section 3, and it runs
during **request startup — before RINIT**, so no application code is involved.
Three details make it observable from outside:

- PHP accepts the session id from a **form field named after `session.name`**
  (`PHPSESSID`) inside the multipart body, not only from a cookie.
- When PHP starts a session it **echoes the session id back in `Set-Cookie`**.
- A session id that fails PHP's character check still produces the header, plus
  a warning.

So if the session id is read out of recycled memory, the response itself carries
the result. The observable is the length and content of the
`Set-Cookie: PHPSESSID=...` value. A healthy worker returns 32 characters.

### 6.2 Ground truth in the patch

The fix commit is explicit about the ordering hazard. In `ext/session/session.c`:

```c
case MULTIPART_EVENT_START: {
    multipart_event_start *data = (multipart_event_start *) event_data;

    /* This runs before RINIT, so we need to clear these early */
    php_rinit_session_globals();
```

Before the fix those globals were **not** cleared at that point, so the handler
ran with the previous request's session globals still live. The commit also adds
a `PS(in_rfc1867_update)` flag so the decode/encode performed here resolves no
classes, and deletes `$_SESSION` afterwards:

```c
/* $_SESSION was populated in incomplete_classes_only mode */
zend_string *session_var_name = ZSTR_INIT_LITERAL("_SESSION", 0);
zend_delete_global_variable(session_var_name);
```

The regression test added for this path, `ext/session/tests/rfc1867_no_user_code.phpt`,
is this attack's skeleton — a multipart POST carrying a `PHPSESSID` **form field**
next to `PHP_SESSION_UPLOAD_PROGRESS` — and its own comment states the consequence:

> "This script has not called `session_start()`, so it must not be left behind:
> it would otherwise expose the session data of whatever id the request body
> carried."

The sibling test `rfc1867_sid_invalid.phpt` asserts the exact warning this lab
observes:

```
Warning: PHP Request Startup: Session ID is too long or contains illegal
characters. Only the A-Z, a-z, 0-9, "-", and "," characters are allowed in
Unknown on line 0
```

`PHP Request Startup` is the tell: the session id is being read before the
request's own code exists.

### 6.3 Measured

Builds: `php:8.4.26-fpm-alpine3.23` and `php:8.4.27-fpm-alpine3.23` — the image
family the public proof of concept was calibrated against — both run as `php -S`
with `PHP_CLI_SERVER_WORKERS=4` and the default `memory_limit=128M`.

| mode | PHP 8.4.26 (vulnerable) | PHP 8.4.27 (patched) |
|---|---|---|
| `fresh` — consumer only, worker never OOM'd | 32-byte ids, 0 fatals (8/8) | 32-byte ids, 0 fatals (8/8) |
| `after` — OOM producer, then consumer (code geometry) | **18–20 of 20 anomalous**: 8-byte ids `0100000000000000`, startup warning in the same runs | producer does not OOM (0/20); every id 32 bytes |
| `after` (heap geometry) | **10/10 anomalous**: mostly corrupted-allocation deaths (7–10 of 10), occasionally a stale id instead | — |

The `fresh` row is the control that makes the rest mean something: without a
preceding OOM, the same request shapes are completely clean.

Counts vary between runs — which worker picks up which request is not fully under
the client's control. The *shape* of the result is stable; the exact tally is not,
so a single run is not evidence of a rate. Read these as "nearly always" and
"usually", not as constants.

Anomalous id, as it appears on the wire:

```
Set-Cookie: PHPSESSID=%01%00%00%00%00%00%00%00; path=/
Warning: PHP Request Startup: Session ID is too long or contains illegal characters...
```

Corrupted allocation (heap pairing):

```
Fatal error: Possible integer overflow in memory allocation (3 * 18446744073709551615 + 32)
Fatal error: Allowed memory size ... (tried to allocate 17361641481138401552 bytes)
```

The second value is `0xF0F0F0F0F0F0F0F0`; the first is `3 * SIZE_MAX + 32`. Both
are allocation sizes taken from memory the aborted request left behind — a
memory-safety failure, not merely a denial of service.

### 6.4 The emitted length tracks attacker input

Sweeping the consumer's filler value size (code geometry):

| filler value size | emitted `PHPSESSID` length |
|---|---|
| 16 | 16 |
| 96 | 96 |
| 256 | 256 |
| 512 | 512 |
| 32, 48, 64, 192 | request dies before the header is written |

The session id's **length field** therefore comes from memory this request
recycled, and the bytes are this request's own filler. The primitive is present —
PHP will emit an attacker-influenced number of bytes from a recycled buffer — but
at these field sizes the read stays inside a buffer the attacker supplied.

> **Corrected 28 Oct 2026.** The clause above — *"the read stays inside a buffer
> the attacker supplied"* — is true of the shapes measured here (64–512-byte
> fields) and **false in general**. Growing the value until a single allocation
> *contains* the stale pointer decouples the emitted length from the buffer it is
> read from, and the read continues into memory this request never wrote. **§7**
> supersedes this subsection's ceiling; the sweep table above is left as measured.

### 6.5 The pairing decides which symptom appears

The same two bugs, on the same worker, produce two different outcomes depending
on which producer geometry precedes the consumer — predominantly, not as a clean
switch:

- **code geometry** (251,557-byte producer) → almost always a session id read
  from recycled memory, with the startup warning;
- **heap geometry** (249,042-byte producer) → usually the follow-up request dies
  on an allocation size taken from stale memory, with no id emitted; a stale id
  still appears in some runs.

Both are stale-state consequences. This is also the honest explanation for why
the public PoC's offsets look arbitrary: they are one point in a pairing space,
not universal constants.

### 6.6 What did not reproduce

Three claims from the public proof of concept did not hold here, and are recorded
rather than smoothed over:

1. **Pipelining.** Its leak batches send one producer plus eight consumers down a
   single connection. On this build `php -S` returns **zero responses** for any
   pipelined batch — including two pipelined `GET`s, and a batch whose producer
   does not OOM at all. The consumers therefore cannot ride the poisoned
   connection; this lab reaches the same primitive on separate connections
   instead. The public run was behind nginx and never captured its own wire
   traffic, so this is a statement about this lab's clean CLI-server setup, not
   about the live run.
2. **The 256-byte over-read with a foreign tail.** The PoC's heap-stage consumer
   stamps a length (256) into a 79-byte field so the claimed length exceeds the
   real buffer. That shape never landed here: 100/100 attempts returned ordinary
   32-byte ids.
3. **The 16-byte code cookie** whose first eight bytes are `16` and whose low 21
   bits fingerprint `zval_ptr_dtor` was not observed.

### 6.7 Provenance

The request shapes used here are adapted from the public proof of concept for the
*Steal My Bitcoin* challenge (`KillaBoi/StealMyBitcoin-PoC`), which declares no
licence — so this is an independent implementation of the technique and its
measured geometry, not a copy of its code. The two producer bodies this lab
builds are **249,042** and **251,557** bytes, matching the figures that PoC
documents for the same image family, which is what keeps the comparison
like-for-like.

### 6.8 Ceiling

Command execution still needs the length/buffer decoupling from 6.6(2), then a
code-pointer leak to defeat ASLR, then a forged structure that request cleanup
will call. This lab demonstrates the stale-state primitive and a corrupted
allocation size, with a clean vulnerable/patched A/B — and stops there.

> **Corrected 28 Oct 2026.** The first of those three prerequisites — the
> length/buffer decoupling — is now demonstrated in **§7**. The ceiling for RCE as
> a whole is unchanged: §7 adds a disclosed over-read carrying heap pointers, not a
> code pointer or a forged structure.

## 7. Stage 3 — decoupling the length from the buffer (measured)

Section 6.4 left a ceiling in place: at every size measured there, the read stayed
inside a buffer the attacker had supplied. That ceiling was an artefact of the
*sizes tested*, not of the bug. This records what lifted it.

### 7.1 The question is an address, not a payload

The emitted length is not a value the attacker sets — it is a **struct field of a
`zend_string`**, read from wherever the stale pointer happens to point:

```
PS(id)+0x00  gc(refcount)  reference count + type
PS(id)+0x08  h             hash
PS(id)+0x10  len  <-- the length PHP will trust
PS(id)+0x18  val[1]        first byte of the string body
```

The length is *truthful* exactly when `PS(id)` lands at the **start** of a buffer we
control: `+0x10` is then that buffer's own header, written by PHP consistently with
its allocation size. It becomes a lie when `PS(id)` lands **inside** our buffer at
offset ≥ 0x18, because then `+0x10` is bytes we chose.

Neither case is visible from the wire — both can emit the same bytes. It has to be
measured from inside the process, which is why this stage needs a modified build.

### 7.2 Method: instrument rather than guess

`build-instrumented.sh` builds stock php 8.4.26 with three `fprintf()`s added by
`instrument-php.py`. The probes only observe; behaviour is unmodified.

| probe | site | prints |
|---|---|---|
| A | `php_session_send_cookie()`, before the id is URL-encoded | `PS(id)`, `ZSTR_VAL`, `ZSTR_LEN`, the header, the first bytes |
| B | rfc1867 `MULTIPART_EVENT_START` | `PS(id)` as the upload-progress path sees it |
| C | `php_register_variable_ex()` | address and length of every controlled POST value |

A and C together give the delta between the stale pointer and our own buffers —
the number the entire grooming problem reduces to, and one that cannot be read off
the wire. The release tarball ships a pre-generated `configure` and pre-generated
parsers, so this builds with only a C compiler and make: no autoconf, bison, re2c.

### 7.3 Measured: containment

Producer = the `code` geometry (251,557 bytes on the wire), then the consumer on a
following connection. `php -S`, 4 workers, vulnerable 8.4.26:

| consumer fields × value size | `PS(id)` | containment |
|---|---|---|
| 73 × 256 B | `0x72213927e080` | none — lands at a buffer **header** |
| 73 × 512 B | `0x72213927e080` | none |
| 73 × 1024 B | `0x72213927e080` | **inside** a 1024-byte buffer at `+0x278` |
| 73 × 4096 B | `0x72213927e080` | **inside** a 4096-byte buffer at `+0x78` |
| 16 × 8192 B | `0x72213927e080` | **inside** an 8192-byte buffer at `+0x78` |
| 8 × 16384 B | `0x72213927e080` | **inside** a 16384-byte buffer at `+0x2078` |

Two things to read from that. `PS(id)` is **identical across every shape within a
run** — the stale pointer's address is a property of the previous request, not of the
consumer, so it is knowable. And containment appears only once the value is large
enough for one allocation to *span* that address: it needs a buffer that contains
`PS(id)`, not a buffer that starts at it.

That also explains all of §6.4. A 64–512-byte allocation is too small to reach the
stale address, so PHP kept reading its own header — which is exactly why the
emitted length always equalled the filler size.

> **The offset is not stable — only the address is.** A later run measured the same
> 1024-byte containment at `+0x128`, with `PS(id) = 0x7ad01a67d040`, not `+0x278`.
> The allocator's history differs between runs, so *which* offset inside the region
> the stale pointer lands on moves. Hardcoding the band `[0x270, 0x2a0)` — as an
> earlier revision of this lab did — therefore produced zero adoptions, which is why
> §7.4 discovers the shape at runtime instead of assuming it. Read the offsets above as
> *one* run's values, and the *containment* as the finding, not the number.

### 7.4 Measured: the length becomes ours

Because the offset moves between runs (§7.3), a constant cannot aim at it. So
`stage3.py` discovers the shape instead of assuming one: it walks the value-size
classes, sends a producer plus a plain `P`-filled consumer for each, reads the offset
out of probe C, and once a shape is found that contains `PS(id)+0x10` at an offset
`>= 0x18`, it builds the payload that stamps `0x1234` at every 8-aligned offset across
a window around that measured offset. Any 8-aligned read inside the window yields the
claim. From the run that gates CI:

```
  aiming with fields=73, vsize=512: the len field is at +0x138 of the value
  stamping 0x1234 at every 8-aligned offset in [0x128, 0x150)
  rep    id len     verdict
  0      4660       *** length adopted our claim ***
  1      4660       *** length adopted our claim ***
```

Getting here took two failures, and the second is the instructive one. A single
scout on a **fresh** pool reported *no containment* at `vsize=1024` while containment
mode — on its own pool, with several shapes already through it — was simultaneously
measuring `+0x138` at that same size. Where the stale pointer lands depends on the
pool's accumulated history, not only on the request, so a shape that works on a warmed
pool does nothing on a fresh one. Discovering the shape per mode, rather than assuming
one, is what made the claim reproducible — and it is why claim and leak get a fresh
pool per rep (§7.7): the measurement has to be self-contained.

4660 = `0x1234`. The length is now decoupled from the buffer it is read from.

```
read started in buffer 0x796fb607cf18 (len 512), which ends at 0x796fb607d118
        *** 6 leaked value(s) lie BEYOND that end ***
        -> 0x796fb607d180 & ~0x1FFFFF = 0x796fb6000000  (2 MiB-aligned Zend chunk)
```

### 7.5 Measured: the tail is memory we did not write

A long id full of one's own filler proves nothing — "my other allocations" and
"foreign heap" look identical. Two tells that survive it, then one inequality.

**Tell 1 — per-field markers.** Fill field *i* with byte `0x40+i`; a read crossing
allocation boundaries mixes their markers. Measured output alternates runs of
`0x40` (field 0) with runs of `0x50` (field 16) at regular strides:

```
+0x0020   352 bytes of 0x40
+0x0284   620 bytes of 0x50
+0x0520   352 bytes of 0x40
```

**Tell 2 — address-like u64.** Real heap structures hold `0x7…` values that filler
never produces. Nine found, spaced `0x40` apart — a HashTable bucket array:

```
+0x01a8 = 0x72213927e280
+0x01e8 = 0x72213927e2c0
+0x0228 = 0x72213927e300
+0x06a8 = 0x72213927e780
```

**The inequality.** The read started in a buffer at `0x72213927de18`, length 1024, so
it ends at `0x72213927e218`. Every leaked pointer lies **beyond** that address. That
comparison is the proof: the bytes are not ours, because they are outside the
allocation they were read from.

> **Corrected 2026-10-28 — the inequality proves less than this paragraph claims.** It
> proves the over-read; it does not prove the bytes are outside memory the *attacker*
> controls. See [§10](#102026-10-28--the-75-inequality-proves-less-than-the-text-claims).
> Subsequent measurement put all 20 leaked pointers inside our own POST-body buffers. Masking one to Zend's 2 MiB chunk alignment gives
the chunk base — the input the next two chain steps need:

```
0x72213927e280 & ~0x1FFFFF = 0x722139200000
```

### 7.6 What this does and does not establish

Establishes:

- the stale pointer lands inside a buffer the attacker controls, repeatably, at an
  address that is stable across consumer shapes;
- the emitted length is attacker-chosen and the read continues past the end of that
  allocation;
- the tail contains live heap pointers, from which the allocator's chunk base
  follows — qualified 2026-10-28: they are real chunk addresses *of our own POST
  data* ([§10](#102026-10-28--the-75-inequality-proves-less-than-the-text-claims)).

Does **not** establish:

- **no code pointer.** The leaked values are heap addresses of strings and HashTable
  buckets. Defeating PIE needs a value in the text or library range, which would
  need a different object type at the stale address.
- **no forged structure.** The end state is a disclosed id, not a corrupted object
  that request cleanup will call.
- **no control-flow change**, and nothing beyond a single worker. Multi-worker
  reliability is untouched.

This is chain step 3 of 6. It closes the gap §6.4 recorded; it does not close the
exploit.

### 7.7 Reproducing

```bash
./build-instrumented.sh    # php 8.4.26 + probes A/B/C, a few minutes
PORT=18627 ./stage3.sh     # control -> containment -> claim -> leak
```

`stage3.sh` starts its own server per measurement, because the control is only valid
on a pool that has never served an OOM request. Reusing a pool would show a stale
`PS(id)` with no producer in flight, and `stage3.py` reports that instead of
presenting it as a control.

Pools are also spent by the measurement itself. A pool tolerates roughly **three**
corrupting requests before Zend aborts it, and discovery costs producers: claim and
leak sweep the value-size classes to find a shape that contains the stale pointer,
then spend one more request on the stamped read. Running three reps inside one pool
therefore spent the pool's tolerance on rep 0 and reported `server died` for the rest,
which is indistinguishable from the bug failing to reproduce. So claim and leak get a
**fresh pool per rep**, and the gate asks for at least one success rather than all of
them — the run that gates CI reports claim 2/3 and leak 3/3, against a control that is
clean and containment that is found every time.

## 8. Limitations of this reproduction

What is demonstrated is the pre-condition, the vulnerable/patched delta, the
root cause from the source diff, the stale-state consequences measured in
section 6, and the over-read measured in section 7. What is **not** demonstrated
is the weaponised RCE. Reaching control-flow hijack additionally requires:

1. ~~Controlling the *content*, *location* and *timing* of the corrupted memory.~~
   **Demonstrated in §7** for the read path — but only on Zend's allocator and a
   single worker. Remaining: the same control over a structure that is *written*,
   and the glibc `malloc` pairing.
2. A value that is used as a pointer, length or index rather than merely read —
   plus an information leak to defeat ASLR/PIE.
3. Bypassing NX (ROP), stack canaries and CET/shadow stack.
4. Doing all of the above reliably across a multi-worker prefork pool.

A public proof of concept does exist — see section 6.5 and 6.7. What this lab
takes from it is the stale-state primitive; what it does not take is the command
execution, which needs the code-pointer leak listed above (the decoupling is in
§7). Section 6.6
records the parts of that PoC that did not reproduce here, because a negative
result dated to this build is more useful than an assumed one.

## 9. Mitigation

1. **Patch** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This is the only complete fix.
2. If patching is impossible: set and enforce `memory_limit=-1` administratively,
   which removes the predictable per-request limit the confirmed exploit depends
   on. Incomplete.
3. Set `fatal_error_backtraces=0` (PHP 8.5) and `session.upload_progress.enabled=0`,
   then restart every worker. Covers the confirmed RCE case and the demonstrated
   session lifecycle path respectively, but not other request-owned state.
4. Reduce the remaining risk: keep `post_max_size` conservative and enforce
   decoded request size at the frontend; bound `max_input_vars`,
   `max_input_nesting_level`, multipart parts, headers per part and uploads.
   Block multipart entirely at the frontend if the application does not use it.
5. A container or cgroup `memory.max` can serve as a backstop, with caveats.
   **Do not use `RLIMIT_AS` or `RLIMIT_DATA`** — they make `mmap()` fail at the
   limit, which re-triggers the vulnerable `longjmp()` path.

## 10. Corrections — dated

Corrections are appended and dated. Superseded wording above is left standing, with a
pointer to the correction, so the record shows what was believed and when it changed.

### 10.1 2026-10-28 — the §7.5 inequality proves less than the text claims

§7.5 argues from `V+0x400 < every leaked pointer` that "the bytes are not ours". The
addresses are indeed outside *that* 1024-byte buffer, so the over-read (chain step 3) is
proved. They are **not** shown to be outside memory the attacker controls.

Measured on the same build (the §7.5 configuration plus two more; probe C logs the
address of every controlled field value, so each leaked pointer can be attributed):

| configuration | leaked pointers | pointing outside our own POST-body buffers |
|---|---|---|
| 73 fields x 1024 B | 6 | **0** |
| 73 fields x 2048 B | 7 | **0** |
| 32 fields x 2048 B | 7 | **0** |

All 20 resolve into sibling allocations of the *same request's* POST body — Zend arena
memory (`[anon:zend_alloc]`), stride `0x40`. Corrected reading: the §7.5 tail is memory
we did not write **in that allocation** — an over-read past the claimed length, but still
inside our own block. The chunk-base arithmetic survives (the addresses are real Zend
chunk addresses); what it yields is the arena base of our own POST data, not of foreign
structures. README's "the tail memory we did not write" carries the same qualification.

Two harness notes from producing this table, both of which had already corrupted a
conclusion before they were found:

- `classify()` returns a `(kind, base, perm)` tuple; the check was `kind in ("text",
  "lib")`, which never matched anything. The first "0 code pointers" result was this bug,
  not a measurement.
- The read never leaves the Zend allocator: `escaped` counts bytes past our buffer, but
  the bytes there are the parser's own index for our POST data (a ~4 KB bucket array),
  then zeroed heap.

### 10.2 2026-10-28 — Step 4: the public PoC's code-pointer route, identified but not transferable

Chain step 4 is heap base -> code pointer. A public PoC does reach a code pointer, and
reading it against this lab resolves the route exactly — but it does not transfer to this
build, and the reason is structural in two independent ways.

**Its code-pointer read never uses a lying length.** The PoC's cookie is `{16,
zval_ptr_dtor}` because `PS(id)` lands on a **HashTable struct + 0x18**: PHP reads `len`
from `ht+0x28` (`nNextFreeElement == 16`, a packed 16-element array) and the cookie bytes
from `ht+0x30` (`pDestructor == zval_ptr_dtor`). **[Corrected 2026-10-28: the struct is
entered at `+0x10` and the length comes from `ht+0x20` `nTableSize` — see §10.3(a).]** §7's attacker-controlled length — the
harder primitive this lab spent its Stage 3 on — is not part of that route at all. The
PoC's consumer geometry is 73 field values of **24 bytes** plus **one 16-element array at
field position 69**; this lab used 512 B and up. Note that §7.3's containment band
(`off >= 0x18` and `off + 0x18 <= vsize`) is unsatisfiable below `vsize` 32, so a
containment sweep can never visit that geometry.

**Blocker 1 — the published transport cannot be hosted by the SAPI the PoC names.**
`sapi/cli/php_cli_server.c:394` appends `Connection: close` unconditionally to every
response, and the file contains no keep-alive machinery (`conn_close` does not exist in
it). The PoC sends one `sendall` carrying nine HTTP requests on one connection — producer
keep-alive plus eight pipelined consumers, written before any response is read — so the
consumers are served by the worker whose heap the producer just exhausted. Measured on
three configurations:

| probe | instrumented, 4 workers | stock 8.4.26, 4 workers | single worker |
|---|---|---|---|
| one keep-alive GET | 1 response | 1 response | 1 response |
| two pipelined GETs, one `sendall` | **0 responses** | **0 responses** | **0 responses** |
| two sequential GETs, one connection | 1, then closed | 1, then closed | 1, then closed |

A php-fpm + nginx front-end does not substitute: FastCGI carries no client-connection
affinity, so the nine requests would be dispatched to whichever worker is free, which
removes the only thing the pipeline was for. Copying the PoC's builders verbatim against
this lab's server reproduces the rejection: producer + one pipelined consumer in a single
`sendall` -> 0 bytes, `Invalid request (Malformed HTTP request)` in the server log.

**Blocker 2 — the 24-byte geometry does not reproduce the stale read here, measured at
the read site.** Producer from §7, then the PoC's consumer, with probe A logging every
consumer read:

```
[INSTR-A] PS(id)=0x722dcc6c9000 val=PS(id)+0x18 len=32 gc_refcount=1 gc_type=0x16
[INSTR-A] bytes(32): 32 38 66 66 33 65 66 33 ...      ("28ff3ef3...", valid hex)
```

Stable address, live refcount, valid hex: `PS(id)` is not stale, PHP regenerated the id.
A sweep of 13 consumer value sizes (8..512) x 2 pools x 4 consumers, over fresh
connections, saw only clean 32-byte ids or no cookie. To test the allocation-order
hypothesis directly, marker-bearing values (`PPPP...`) at 32, 40 and 64 bytes make probe C
log all 73 controlled field addresses in each run; at every size the read site's `PS(id)`
matched **none** of them and read a healthy 32-byte id (0/9). With 512-byte values the
stale pointer *is* contained — §7.3 measures it — so this is a size-class effect, not an
absence of corruption.

**Conclusion.** The disclosure primitive reproduces (§6, §7). The calibration that turns
it into a code-pointer over-read does not: its transport is impossible on the SAPI it
names, and its small-value geometry never places the stale pointer where the hash-table
read needs it. At least one detail in the PoC must be reconstructed rather than observed
— its README concedes the original run never captured its own wire traffic. Reporting the
negative this way keeps the claim falsifiable: it names the two blockers, the source line
for one of them, and the measurement for the other.


### 10.3 2026-10-28 — the `+0x10` offset, and the producer's value size is the real lever

Two claims in §10.2 do not survive measurement. Nothing above has been rewritten; this
section is the correction.

**(a) The offset is `+0x10`, and the length comes from `nTableSize`.** §10.2 says `PS(id)`
lands on "a HashTable struct + 0x18" with `len` from `ht+0x28`. The real `struct
_zend_array` (`Zend/zend_types.h`, 8.4.26) is `0x00` `gc`; `0x08` `u.flags` / `0x0c`
`nTableMask`; `0x10` `arHash`/`arData`/`arPacked`; `0x18` `nNumUsed`/`nNumOfElements`;
`0x20` `nTableSize`/`nInternalPointer`; `0x28` `nNextFreeElement`; `0x30` `pDestructor`.
The PoC's check — `len == 16`, `cookie[0:8] == 16`, `cookie[8:16]` a code pointer whose low
21 bits are the page offset `0x112930` — holds exactly when `PS(id) = HT + 0x10`:

| read | field | value for a packed 16-element array |
|---|---|---|
| `len` <- `HT+0x20` | `nTableSize` \| `nInternalPointer` | `16` |
| `cookie[0:8]` <- `HT+0x28` | `nNextFreeElement` | `16` |
| `cookie[8:16]` <- `HT+0x30` | `pDestructor` | `zval_ptr_dtor` |

`nTableSize` and `nNextFreeElement` are both 16 for a packed 16-element array, which is why
the one-field error was invisible. The PoC's own Stage 4 forged table agrees: `arData` at
`0x10`, `zif_system` at `0x30` (`stealmybitcoin_poc.py:369-374`).

**(b) The 24-byte geometry claim needed a condition it did not state.** §10.2's "its
24-byte geometry does not place the stale pointer at the read site" was measured with the
producer of §6/§7 — depth 58 / count 935 / 65 fields / **value 39**. Sweeping the
*producer's* geometry instead, fresh worker pool per run, consumer kept at the PoC's own
calibration:

| producer depth/count/fields/value | OOM | read at the PoC's consumer geometry |
|---|---|---|
| 58/935/65/39 | yes | healthy 32-byte id |
| 58/935/65/1 | yes | `PS(id)` = one of our own value strings: `len=24`, content = our fill |
| 58/935/65/24 | yes | `len=262`: a stale string read out of recycled heap |
| 58/935/65/256 | yes | length read as the table's `arData`; PHP refuses the id, no cookie |
| 40/1300/65/24 | **no** | invalid — no OOM |
| 16/3300/65/24 | **no** | invalid — no OOM |

Re-run for reproducibility (2 pools each): value 1 -> stale in 1 of 2; value 24 -> stale in
3 of 4. Real, but not deterministic: about half of fresh pools. The size class that decides
whether a small-value consumer reaches the stale block is therefore chosen by the
**producer's** value size, and the 24-byte geometry does reach it at value 1 and 24 — it
just does not reach a code pointer. Sweeping the consumer's array position over 0..160 (41
positions, every stale one re-run once: 72 runs total) produced zero code-pointer reads,
with one dominating landmark: `len=262`, `PS(id)` page-aligned, content = a leftover
32-character id string followed by NUL and raw heap words.

**(c) Why the reference PoC succeeds where these runs do not.** Its source
(`stealmybitcoin_poc.py:228-245`) manufactures the structure it reads instead of looking
for one. `heap_consumer()` sends a 79-byte value whose *payload* is a fake `zend_string`
header — `struct.pack_into("<Q", forged, 0x10, 256)` writes the length field and
`forged[0x18] = ord("L")` marks the leak's start — positioned so that payload lands on the
stale string header ("Repeating numeric key 1050 changes the array's allocation pattern so
the crafted value below lands on the stale string header"). Its code-pointer stage is the
same trick with a hand-fitted trailing position (24-byte values, one 16-element array at
position 69). What the code-pointer read needs is a real `HashTable` struct sitting exactly
`0x10` bytes before the stale id string, because that is the only way a POST-shaped payload
makes PHP read `nTableSize`, `nNextFreeElement` and `pDestructor` as one 16-byte string.
Zend's segregated-fit allocator puts a `HashTable` struct (56 B) and a 32-character id
string (57 B) in the same class, so that reuse is possible — and the value-256 runs show the
class collision happening (the length is read as the table's `arData`). What 92 runs never
produced is the `0x10` shift: `PS(id)` lands on the table's own base, not on `HT+0x10`.

Reproduce: `step4_prodsweep.py --mode producer` and `--mode offset` (per-run server logs
under `logs/`).

### 10.4 2026-10-28 — the probe was blind, and what the two remaining knobs actually do

**(a) A measurement defect in §10.3, found and fixed.** Probe A was inserted inside
`php_session_send_cookie()` *below* its first statement:

```c
static zend_result php_session_send_cookie(void) {
    smart_str ncookie = {0};
    zend_string *date_fmt = NULL;
    zend_string *e_id;

    if (SG(headers_sent)) { ...; return FAILURE; }   /* probe A sat below this */
```

So whenever PHP warned before sending headers — which the stale-id path does — the function
returned before the probe, and a run was recorded as "no cookie, no data" even though
`PS(id)` had been dereferenced. Probe **A0** now sits at function entry, above the guard, and
reports `send_cookie` and `headers_sent`; probe **D** sits in `ppid2sid()` right after the id
is built from the upload-progress field. Applied by `add-probes.py` (idempotent), rebuilt
with `make -j` in both instrumented trees.

Two harness faults were fixed at the same time: a second sweep instance ran concurrently and
interleaved two result blocks into one log (ports are deterministic per index), and the first
rebuild went into `ci-sim4/` while the sweeps run `php-8.4.26/sapi/cli/php` — so probe A0 was
absent from the binary under test. Both are now guarded (`fcntl` single-instance lock, pid in
the log header).

**(b) The two knobs, measured.** 32 configurations — the `PHPSESSID` field value length on
each side (NUL, 16, 37, 56 bytes) crossed with the PoC's repeated-key churn (16 and 64 copies
of one key, plain 24-byte values and the PoC's 79-byte forged `zend_string` header). Every
configuration OOM'd the producer; 54 worker pools in total, re-runs included.

| knob | result |
|---|---|
| `PHPSESSID` length, producer side | 0 wins. Shorter is the only usable range: at 16/37/56 the id stops being regenerated, `send_cookie` is never reached and the run ends with no `Set-Cookie` at all |
| `PHPSESSID` length, consumer side | 0 wins, but it does move the class of the string that lands on the stale chunk — see (c) |
| repeated-key churn (16, 64) | 0 wins and no change of symptom: every churned run reproduced the same `len=4294967297` read. It also pushed runs into the headers-already-sent path (`send_cookie=1 headers_sent=1`), i.e. no cookie |
| probe D (`ppid2sid`) | **never fired in any of the 54 runs** — in this configuration the id is never adopted from a POST field, so the stale pointer is not "our field being adopted"; it dangles from an earlier request |

**(c) What the stale reads are.** Two configurations read stale state reproducibly, both now
visible at entry with `send_cookie=1 headers_sent=0`:

```
P-NUL+C-24 : [INSTR-A0] len=4294967297 (0x100000001)  first8=08 00 00 00 00 00 00 00
P-NUL+C-37 : [INSTR-A0] len=5  bytes = 61 30 30 35 35  ("a0055")
             wire Set-Cookie: PHPSESSID=a0055
```

`"a0055"` is a **field name from our own multipart body** (`a0055[0]`). In that pool the same
pointer was logged in both requests:

```
producer : [INSTR-A0] entry PS(id)=0x7f307b87d040 val=+0x18 len=32  gc_refcount=1 gc_type=0x16
consumer : [INSTR-A0] entry PS(id)=0x7f307b87d040 val=+0x18 len=5   bytes 61 30 30 35 35
```

Same address, different contents: `PS(id)` is a dangling pointer into a chunk that request
shutdown returned to Zend MM and the next request's multipart parser handed back out for a
field name. That is the PoC's plant-on-the-stale-header effect arriving by accident, and it
reached the wire (a 5-byte `PHPSESSID`). What it never produced is a 16-byte read of
`{16, pDestructor}`: the class that lands there is decided by whichever string the parser
allocates next, and nothing in the two knobs makes a real `HashTable` struct land `0x10`
before the stale pointer.

**(d) Running total.** 146 pools across §10.3 and §10.4, zero code-pointer reads. The
structural statement in §10.3(c) is unchanged and now better supported: what step 4 needs is
a real `HashTable` at `stale - 0x10`, and the knobs tried so far move *which string* reuses
the chunk, not *where a table* sits relative to it.

Reproduce: `step4_fitsweep.py` (writes `fitsweep2.log`, per-run server logs under
`fitsweep2-logs/`), probes added by `add-probes.py`.

### 10.5 2026-10-28 — heap grooming on the stable pad: the bin goes to strings, every time

§10.4 left a reproducible landing pad: 22 of 32 configurations put a dangling `PS(id)` on
the wire, deterministically. That pad is what makes grooming possible — you cannot steer an
allocation onto a chunk that only sometimes exists. This section is the first grooming
attempt on it.

The step-4 win condition is a layout fact, not a payload fact. A win needs
`PS(id) == address(HashTable) + 0x10`, so that the 16-byte cookie read is
`{HT+0x28 nNextFreeElement, HT+0x30 pDestructor}` — `16` followed by a code pointer.
Nothing about the payload can substitute for the shift.

Method. Hold the pad fixed (producer `PHPSESSID` = NUL, consumer id = 24 `a`) and vary only
the consumer's array geometry: how many scalar fields precede the array (0, 8, 16, 32, 48,
64, 72), where the array sits in the part order (front / tail), element size (8..64),
element count (8/16/32), repeated arrays (2/4/8), and scalar value size (8/16/24/40). Every
stale configuration is re-run once; a disagreement is reported as flaky. 35 configurations,
46 pool runs, fresh server per run.

Result: **18 stale, 0 wins, 0 flaky.** No configuration read a 16-byte length, and no read
produced a code pointer. The pad itself is solid: a separate four-rep check on the baseline
geometry read stale 4/4 with byte-identical bodies (92,411 B, verified against
`step4_fitsweep.consumer`).

The stale reads fall into three shapes, and the first two are new relative to §10.3:

| configuration | length read | first 8 bytes | what the freed chunk was reused as |
|---|---|---|---|
| `end-f64-l16-v32` | `32` | `0x78` x 8 | **our own array element value**, `"x" * 32` |
| `end-f48/f64/f72-l16-v16`, `end-f64-l8-v16`, `end-f64-x2/x8` | `5` | `61 30 30 38 30` = `"a0080"` | **our own multipart part name** |
| `end-f64-l16-v8/v16/v40/v56/v64`, `s8`, `bin-id8-*` | `4294967297` | `0x8 0x1 <ptr> 0x700000001 ...` | unaligned/garbage words |
| `end-f64-l16-v24`, `front-f0-l16-v16` | `9223372247559138859/960` | pointer-like words | ditto |

**(a) A controlled read, on the wire.** `end-f64-l16-v32` is the PoC's "plant on the stale
header" effect, reproduced without forging anything. The producer's request leaves the id
chunk at `PS(id)`; the consumer's request reuses that exact address for one of its own array
element strings. The A0 probe sees the same address in both requests:

```
producer: PS(id)=0x7e170e47d040 len=32  headers_sent=1   (live id)
consumer: PS(id)=0x7e170e47d040 len=32  headers_sent=0   bytes = 0x78 * 32
```

and that value reaches the wire as the session id (`wire=id len=32 7878...`). So the
content of the stale read is attacker-chosen and its length is attacker-chosen — when the
bin reuse happens to be an array value string. That is a real capability, and it is why the
`len=5` reads print our part names: same mechanism, different string.

**(b) Why the HashTable never lands there — and why the "same size class" argument in §10.3
was necessary but not sufficient.** A 16-element `HashTable` struct is 56 B and a 32-character
string header is 57 B, so both round into the same 64-byte bin — §10.3 called this collision
possible and the `value_size=256` runs showed it happening. But *sharing a bin* only means
the table *could* win; it says nothing about who wins. In these requests the matching-class
strings outnumber matching-class tables by roughly a hundred to one: every part name and
every element value is a string, while the request builds one or two tables. The bin head is
therefore taken by a string in essentially every request, and the read lands on a string
header rather than a table. That is a quantitative explanation of the blocker, not a new
observation about the allocator.

**(c) The bin-steering variant also failed.** If strings win because there are more of them,
remove them: keep every string in the body out of the 64-byte bin (id length 8, scalar and
element values 8 or 16, so the smallest strings round to 32 or 48) and leave the table as the
only 64-byte candidate. Four configurations, three stale, one healthy, **0 wins**. The reads
that did occur were the `4294967297` garbage shape or a `len=5` part name, i.e. the bin went
to a string anyway (a part name is 9 bytes, 34 B with the header, which rounds to 48 — so
something else was taking it) or to nothing recognisable. Removing the obvious competitors
did not hand the bin to the table.

**(d) What this does and does not establish.** It establishes that the pad is stable enough to
groom, that the dangling chunk is reliably reused by strings the same request supplies, and
that the read's length and content can be chosen when the reuse is an array value. It does
not establish a route to the `0x10` shift. Four hypotheses were tried across §10.3–§10.5 —
producer geometry, offset position, two PoC knobs, and bin competition — and the shift
appeared in none of them. The next step is therefore not another geometry sweep; it is a
question about the mechanism itself. Either the reference PoC's `0x10` shift comes from an
allocation path these bodies never exercise (its `heap_consumer()` sends a 79-byte value
whose payload *is* a forged header, which is a different request shape from ours), or the
"real `HashTable` at `PS(id)-0x10`" reading of its own numbers is wrong. Reading
`stealmybitcoin_poc.py:228-245` against a live run of *its* request shape is the cheap way to
decide, and it is the only step left that can distinguish those two.

Reproduce: `step4_occupy.py` (writes `occupy.log`, per-run server logs under `occupy-logs/`).
Total step-4 pool runs to date: 196 (92 §10.3, 54 §10.4, 46 + 4 here).
