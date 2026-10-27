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
on this layout the read stays inside a buffer the attacker supplied.

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

## 7. Limitations of this reproduction

What is demonstrated is the pre-condition, the vulnerable/patched delta, the
root cause from the source diff, and the stale-state consequences measured in
section 6. What is **not** demonstrated is the weaponised RCE. Reaching
control-flow hijack additionally requires:

1. Controlling the *content*, *location* and *timing* of the corrupted memory
   (heap grooming against both glibc malloc and Zend's own allocator).
2. A value that is used as a pointer, length or index rather than merely read —
   plus an information leak to defeat ASLR/PIE.
3. Bypassing NX (ROP), stack canaries and CET/shadow stack.
4. Doing all of the above reliably across a multi-worker prefork pool.

A public proof of concept does exist — see section 6.5 and 6.7. What this lab
takes from it is the stale-state primitive; what it does not take is the command
execution, which needs the decoupling and the leak listed above. Section 6.6
records the parts of that PoC that did not reproduce here, because a negative
result dated to this build is more useful than an assumed one.

## 8. Mitigation

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
