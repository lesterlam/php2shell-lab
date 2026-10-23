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
| Fix commit | `506e87fa` — "Avoid state corruption via bailout" |
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

## 6. Limitations of this reproduction

What is demonstrated is the pre-condition and the vulnerable/patched delta, plus
the root cause from the source diff. What is **not** demonstrated is the
weaponised RCE. Reaching control-flow hijack additionally requires:

1. Controlling the *content*, *location* and *timing* of the corrupted memory
   (heap grooming against both glibc malloc and Zend's own allocator).
2. A value that is used as a pointer, length or index rather than merely read —
   plus an information leak to defeat ASLR/PIE.
3. Bypassing NX (ROP), stack canaries and CET/shadow stack.
4. Doing all of the above reliably across a multi-worker prefork pool.

There is no public proof-of-concept. This lab, and the honest ceiling on what it
can show, stop at the boundary above.

## 7. Mitigation

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
