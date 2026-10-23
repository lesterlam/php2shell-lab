# PHP2Shell Reproduction Lab

A minimal, dependency-light lab that reproduces the **trigger condition** behind
CVE-2026-109618 / CVE-2026-109619 — the October 2026 PHP core remote code
execution disclosed as "PHP2Shell" (CVSS 4.0 **9.2**).

The lab shows that a single unauthenticated HTTP request can exhaust PHP's
`memory_limit` while remaining far inside `post_max_size`, **during request
startup — before any application code executes**. That is the condition the PHP
security team describes as reachable to RCE on Apache `mod_php`.

## Scope

| | |
|---|---|
| ✅ Demonstrates | The unauthenticated OOM pre-condition, that it occurs before application code, and the behavioural difference between vulnerable and patched builds. |
| ❌ Does not demonstrate | A weaponised exploit. **No public proof-of-concept exists.** Turning the resulting invalid memory state into control-flow hijack additionally requires a specific allocator layout, heap grooming and a producer/consumer pair across requests. |

This is an educational / defensive-research artefact. Everything runs on
`127.0.0.1`. Do not point it at systems you do not own.

## Results

Measured on official builds, `memory_limit=64M`, `post_max_size=256M`.

**Memory amplification** — one part header on the wire vs. what it costs inside PHP:

| Part headers | Wire body | PHP peak | Ratio | Outcome |
|---:|---:|---:|---:|---|
| 10,000 | 189 KB | 4 MiB | 22× | 200 OK |
| 50,000 | 989 KB | 16 MiB | 17× | 200 OK |
| 100,000 | 1.99 MB | 32 MiB | 17× | 200 OK |
| 150,000 | 3.04 MB | 48 MiB | 17× | 200 OK |
| 200,000 | 4.09 MB | 62 MiB | 16× | 200 OK |
| 250,000 | **5.14 MB** | — | — | **OOM, application never ran** |

**Vulnerable vs. patched** — identical payloads:

| Part headers | PHP 8.4.26 (vulnerable) | PHP 8.4.27 (patched) |
|---:|---|---|
| 250,000 | OOM, application never ran | 200 OK, peak 2 MiB |
| 400,000 | OOM, application never ran | 200 OK, peak 2 MiB |
| 700,000 | OOM, application never ran | 200 OK, peak 2 MiB |

A 5 MB payload — under **2 % of `post_max_size`** — already exhausts a 64 MB
`memory_limit`. `post_max_size` permits 256 MB of wire data; at the measured
~17× amplification that is roughly **4.2 GiB of request memory, about 68× the
memory limit**. The patched build does not merely fail gracefully; it stops
retaining attacker-controlled part headers entirely.

## Quickstart

Requires Linux (x86_64 or aarch64), `bash`, `curl`, `python3`. **No Docker daemon
and no root required** — PHP is pulled straight from Docker Hub and run out of
its extracted rootfs.

```bash
./fetch-php.sh 8.4.26     # vulnerable  (~1.1 GB)
./fetch-php.sh 8.4.27     # patched     (~1.1 GB)
./demo.sh
```

`demo.sh` starts both builds, sends the same payload to each, and prints a
verdict per step:

```
>>> VERDICT: OOM DURING REQUEST STARTUP -- application code NEVER ran  >>> TRIGGERED <<<
```

Single-shot usage:

```bash
./phpv.sh 8.4.26 -d memory_limit=64M -d post_max_size=256M -S 127.0.0.1:8426 -t www &
./probe.py --port 8426 --headers 250000
```

## Why it works

PHP renders each MIME part header of a `multipart/form-data` body into a
hash-table entry (name and value as separate strings, plus a bucket). A header
that occupies ~20 bytes on the wire costs ~340 bytes of PHP request memory — a
steady **~17× amplification**. `post_max_size` limits wire bytes and
`memory_limit` limits RAM, so an attacker who controls only header *count* can
drive memory past the limit from inside the size limit.

Historically PHP handled OOM with `longjmp()`, which exits the current context
without unwinding. If the OOM lands while request memory is only temporarily
reachable, the request scope is left invalid and request shutdown reads or
branches on it. Apache `mod_php` runs request shutdown unconditionally, even
after a failed startup, which is why it is the confirmed-exploitable
configuration.

The patch (commit `506e87fa`, "Avoid state corruption via bailout") replaces the
`longjmp()` path with a delayed soft OOM at the next VM safe point plus a hard
`_exit()` at a second, higher threshold, and stops the multipart parser from
retaining unbounded attacker-controlled headers. See
[`docs/ANALYSIS.md`](docs/ANALYSIS.md).

## Repository layout

```
fetch-php.sh        pull + extract a PHP image via the Registry API (no daemon)
phpv.sh             run an extracted PHP with its own dynamic loader
probe.py            crafted multipart body + verdict
demo.sh             one-command A/B walkthrough
www/                minimal probe endpoints
docs/ANALYSIS.md    root-cause and patch analysis
docs/index.html     interactive visualiser (GitHub Pages)
runtimes/           downloaded PHP builds (gitignored)
```

## References

- CVE-2026-109618 — <https://www.cve.org/CVERecord?id=CVE-2026-109618>
- CVE-2026-109619 — <https://www.cve.org/CVERecord?id=CVE-2026-109619>
- GHSA-w8hw-w9fx-j79w — <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- GHSA-6wmf-4rv5-p3rp — <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- Fix commit — <https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf>

Fixed in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**.
