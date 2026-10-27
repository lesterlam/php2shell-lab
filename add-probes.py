#!/usr/bin/env python3
"""Add two observation probes to ext/session/session.c (idempotent).

Why: probe A sits *below* the `if (SG(headers_sent)) return FAILURE;` guard in
php_session_send_cookie(), so whenever PHP emits a warning before sending
headers the probe never fires and a run looks like "no cookie, no data" even
though PS(id) was dereferenced. The fit sweep lost 28 of 32 configs to exactly
that blind spot.

  probe A0 - entry of php_session_send_cookie(), before the headers guard.
             Recovers every call, including the ones that bail out.
  probe D  - ppid2sid(), right after PS(id) is built from the upload-progress
             field. Shows the adopted id string's address, length and gc
             header, i.e. which Zend MM class it landed in.

Usage: add-probes.py /path/to/php-src
"""
import sys

A0 = '''\t/* --- PHP2SHELL LAB INSTRUMENTATION (probe A0: entry, before the headers guard) --- */
\tif (PS(id)) {
\t\tconst unsigned char *d0 = (const unsigned char *) ZSTR_VAL(PS(id));
\t\tsize_t n0 = ZSTR_LEN(PS(id));
\t\tsize_t i0;
\t\tfprintf(stderr, "[INSTR-A0] entry PS(id)=%p val=%p len=%zu gc_refcount=%u gc_type=0x%x send_cookie=%d headers_sent=%d\\n",
\t\t\t(void *) PS(id), (void *) ZSTR_VAL(PS(id)), n0,
\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->refcount,
\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->u.type_info,
\t\t\t(int) PS(send_cookie), (int) SG(headers_sent));
\t\tfprintf(stderr, "[INSTR-A0] bytes(%zu):", n0 < 64 ? n0 : 64);
\t\tfor (i0 = 0; i0 < n0 && i0 < 64; i0++) fprintf(stderr, " %02x", d0[i0]);
\t\tfprintf(stderr, "\\n");
\t\tfflush(stderr);
\t}
'''

D = '''\t\t/* --- PHP2SHELL LAB INSTRUMENTATION (probe D: adopted upload-progress id) --- */
\t\tfprintf(stderr, "[INSTR-D] ppid2sid PS(id)=%p val=%p len=%zu gc_refcount=%u gc_type=0x%x\\n",
\t\t\t(void *) PS(id), (void *) ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)),
\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->refcount,
\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->u.type_info);
\t\tfflush(stderr);
'''

ANCHOR_A0 = "\tzend_string *e_id;\n\n\tif (SG(headers_sent)) {\n"
ANCHOR_D = ("\tif (Z_TYPE_P(ppid) == IS_STRING) {\n"
            "\t\tPS(id) = zend_string_init(Z_STRVAL_P(ppid), Z_STRLEN_P(ppid), 0);\n"
            "\t\tPS(send_cookie) = 0;\n")


def main():
    src = sys.argv[1]
    path = src + "/ext/session/session.c"
    s = open(path, encoding="utf-8").read()
    changed = []

    if "INSTR-A0" in s:
        print("probe A0 already present")
    else:
        if s.count(ANCHOR_A0) != 1:
            print("ANCHOR_A0 not unique (%d) -> abort" % s.count(ANCHOR_A0))
            return 1
        s = s.replace(ANCHOR_A0, "\tzend_string *e_id;\n\n" + A0 + "\n\tif (SG(headers_sent)) {\n")
        changed.append("A0")

    if "INSTR-D" in s:
        print("probe D already present")
    else:
        if s.count(ANCHOR_D) != 1:
            print("ANCHOR_D not unique (%d) -> abort" % s.count(ANCHOR_D))
            return 1
        s = s.replace(ANCHOR_D, ANCHOR_D + D)
        changed.append("D")

    if changed:
        open(path, "w", encoding="utf-8").write(s)
    print("patched: %s" % (", ".join(changed) or "nothing"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
