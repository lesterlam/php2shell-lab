#!/usr/bin/env python3
"""Add the three address probes to a php-src tree.

Without these the alignment search is guesswork: you can see *what* PHP emitted
but not *where* the stale pointer landed relative to the buffers you control.
With them, the question becomes subtraction.

Probes (anchored text insertion, so it survives unrelated edits):

  A  ext/session/session.c  php_session_send_cookie(), immediately before the
     URL-encode of PS(id) -- prints PS(id), ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)),
     the zend_string header, and the first bytes about to be emitted.

  B  ext/session/session.c  the rfc1867 handler's MULTIPART_EVENT_START -- prints
     PS(id) as the upload-progress path sees it, i.e. before the session starts.

  C  main/php_variables.c  php_register_variable_ex() -- prints the address and
     length of every POST field value we control. Values are recognised by their
     first four bytes being ``PPPP`` (what stage3.py sends), so this fires only
     for the buffers the experiment cares about.

Usage:
    ./instrument-php.py <php-src-dir>          instrument a tree
    ./instrument-php.py --check <php-src-dir>  report which probes are present

Refuses to instrument a tree twice. Use --check to detect a *partially*
instrumented tree: a run interrupted between probes leaves one probe in place,
and a naive "is the marker there?" test will then skip the rest.
"""
import os
import sys

MARK = "PHP2SHELL LAB INSTRUMENTATION"

# probe A -- the length lie is read here
ANCHOR_A = (
    "\t/* URL encode id because it might be user supplied */\n"
    "\te_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));\n"
)
PROBE_A = (
    "\t/* --- " + MARK + " (probe A) --- */\n"
    "\tif (PS(id)) {\n"
    "\t\tconst unsigned char *d = (const unsigned char *) ZSTR_VAL(PS(id));\n"
    "\t\tsize_t n = ZSTR_LEN(PS(id));\n"
    "\t\tsize_t i;\n"
    "\t\tfprintf(stderr, \"[INSTR-A] PS(id)=%p val=%p len=%zu gc_refcount=%u gc_type=0x%x\\n\",\n"
    "\t\t\t(void *) PS(id), (void *) ZSTR_VAL(PS(id)), n,\n"
    "\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->refcount,\n"
    "\t\t\t(unsigned) ((zend_refcounted_h *) PS(id))->u.type_info);\n"
    "\t\tfprintf(stderr, \"[INSTR-A] bytes(%zu):\", n < 64 ? n : 64);\n"
    "\t\tfor (i = 0; i < n && i < 64; i++) fprintf(stderr, \" %02x\", d[i]);\n"
    "\t\tfprintf(stderr, \"\\n\");\n"
    "\t\tfflush(stderr);\n"
    "\t}\n"
)

# probe B -- PS(id) before the session is (re)started
ANCHOR_B = "\t\tcase MULTIPART_EVENT_START: {\n"
PROBE_B = (
    ANCHOR_B +
    "\t\t\t/* --- " + MARK + " (probe B) --- */\n"
    "\t\t\tfprintf(stderr, \"[INSTR-B] rfc1867 START: PS(id)=%p status=%d\\n\",\n"
    "\t\t\t\tPS(id) ? (void *) PS(id) : NULL, (int) PS(session_status));\n"
    "\t\t\tfflush(stderr);\n"
)

# probe C -- where our controlled buffers live
ANCHOR_C = (
    "PHPAPI void php_register_variable_ex(const char *var_name, zval *val, zval *track_vars_array)\n"
    "{\n"
)
PROBE_C = (
    ANCHOR_C +
    "\t/* --- " + MARK + " (probe C): address of every controlled field value --- */\n"
    "\tif (val && Z_TYPE_P(val) == IS_STRING && Z_STRLEN_P(val) >= 32\n"
    "\t    && Z_STRVAL_P(val)[0] == 'P' && Z_STRVAL_P(val)[1] == 'P'\n"
    "\t    && Z_STRVAL_P(val)[2] == 'P' && Z_STRVAL_P(val)[3] == 'P') {\n"
    "\t\tfprintf(stderr, \"[INSTR-C] field name=%-8s val=%p len=%zu\\n\",\n"
    "\t\t\tvar_name, (void *) Z_STRVAL_P(val), Z_STRLEN_P(val));\n"
    "\t\tfflush(stderr);\n"
    "\t}\n"
)

EDITS = [
    ("ext/session/session.c", ANCHOR_A, PROBE_A + ANCHOR_A, "probe A (send_cookie)"),
    ("ext/session/session.c", ANCHOR_B, PROBE_B, "probe B (rfc1867 START)"),
    ("main/php_variables.c", ANCHOR_C, PROBE_C, "probe C (register_variable_ex)"),
]


PROBE_TAGS = [
    ("ext/session/session.c", "(probe A)", "send_cookie"),
    ("ext/session/session.c", "(probe B)", "rfc1867 START"),
    ("main/php_variables.c", "(probe C)", "register_variable_ex"),
]


def check(root):
    """Exit 0 only if every probe is present in its file."""
    missing = []
    for path, tag, label in PROBE_TAGS:
        try:
            src = open(root + path, encoding="utf-8").read()
        except OSError:
            missing.append("%s (%s)" % (label, path))
            continue
        if tag not in src:
            missing.append("%s (%s)" % (label, path))
    if missing:
        print("missing probes: %s" % ", ".join(missing))
        return 1
    print("all probes present")
    return 0


def main():
    args = [a for a in sys.argv[1:] if a != "--check"]
    want_check = "--check" in sys.argv[1:]
    if len(args) != 1:
        sys.exit(__doc__.strip())
    root = args[0].rstrip("/") + "/"
    if want_check:
        sys.exit(check(root))
    if not os.path.isfile(root + "main/php_variables.c"):
        sys.exit("not a php-src tree: %s" % root)

    # The guard has to be evaluated once per file, before any edit: two probes
    # share session.c, so a per-edit check would trip on our own first insertion.
    files = {}
    for path, _anchor, _replacement, _label in EDITS:
        if path not in files:
            src = open(root + path, encoding="utf-8").read()
            if MARK in src:
                sys.exit("%s already instrumented -- re-extract the tarball first" % path)
            files[path] = src

    for path, anchor, replacement, label in EDITS:
        src = files[path]
        if anchor not in src:
            sys.exit("anchor not found in %s (%s) -- wrong PHP version?" % (path, label))
        files[path] = src.replace(anchor, replacement, 1)
        print("  %-22s %s" % (path, label))

    for path, src in files.items():
        open(root + path, "w", encoding="utf-8").write(src)

    print("\nmarker count per file:")
    for path in ("ext/session/session.c", "main/php_variables.c"):
        n = open(root + path, encoding="utf-8").read().count(MARK)
        print("  %-22s %d" % (path, n))


if __name__ == "__main__":
    main()
