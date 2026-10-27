<?php
/*
 * Readiness check. Not part of the attack -- read-only, prints INI values.
 *
 * Stage 2's only observable is the `Set-Cookie: PHPSESSID=...` response header,
 * and that header appears only if PHP's multipart upload-progress callback runs
 * during request startup. On a SAPI where that path is not wired up, every
 * follow-up request returns no cookie at all -- which is indistinguishable from
 * "the bug did not reproduce". Hit this endpoint first to tell those apart.
 *
 * Expected on a working cli-server lab:
 *   sapi=cli-server   upload_progress.enabled=1   file_uploads=1
 *
 * Two values that are easy to misread:
 *
 *   session_status=1   -- 1 is PHP_SESSION_NONE. The callback runs before any
 *                         application code, and this script never calls
 *                         session_start().
 *
 *   _SESSION_set=no    -- a session really was started and flushed during
 *                         startup (you can see it in the response header), but
 *                         $_SESSION is not left behind in this script's
 *                         globals. The bug is therefore not observable from
 *                         inside the application, only from the response --
 *                         which is why stage2.py reads the header, not $_SESSION.
 *
 * No session path, no host paths, no session contents: deliberately trimmed so
 * this can sit on a public demo without disclosing anything.
 */
header('Content-Type: text/plain');
echo "sapi=", PHP_SAPI, "\n";
echo "upload_progress.enabled=", ini_get('session.upload_progress.enabled'), "\n";
echo "upload_progress.name=", ini_get('session.upload_progress.name'), "\n";
echo "file_uploads=", ini_get('file_uploads'), "\n";
echo "session_status=", session_status(), " (1=none, 2=active)\n";
echo "_SESSION_set=", (isset($GLOBALS['_SESSION']) ? 'yes' : 'no'), "\n";
echo "POST_keys=", implode(',', array_keys($_POST)), "\n";
echo "peak=", memory_get_peak_usage(true), "\n";
