<?php
// Observability for the FPM replay: print the session id PHP actually resolved,
// its length and raw bytes. A healthy id is 32 hex chars; a stale/dangling one
// shows up as 16 bytes or as non-hex garbage.
header('Content-Type: text/plain');
session_start();
$id = session_id();
echo "SID_LEN=".strlen($id)."\n";
echo "SID_HEX=".bin2hex($id)."\n";
echo "REACHED_APP\n";
echo "peak=".memory_get_peak_usage(true)."\n";
echo "post_keys=".count($_POST)."\n";
