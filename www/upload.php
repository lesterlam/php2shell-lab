<?php
// A conventional file-upload endpoint.
//
// Note: the vulnerability is reached during PHP *request startup* (automatic
// body parsing), i.e. before any line of this file executes. If the response
// contains "REACHED_APP" the request survived parsing; if it does not, parsing
// aborted before application code was reached.
header('Content-Type: text/plain');
echo "REACHED_APP\n";
echo "peak=".memory_get_peak_usage(true)."\n";
echo "files=".count($_FILES)."\n";
foreach ($_FILES as $k => $f) {
    echo "file[$k]: name=".($f['name'] ?? '')." size=".($f['size'] ?? 0)."\n";
}
echo "post_keys=".count($_POST)."\n";
