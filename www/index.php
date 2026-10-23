<?php
// Plain text probe endpoint. Prints what the request actually cost in memory
// and whether application code was reached at all.
header('Content-Type: text/plain');
echo "REACHED_APP\n";
echo "php=".PHP_VERSION."\n";
echo "memory_limit=".ini_get('memory_limit')."\n";
echo "post_max_size=".ini_get('post_max_size')."\n";
echo "peak=".memory_get_peak_usage(true)."\n";
echo "post_keys=".count($_POST)."\n";
echo "file_keys=".count($_FILES)."\n";
