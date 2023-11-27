<?php

$domains = require_once __DIR__ . "/domains.php";
$template = file_get_contents(__DIR__ . "/template.md");
date_default_timezone_set('Asia/Tehran');

function getSSLCertificate(string $domain)
{
    $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
    $read = stream_socket_client("ssl://" . $domain . ":443", $errno, $errstr, 4, STREAM_CLIENT_CONNECT, $get);

    if ($read === false) {
        throw new Exception("Failed to connect: $errstr ($errno)");
    }

    $cert = stream_context_get_params($read);
    return openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
}

function getDaysTillExpiry(array $certinfo)
{
    $validTo = date('Y-m-d', $certinfo['validTo_time_t']);

    $now = new DateTime();
    $expiryDate = new DateTime($validTo);
    $interval = $now->diff($expiryDate);

    return $interval->format('%a');
}

$template = sprintf($template, date('Y-m-d H:i'));

foreach ($domains as $domain) {
    try {
        $certinfo = getSSLCertificate($domain);
        $daysTillExpiry = getDaysTillExpiry($certinfo);
        echo "The SSL certificate for " . $domain . " expires in " . $daysTillExpiry . " days" . PHP_EOL;
        $template .= sprintf("| %s     | %d Day   | %s |" . PHP_EOL, $domain, $daysTillExpiry, $daysTillExpiry > 10 ? "✅" : "❌");
    } catch (Exception $e) {
        $template .= sprintf("| %s     | %s       | %s |" . PHP_EOL, $domain, $e->getMessage(), "❌");
        echo "Error: " . $e->getMessage() . PHP_EOL;
    }

    file_put_contents(__DIR__ . "/README.md", $template);
}
echo "DONE.";
