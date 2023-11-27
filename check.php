<?php
$domain = 'www.example.com'; // replace with your domain
$get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
$read = stream_socket_client("ssl://".$domain.":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
$cert = stream_context_get_params($read);
$certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
$validTo = date('Y-m-d', $certinfo['validTo_time_t']);

$now = new DateTime();
$expiryDate = new DateTime($validTo);
$interval = $now->diff($expiryDate);

echo "The SSL certificate for " . $domain . " expires in " . $interval->format('%a days');
