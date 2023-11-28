<?php

const TEMPLATE = <<<TEMPLATE
# SSL expiration monitoring

**Checked on %s**

| Domain | Remained | Status       |
|--------|----------|--------------|

TEMPLATE;

class SSLCertificateMonitor
{

    private $expiryLimit;
    private $domains;
    private $template;

    public function __construct()
    {
        $this->domains = explode(',', getenv('DOMAINS'));
        $this->expiryLimit = getenv("EXPIRATION_LIMIT");
        date_default_timezone_set('Asia/Tehran');
        $this->template = sprintf(TEMPLATE, date('Y-m-d H:i'));
    }

    public function getSSLCertificate(string $domain)
    {
        $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
        $read = stream_socket_client("ssl://" . $domain . ":443", $errno, $errstr, 4, STREAM_CLIENT_CONNECT, $get);

        if ($read === false) {
            throw new Exception("Failed to connect: $errstr ($errno)");
        }

        $cert = stream_context_get_params($read);
        return openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
    }

    public function getDaysTillExpiry(array $certinfo)
    {
        $validTo = date('Y-m-d', $certinfo['validTo_time_t']);

        $now = new DateTime();
        $expiryDate = new DateTime($validTo);
        $interval = $now->diff($expiryDate);

        return $interval->format('%a');
    }

    public function monitor()
    {
        foreach ($this->domains as $domain) {
            try {
                $certinfo = $this->getSSLCertificate($domain);
                $daysTillExpiry = $this->getDaysTillExpiry($certinfo);
                $this->template .= sprintf("| %s     | %d Day   | %s |" . PHP_EOL, $domain, $daysTillExpiry, $daysTillExpiry > $this->expiryLimit ? "✅" : "❌");
                if ($daysTillExpiry > $this->expiryLimit) {
                    echo "The SSL certificate for " . $domain . " expires in " . $daysTillExpiry . " days" . PHP_EOL;
                } else {
                    if ($daysTillExpiry > 0) {
                        echo "WARNING! The SSL certificate for " . $domain . " will be expired soon." . PHP_EOL;
                    } else {
                        echo "WARNING! The SSL certificate for " . $domain . " has expired." . PHP_EOL;
                    }
                }
            } catch (Exception $e) {
                $this->template .= sprintf("| %s     | %s       | %s |" . PHP_EOL, $domain, $e->getMessage(), "❌");
                echo "ERROR! May $domain has expired: " . $e->getMessage() . PHP_EOL;
            }

            file_put_contents(__DIR__ . "/README.md", $this->template);
        }
    }
}

$monitor = new SSLCertificateMonitor();
$monitor->monitor();