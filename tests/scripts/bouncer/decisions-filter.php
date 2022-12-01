<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use CrowdSec\LapiClient\Bouncer;

$filter = isset($argv[1]) ? json_decode($argv[1], true) : [];

if (is_null($filter)) {
    exit('Param <FILTER_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php decisions-filter.php <STARTUP> <FILTER_JSON>'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Instantiate bouncer ...' . \PHP_EOL;
// Config to use an Api Key for connection
$apiKeyConfigs = [
    'auth_type' => 'api_key',
    'api_url' => 'https://crowdsec:8080',
    'api_key' => 'fc7a41bc16a3d6bb87e1696936a6a28a',
];
// Config to use TLS for connection
$tlsConfigs = [
    'auth_type' => 'tls',
    'api_url' => 'https://crowdsec:8080',
    'user_agent_suffix' => 'LapiClientTest',
    'tls_cert_path' => '/var/www/html/cfssl/bouncer.pem',
    'tls_key_path' => '/var/www/html/cfssl/bouncer-key.pem',
    'tls_verify_peer' => true,
    'tls_ca_cert_path' => '/var/www/html/cfssl/ca-chain.pem',
];
$client = new Bouncer($apiKeyConfigs);
echo 'Bouncer instantiated' . \PHP_EOL;

echo 'Calling ' . $client->getConfig('api_url') . ' for decisions ...' . \PHP_EOL;
echo 'Filter: ';
print_r(json_encode($filter));
$response = $client->getFilteredDecisions($filter);
echo \PHP_EOL . 'Decisions response is:' . json_encode($response) . \PHP_EOL;
