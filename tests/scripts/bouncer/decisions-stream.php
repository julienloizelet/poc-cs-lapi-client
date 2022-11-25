<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\Constants;

$startup = isset($argv[1]) ? (bool) $argv[1] : false;
$filter = isset($argv[2]) ? json_decode($argv[2], true)
    : ['scopes' => [Constants::SCOPE_IP, Constants::SCOPE_RANGE]];

if (is_null($filter)) {
    exit('Param <FILTER_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php decisions-stream.php <STARTUP> <FILTER_JSON>'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Instantiate bouncer ...' . \PHP_EOL;
// Config to use an Api Key for connection
$apiKeyConfigs = [
    'auth_type' => 'api_key',
    'api_url' => 'https://crowdsec:8080',
    'api_key' => '6a20918e3cb13f622160688b1848397d',
];
// Config to use TLS for connection
$tlsConfigs = [
    'auth_type' => 'tls',
    'user_agent_suffix' => 'LapiClientTest',
    'tls_cert_path' => '/var/www/html/cfssl/bouncer.pem',
    'tls_key_path' => '/var/www/html/cfssl/bouncer-key.pem',
    'tls_verify_peer' => true,
    'tls_ca_cert_path' => '/var/www/html/cfssl/ca-chain.pem',
    ];
$client = new Bouncer($apiKeyConfigs);
echo 'Bouncer instantiated' . \PHP_EOL;

echo 'Calling ' . $client->getConfig('api_url') . ' for decisions stream ...' . \PHP_EOL;
$response = $client->getStreamDecisions($startup, $filter);
echo 'Decisions stream response is:' . json_encode($response) . \PHP_EOL;
