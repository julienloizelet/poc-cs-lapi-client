<?php

require_once __DIR__ . '/../../../../vendor/autoload.php';

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\RequestHandler\FileGetContents;

$filter = isset($argv[1]) ? json_decode($argv[1], true) : [];

if (is_null($filter)) {
    exit('Param <FILTER_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php decisions-stream.php <STARTUP> <FILTER_JSON>'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Instantiate bouncer ...' . \PHP_EOL;
echo \PHP_EOL . 'Instantiate custom request handler ...' . \PHP_EOL;
$customRequestHandler = new FileGetContents();
$configs = [
    'auth_type' => 'tls',
    'api_url' => 'https://crowdsec:8080',
    'api_key' => '6a20918e3cb13f622160688b1848397d',
    'user_agent_suffix' => 'LapiClientTest',
    'tls_cert_path' => '/var/www/html/cfssl/bouncer.pem',
    'tls_key_path' => '/var/www/html/cfssl/bouncer-key.pem',
    'tls_verify_peer' => true,
    'tls_ca_cert_path' => '/var/www/html/cfssl/ca-chain.pem',
    ];
$client = new Bouncer($configs, $customRequestHandler);
echo 'Bouncer instantiated' . \PHP_EOL;

echo 'Calling ' . $client->getConfig('api_url') . ' for decisions ...' . \PHP_EOL;
echo 'Filter: ';
print_r(json_encode($filter));
$response = $client->getDecisions($filter);
echo \PHP_EOL . 'Decisions response is:' . json_encode($response) . \PHP_EOL;
