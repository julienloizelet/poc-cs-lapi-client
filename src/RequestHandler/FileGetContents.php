<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\RequestHandler;

use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\HttpMessage\Request;
use CrowdSec\LapiClient\HttpMessage\Response;

/**
 * File_get_contents request handler.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class FileGetContents implements RequestHandlerInterface
{
    /**
     * {@inheritdoc}
     *
     * @throws ClientException
     */
    public function handle(Request $request): Response
    {
        $config = $this->createContextConfig($request);
        $context = stream_context_create($config);

        $method = $request->getMethod();
        $parameters = $request->getParams();
        $url = $request->getUri();

        if ('GET' === strtoupper($method)) {
            if (!empty($parameters)) {
                $url .= strpos($url, '?') ? '&' : '?';
                $url .= http_build_query($parameters);
            }
        }

        $fullResponse = $this->exec($url, $context);
        $responseBody = (isset($fullResponse['response'])) ? $fullResponse['response'] : false;
        if (false === $responseBody) {
            throw new ClientException('Unexpected HTTP call failure.', 500);
        }
        $responseHeaders = (isset($fullResponse['header'])) ? $fullResponse['header'] : [];
        $parts = !empty($responseHeaders) ? explode(' ', $responseHeaders[0]) : [];
        $status = $this->getResponseHttpCode($parts);

        return new Response($responseBody, $status);
    }

    /**
     * @codeCoverageIgnore
     *
     * @param resource $context
     */
    protected function exec(string $url, $context): array
    {
        return ['response' => file_get_contents($url, false, $context), 'header' => $http_response_header];
    }

    /**
     * @param string[] $parts
     *
     * @psalm-param list<string> $parts
     */
    protected function getResponseHttpCode(array $parts): int
    {
        $status = 0;
        if (\count($parts) > 1) {
            $status = (int) $parts[1];
        }

        return $status;
    }

    /**
     * Convert a key-value array of headers to the official HTTP header string.
     */
    private function convertHeadersToString(array $headers): string
    {
        $builtHeaderString = '';
        foreach ($headers as $key => $value) {
            $builtHeaderString .= "$key: $value\r\n";
        }

        return $builtHeaderString;
    }

    /**
     * Retrieve configuration for the stream content.
     *
     * @return array|array[]
     *
     * @throws ClientException
     */
    private function createContextConfig(Request $request): array
    {
        $headers = $request->getHeaders();
        if (!isset($headers['User-Agent'])) {
            throw new ClientException('User agent is required', 400);
        }
        $header = $this->convertHeadersToString($headers);
        $method = $request->getMethod();
        $configs = $request->getConfigs();
        $config = [
            'http' => [
                'method' => $method,
                'header' => $header,
                'ignore_errors' => true,
            ],
        ];

        $config['ssl'] = ['verify_peer' => false];
        if (isset($configs['auth_type']) && Constants::AUTH_TLS === $configs['auth_type']) {
            $verifyPeer = $configs['tls_verify_peer'] ?? true;
            $config['ssl'] = [
                'verify_peer' => $verifyPeer,
                'local_cert' => $configs['tls_cert_path'] ?? '',
                'local_pk' => $configs['tls_key_path'] ?? '',
            ];
            if ($verifyPeer) {
                $config['ssl']['cafile'] = $configs['tls_ca_cert_path'] ?? '';
            }
        }

        if ('POST' === strtoupper($method)) {
            $config['http']['content'] = json_encode($request->getParams());
        }

        return $config;
    }
}