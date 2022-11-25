<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\RequestHandler;

use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\HttpMessage\Request;
use CrowdSec\LapiClient\HttpMessage\Response;

/**
 * Curl request handler.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class Curl implements RequestHandlerInterface
{
    /**
     * {@inheritdoc}
     *
     * @throws ClientException
     */
    public function handle(Request $request): Response
    {
        $handle = curl_init();

        $curlOptions = $this->createOptions($request);
        curl_setopt_array($handle, $curlOptions);

        $response = $this->exec($handle);

        if (false === $response) {
            throw new ClientException('Unexpected CURL call failure: ' . curl_error($handle), 500);
        }

        $statusCode = $this->getResponseHttpCode($handle);
        if (empty($statusCode)) {
            throw new ClientException('Unexpected empty response http code');
        }

        curl_close($handle);

        return new Response((string) $response, $statusCode);
    }

    /**
     * @codeCoverageIgnore
     *
     * @param mixed $handle
     *
     * @return bool|string
     */
    protected function exec($handle)
    {
        return curl_exec($handle);
    }

    /**
     * @codeCoverageIgnore
     *
     * @param mixed $handle
     *
     * @return mixed
     */
    protected function getResponseHttpCode($handle)
    {
        return curl_getinfo($handle, \CURLINFO_HTTP_CODE);
    }

    /**
     * Retrieve Curl options.
     *
     * @throws ClientException
     */
    private function createOptions(Request $request): array
    {
        $headers = $request->getHeaders();
        $method = $request->getMethod();
        $url = $request->getUri();
        $parameters = $request->getParams();
        $configs = $request->getConfigs();
        if (!isset($headers['User-Agent'])) {
            throw new ClientException('User agent is required', 400);
        }
        $options = [
            \CURLOPT_HEADER => false,
            \CURLOPT_RETURNTRANSFER => true,
            \CURLOPT_USERAGENT => $headers['User-Agent'],
        ];

        $options[\CURLOPT_HTTPHEADER] = [];
        foreach ($headers as $key => $values) {
            foreach (\is_array($values) ? $values : [$values] as $value) {
                $options[\CURLOPT_HTTPHEADER][] = sprintf('%s:%s', $key, $value);
            }
        }

        $options[\CURLOPT_SSL_VERIFYPEER] = false;
        if (isset($configs['auth_type']) && Constants::AUTH_TLS === $configs['auth_type']) {
            $verifyPeer = $configs['tls_verify_peer'] ?? true;
            $options[\CURLOPT_SSL_VERIFYPEER] = $verifyPeer;
            //   The --cert option
            $options[\CURLOPT_SSLCERT] = $configs['tls_cert_path'] ?? '';
            // The --key option
            $options[\CURLOPT_SSLKEY] = $configs['tls_key_path'] ?? '';
            if ($verifyPeer) {
                // The --cacert option
                $options[\CURLOPT_CAINFO] = $configs['tls_ca_cert_path'] ?? '';
            }
        }

        if ('POST' === strtoupper($method)) {
            $options[\CURLOPT_POST] = true;
            $options[\CURLOPT_CUSTOMREQUEST] = 'POST';
            $options[\CURLOPT_POSTFIELDS] = json_encode($parameters);
        } elseif ('GET' === strtoupper($method)) {
            $options[\CURLOPT_POST] = false;
            $options[\CURLOPT_CUSTOMREQUEST] = 'GET';
            $options[\CURLOPT_HTTPGET] = true;

            if (!empty($parameters)) {
                $url .= strpos($url, '?') ? '&' : '?';
                $url .= http_build_query($parameters);
            }
        }

        $options[\CURLOPT_URL] = $url;

        return $options;
    }
}
