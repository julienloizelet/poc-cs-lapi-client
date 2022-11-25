<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\HttpMessage;

/**
 * Request that will be sent to CAPI.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class Request extends AbstractMessage
{
    /**
     * @var array
     */
    protected $headers = [
        'Accept' => 'application/json',
        'Content-Type' => 'application/json',
    ];
    /**
     * @var array
     */
    private $configs;
    /**
     * @var string
     */
    private $method;
    /**
     * @var array
     */
    private $parameters;
    /**
     * @var string
     */
    private $uri;

    public function __construct(
        string $uri,
        string $method,
        array $headers = [],
        array $parameters = [],
        array $configs = [])
    {
        $this->uri = $uri;
        $this->method = $method;
        $this->headers = array_merge($this->headers, $headers);
        $this->parameters = $parameters;
        $this->configs = $configs;
    }

    public function getConfigs(): array
    {
        return $this->configs;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getParams(): array
    {
        return $this->parameters;
    }

    public function getUri(): string
    {
        return $this->uri;
    }
}
