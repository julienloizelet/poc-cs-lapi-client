<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

/**
 * Test for watcher.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */

use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\HttpMessage\Response;
use CrowdSec\LapiClient\Storage\FileStorage;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;
use CrowdSec\LapiClient\Bouncer;

/**
 * @uses \CrowdSec\LapiClient\HttpMessage\Response
 * @uses \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @uses \CrowdSec\LapiClient\Bouncer::formatUserAgent
 * @uses \CrowdSec\LapiClient\Storage\FileStorage::__construct
 *
 * @covers \CrowdSec\LapiClient\AbstractClient::__construct
 * @covers \CrowdSec\LapiClient\AbstractClient::getConfig
 * @covers \CrowdSec\LapiClient\AbstractClient::getUrl
 * @covers \CrowdSec\LapiClient\AbstractClient::getRequestHandler
 * @covers \CrowdSec\LapiClient\AbstractClient::formatResponseBody
 * @covers \CrowdSec\LapiClient\AbstractClient::getFullUrl
 * @covers \CrowdSec\LapiClient\Bouncer::__construct
 * @covers \CrowdSec\LapiClient\Bouncer::configure
 */
final class AbstractClientTest extends AbstractClient
{
    public function testClientInit()
    {
        $client = new Bouncer($this->configs, new FileStorage());

        $url = $client->getUrl();
        $this->assertEquals(
            Constants::URL_DEV,
            $url,
            'Url should be dev by default'
        );
        $this->assertEquals(
            '/',
            substr($url, -1),
            'Url should end with /'
        );

        $requestHandler = $client->getRequestHandler();
        $this->assertEquals(
            'CrowdSec\LapiClient\RequestHandler\Curl',
            get_class($requestHandler),
            'Request handler must be curl by default'
        );

        $client = new Bouncer(array_merge($this->configs, ['env' => Constants::ENV_PROD]), new FileStorage());
        $url = $client->getUrl();
        $this->assertEquals(
            Constants::URL_PROD,
            $url,
            'Url should be prod if specified'
        );
        $this->assertEquals(
            '/',
            substr($url, -1),
            'Url should end with /'
        );

        $error = false;
        try {
            new Bouncer($this->configs, new FileStorage(), new \DateTime());
        } catch (\TypeError $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/must .*RequestHandlerInterface/',
            $error,
            'Bad request handler should throw an error'
        );
    }

    public function testPrivateOrProtectedMethods()
    {
        $client = new Bouncer($this->configs, new FileStorage());

        $fullUrl = PHPUnitUtil::callMethod(
            $client,
            'getFullUrl',
            ['/test-endpoint']
        );
        $this->assertEquals(
            Constants::URL_DEV . 'test-endpoint',
            $fullUrl,
            'Full Url should be ok'
        );

        $jsonBody = json_encode(['message' => 'ok']);

        $response = new Response($jsonBody, 200);

        $formattedResponse = ['message' => 'ok'];

        $validateResponse = PHPUnitUtil::callMethod(
            $client,
            'formatResponseBody',
            [$response]
        );
        $this->assertEquals(
            $formattedResponse,
            $validateResponse,
            'Array response should be valid'
        );

        $jsonBody = '{bad response]]]';
        $response = new Response($jsonBody, 200);
        $error = false;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'formatResponseBody',
                [$response]
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/not a valid json/',
            $error,
            'Bad JSON should be detected'
        );

        $response = new Response(MockedData::REGISTER_ALREADY, 200);

        $decodedResponse = PHPUnitUtil::callMethod(
            $client,
            'formatResponseBody',
            [$response]
        );

        $this->assertEquals(
            ['message' => 'User already registered.'],
            $decodedResponse,
            'Decoded response should be correct'
        );

        $response = new Response(MockedData::UNAUTHORIZED, 403);

        $error = false;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'formatResponseBody',
                [$response]
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/403.*Unauthorized/',
            $error,
            'Should throw error on 403'
        );

        $response = new Response('', 200);

        $error = false;
        $decoded = [];
        try {
            $decoded = PHPUnitUtil::callMethod(
                $client,
                'formatResponseBody',
                [$response]
            );
        } catch (ClientException $e) {
            $error = true;
        }

        $this->assertEquals(
            false,
            $error,
            'An empty response body should not throw error'
        );

        $this->assertEquals(
            ['message' => ''],
            $decoded,
            'An empty response body should not return some array'
        );

        $response = new Response('', 500);

        $error = false;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'formatResponseBody',
                [$response]
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/500.*/',
            $error,
            'An empty response body should throw error for bad status'
        );

        $error = false;
        try {
            new Response(['test'], 200);
        } catch (\TypeError $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/type .*string/',
            $error,
            'If response body is not a string it should throw error'
        );
    }
}
