<?php

/** @noinspection DuplicatedCode */

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

/**
 * Test for FGC request handler.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\HttpMessage\Request;
use CrowdSec\LapiClient\RequestHandler\FileGetContents;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;

/**
 * @uses \CrowdSec\LapiClient\AbstractClient
 * @uses \CrowdSec\LapiClient\HttpMessage\Request
 * @uses \CrowdSec\LapiClient\HttpMessage\Response
 * @uses \CrowdSec\LapiClient\HttpMessage\AbstractMessage
 * @uses \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @uses \CrowdSec\LapiClient\Bouncer::__construct
 * @uses \CrowdSec\LapiClient\Bouncer::configure
 * @uses \CrowdSec\LapiClient\Bouncer::formatUserAgent
 * @uses \CrowdSec\LapiClient\Bouncer::ensureAuth
 * @uses \CrowdSec\LapiClient\Bouncer::ensureRegister
 * @uses \CrowdSec\LapiClient\Bouncer::manageRequest
 * @uses \CrowdSec\LapiClient\Bouncer::shouldRefreshCredentials
 * @uses \CrowdSec\LapiClient\Bouncer::generateMachineId
 * @uses \CrowdSec\LapiClient\Bouncer::generatePassword
 * @uses \CrowdSec\LapiClient\Bouncer::generateRandomString
 * @uses \CrowdSec\LapiClient\Bouncer::refreshCredentials
 * @uses \CrowdSec\LapiClient\Bouncer::areEquals
 * @uses \CrowdSec\LapiClient\Storage\FileStorage::__construct
 *
 * @covers \CrowdSec\LapiClient\RequestHandler\FileGetContents::handle
 * @covers \CrowdSec\LapiClient\RequestHandler\FileGetContents::createContextConfig
 * @covers \CrowdSec\LapiClient\RequestHandler\FileGetContents::convertHeadersToString
 * @covers \CrowdSec\LapiClient\RequestHandler\FileGetContents::getResponseHttpCode
 * @covers \CrowdSec\LapiClient\Bouncer::login
 * @covers \CrowdSec\LapiClient\Bouncer::handleTokenHeader
 * @covers \CrowdSec\LapiClient\Bouncer::register
 * @covers \CrowdSec\LapiClient\Bouncer::login
 * @covers \CrowdSec\LapiClient\Bouncer::shouldLogin
 * @covers \CrowdSec\LapiClient\Bouncer::handleLogin
 * @covers \CrowdSec\LapiClient\Bouncer::pushSignals
 * @covers \CrowdSec\LapiClient\Bouncer::getStreamDecisions
 */
final class FileGetContentsTest extends AbstractClient
{
    public function testContextConfig()
    {
        $method = 'POST';
        $parameters = ['machine_id' => 'test', 'password' => 'test'];

        $fgcRequestHandler = new FileGetContents();

        $client = new Bouncer($this->configs, $fgcRequestHandler);
        $fgcRequester = $client->getRequestHandler();

        $request = new Request('test-url', $method, ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], $parameters);

        $contextConfig = PHPUnitUtil::callMethod(
            $fgcRequester,
            'createContextConfig',
            [$request]
        );

        $contextConfig['http']['header'] = str_replace("\r", '', $contextConfig['http']['header']);

        $expected = [
            'http' => [
                'method' => $method,
                'header' => 'Accept: application/json
Content-Type: application/json
User-Agent: ' . TestConstants::USER_AGENT_SUFFIX . '
',
                'ignore_errors' => true,
                'content' => '{"machine_id":"test","password":"test"}',
                'timeout' => Constants::API_TIMEOUT
            ],
            'ssl' => [
                'verify_peer' => false
            ]
        ];

        $this->assertEquals(
            $expected,
            $contextConfig,
            'Context config must be as expected for POST'
        );

        $method = 'GET';
        $parameters = ['foo' => 'bar', 'crowd' => 'sec'];

        $request = new Request('test-url', $method, ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], $parameters);

        $contextConfig = PHPUnitUtil::callMethod(
            $fgcRequester,
            'createContextConfig',
            [$request]
        );

        $contextConfig['http']['header'] = str_replace("\r", '', $contextConfig['http']['header']);

        $expected = [
            'http' => [
                'method' => $method,
                'header' => 'Accept: application/json
Content-Type: application/json
User-Agent: ' . TestConstants::USER_AGENT_SUFFIX . '
',
                'ignore_errors' => true,
                'timeout' => Constants::API_TIMEOUT
            ],
            'ssl' => [
                'verify_peer' => false
            ]
        ];

        $this->assertEquals(
            $expected,
            $contextConfig,
            'Context config must be as expected for GET'
        );
    }

    public function testDecisionsStream()
    {
        // Success test
        $mockFGCRequest = $this->getFGCMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::DECISIONS_STREAM_LIST,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK'],
                ]
            )
        );

        $client = new Bouncer($this->configs, $mockFGCRequest);
        $decisionsResponse = $client->getStreamDecisions(true);

        $this->assertEquals(
            json_decode(MockedData::DECISIONS_STREAM_LIST, true),
            $decisionsResponse,
            'Success get decisions stream'
        );
    }

    public function testFilteredDecisions()
    {
        // Success test
        $mockFGCRequest = $this->getFGCMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::DECISIONS_FILTER,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK'],
                ]
            )
        );

        $client = new Bouncer($this->configs, $mockFGCRequest);
        $decisionsResponse = $client->getFilteredDecisions();

        $this->assertEquals(
            json_decode(MockedData::DECISIONS_FILTER, true),
            $decisionsResponse,
            'Success get decisions stream'
        );
    }


    public function testHandleError()
    {
        $mockFGCRequest = $this->getFGCMock();

        $request = new Request('test-uri', 'POST', ['User-Agent' => null]);
        $error = false;
        try {
            $mockFGCRequest->handle($request);
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        $this->assertEquals(
            'User agent is required',
            $error,
            'Should failed and throw if no user agent'
        );

        $mockFGCRequest = $this->getFGCMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                ['header' => []]
            )
        );

        $request = new Request('test-uri', 'POST', ['User-Agent' => TestConstants::USER_AGENT_SUFFIX]);

        $code = 0;
        try {
            $mockFGCRequest->handle($request);
        } catch (ClientException $e) {
            $error = $e->getMessage();
            $code = $e->getCode();
        }

        $this->assertEquals(500, $code);

        $this->assertEquals(
            'Unexpected HTTP call failure.',
            $error,
            'Should failed and throw if no response'
        );
    }

    public function testHandleUrl()
    {
        $mockFGCRequest = $this->getFGCMock();

        $request = new Request('test-uri', 'GET', ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], ['foo' => 'bar']);

        $mockFGCRequest->method('exec')
            ->will(
                $this->returnValue(['response' => 'ok'])
            );

        $mockFGCRequest->expects($this->exactly(1))->method('exec')
            ->withConsecutive(
                ['test-uri?foo=bar']
            );
        $mockFGCRequest->handle($request);
    }

}
