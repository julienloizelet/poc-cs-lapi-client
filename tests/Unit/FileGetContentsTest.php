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

use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\HttpMessage\Request;
use CrowdSec\LapiClient\RequestHandler\FileGetContents;
use CrowdSec\LapiClient\Storage\FileStorage;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;
use CrowdSec\LapiClient\Bouncer;

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

        $client = new Bouncer($this->configs, new FileStorage(), $fgcRequestHandler);
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
            ],
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
            ],
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
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::DECISIONS_STREAM_LIST,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK'],
                ]
            )
        );

        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(
            TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
        );
        $mockFileStorage->method('retrieveToken')->willReturn(
            TestConstants::TOKEN
        );
        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);
        $mockFileStorage->method('retrieveScenarios')->willReturn(
            TestConstants::SCENARIOS
        );
        $decisionsResponse = $client->getStreamDecisions();

        $this->assertEquals(
            json_decode(MockedData::DECISIONS_STREAM_LIST, true),
            $decisionsResponse,
            'Success get decisions stream'
        );
    }

    public function testRefreshToken()
    {
        // Test refresh with good credential
        $mockFGCRequest = $this->getFGCMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                ['response' => MockedData::LOGIN_SUCCESS, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_200]]
            )
        );
        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID);
        $mockFileStorage->method('retrieveToken')->willReturn(null);

        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);
        PHPUnitUtil::callMethod(
            $client,
            'ensureAuth',
            []
        );
        $tokenHeader = PHPUnitUtil::callMethod(
            $client,
            'handleTokenHeader',
            []
        );

        $this->assertEquals(
            'Bearer this-is-a-token',
            $tokenHeader['Authorization'],
            'Header should be populated with token'
        );
        // Test refresh with bad credential
        $mockFGCRequest = $this->getFGCMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->willReturn(
            [
                'response' => MockedData::LOGIN_BAD_CREDENTIALS,
                'header' => ['HTTP/1.1 ' . MockedData::HTTP_400],
            ]
        );
        $mockFileStorage->method('retrievePassword')->willReturn(TestConstants::PASSWORD);
        $mockFileStorage->method('retrieveMachineId')->willReturn(TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID);
        $mockFileStorage->method('retrieveToken')->willReturn(null);
        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);

        $error = '';
        $code = 0;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'handleTokenHeader',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
            $code = $e->getCode();
        }

        $this->assertEquals(401, $code);

        PHPUnitUtil::assertRegExp(
            $this,
            '/Token is required/',
            $error,
            'No retrieved token should throw a ClientException error'
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

    public function testLogin()
    {
        $mockFGCRequest = $this->getFGCMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                ['response' => MockedData::LOGIN_SUCCESS, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_200]],
                [
                    'response' => MockedData::LOGIN_BAD_CREDENTIALS,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_403],
                ],
                ['response' => MockedData::BAD_REQUEST, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_400]]
            )
        );
        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);

        $loginResponse = PHPUnitUtil::callMethod(
            $client,
            'login',
            []
        );
        // 200
        $this->assertEquals(
            'this-is-a-token',
            $loginResponse['token'],
            'Success login case'
        );
        // 403
        $error = '';
        $code = 0;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'login',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
            $code = $e->getCode();
        }
        $this->assertEquals(403, $code);

        PHPUnitUtil::assertRegExp(
            $this,
            '/' . MockedData::HTTP_403 . '.*The machine_id or password is incorrect/',
            $error,
            'Bad credential login case'
        );

        // 400
        $error = '';
        $code = 0;
        try {
            PHPUnitUtil::callMethod(
                $client,
                'login',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
            $code = $e->getCode();
        }
        $this->assertEquals(400, $code);
        PHPUnitUtil::assertRegExp(
            $this,
            '/' . MockedData::HTTP_400 . '.*Invalid request body/',
            $error,
            'Bad request login case'
        );
    }

    public function testRegister()
    {
        // All tests are based on register retry attempts value
        $this->assertEquals(Bouncer::REGISTER_RETRY, 1);
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest = $this->getFGCMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                ['response' => MockedData::REGISTER_ALREADY, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_500]],
                ['response' => MockedData::REGISTER_ALREADY, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_500]],
                ['response' => MockedData::SUCCESS, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK']],
                ['response' => MockedData::BAD_REQUEST, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_400]],
                ['response' => MockedData::REGISTER_ALREADY, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_500]],
                ['response' => MockedData::SUCCESS, 'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK']]
            )
        );

        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);

        // 500 (successive attempts)
        $error = '';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'register',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }
        PHPUnitUtil::assertRegExp(
            $this,
            '/' . MockedData::HTTP_500 . '.*User already registered/',
            $error,
            'Already registered case'
        );
        // 200 (first attempt)
        $error = 'none';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'register',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }
        PHPUnitUtil::assertRegExp(
            $this,
            '/none/',
            $error,
            'Success case'
        );
        // 400 (first attempt)
        $error = '';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'register',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }
        PHPUnitUtil::assertRegExp(
            $this,
            '/' . MockedData::HTTP_400 . '.*Invalid request body/',
            $error,
            'Bad request registered case'
        );
        // 200 (after 1 failed 500 attempt)
        $error = 'none';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'register',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }
        PHPUnitUtil::assertRegExp(
            $this,
            '/none/',
            $error,
            'Success case'
        );
    }

    public function testSignals()
    {
        // Success test
        $mockFGCRequest = $this->getFGCMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::SUCCESS,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200],
                ]
            )
        );
        $mockFileStorage->method('retrievePassword')->will(
            $this->onConsecutiveCalls(
                TestConstants::PASSWORD
            )
        );
        $mockFileStorage->method('retrieveMachineId')->will(
            $this->onConsecutiveCalls(
                TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
            )
        );
        $mockFileStorage->method('retrieveToken')->will(
            $this->onConsecutiveCalls(
                TestConstants::TOKEN
            )
        );
        $mockFileStorage->method('retrieveScenarios')->willReturn(
            TestConstants::SCENARIOS
        );
        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);

        $signalsResponse = $client->pushSignals([]);

        $this->assertEquals(
            'OK',
            $signalsResponse['message'],
            'Success pushed signals'
        );

        // Failed test
        $mockFGCRequest = $this->getFGCMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::SIGNALS_BAD_REQUEST,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_400],
                ]
            )
        );
        $mockFileStorage->method('retrievePassword')->will(
            $this->onConsecutiveCalls(
                TestConstants::PASSWORD
            )
        );
        $mockFileStorage->method('retrieveMachineId')->will(
            $this->onConsecutiveCalls(
                TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
            )
        );
        $mockFileStorage->method('retrieveToken')->will(
            $this->onConsecutiveCalls(
                TestConstants::TOKEN
            )
        );

        $client = new Bouncer($this->configs, $mockFileStorage, $mockFGCRequest);

        $error = '';
        $code = 0;
        try {
            $client->pushSignals([]);
        } catch (ClientException $e) {
            $error = $e->getMessage();
            $code = $e->getCode();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/.*Invalid request body.*scenario_hash/',
            $error,
            'Bad signals request'
        );
        $this->assertEquals(MockedData::HTTP_400, $code);
    }
}
