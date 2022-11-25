<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

/**
 * Test for watcher requests.
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
use CrowdSec\LapiClient\HttpMessage\Response;
use CrowdSec\LapiClient\Storage\FileStorage;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;
use org\bovigo\vfs\vfsStream;

/**
 * @uses \CrowdSec\LapiClient\AbstractClient
 * @uses \CrowdSec\LapiClient\Storage\FileStorage
 * @uses \CrowdSec\LapiClient\Bouncer::shouldLogin
 * @uses \CrowdSec\LapiClient\HttpMessage\Response
 * @uses \CrowdSec\LapiClient\HttpMessage\Request
 * @uses \CrowdSec\LapiClient\HttpMessage\AbstractMessage::getHeaders
 * @uses \CrowdSec\LapiClient\RequestHandler\Curl::createOptions
 * @uses \CrowdSec\LapiClient\RequestHandler\Curl::handle
 *
 * @covers \CrowdSec\LapiClient\Bouncer::__construct
 * @covers \CrowdSec\LapiClient\Bouncer::configure
 * @covers \CrowdSec\LapiClient\Bouncer::login
 * @covers \CrowdSec\LapiClient\Bouncer::register
 * @covers \CrowdSec\LapiClient\Bouncer::manageRequest
 * @covers \CrowdSec\LapiClient\Bouncer::ensureRegister
 * @covers \CrowdSec\LapiClient\Bouncer::ensureAuth
 * @covers \CrowdSec\LapiClient\Bouncer::getStreamDecisions
 * @covers \CrowdSec\LapiClient\Bouncer::pushSignals
 * @covers \CrowdSec\LapiClient\Bouncer::enroll
 * @covers \CrowdSec\LapiClient\AbstractClient::request
 * @covers \CrowdSec\LapiClient\Bouncer::handleTokenHeader
 * @covers \CrowdSec\LapiClient\Bouncer::formatUserAgent
 * @covers \CrowdSec\LapiClient\Bouncer::areEquals
 * @covers \CrowdSec\LapiClient\Bouncer::generatePassword
 * @covers \CrowdSec\LapiClient\Bouncer::generateRandomString
 * @covers \CrowdSec\LapiClient\Bouncer::generateMachineId
 * @covers \CrowdSec\LapiClient\Bouncer::shouldRefreshCredentials
 * @covers \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Bouncer::handleLogin
 * @covers \CrowdSec\LapiClient\Bouncer::refreshCredentials
 * @covers \CrowdSec\LapiClient\Bouncer::normalizeTags
 */
final class WatcherTest extends AbstractClient
{
    public function testRegisterParams()
    {
        $mockFileStorage = $this->getFileStorageMock();
        // Set null password to force register
        $mockFileStorage->method('retrievePassword')->willReturn(
            null
        );

        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['request'])
            ->getMock();
        $mockClient->expects($this->exactly(1))->method('request')
            ->with(
                'POST',
                Bouncer::REGISTER_ENDPOINT,
                self::callback(function ($params): bool {
                    return 2 === count($params) &&
                           !empty($params['password']) &&
                           Bouncer::PASSWORD_LENGTH === strlen($params['password']) &&
                           !empty($params['machine_id']) &&
                           Bouncer::MACHINE_ID_LENGTH === strlen($params['machine_id']) &&
                           0 === substr_compare(
                               $params['machine_id'],
                               TestConstants::MACHINE_ID_PREFIX,
                               0,
                               strlen(TestConstants::MACHINE_ID_PREFIX)
                           );
                }), ['User-Agent' => Constants::USER_AGENT_PREFIX . '_' . TestConstants::USER_AGENT_SUFFIX
                                     . '/' . Constants::VERSION, ]
            );

        PHPUnitUtil::callMethod(
            $mockClient,
            'ensureRegister',
            []
        );
    }

    public function testLoginParams()
    {
        $mockFileStorage = $this->getFileStorageMock();

        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(
            TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
        );
        // Set null token to force login
        $mockFileStorage->method('retrieveToken')->willReturn(
            null
        );
        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['request'])
            ->getMock();
        $mockClient->expects($this->exactly(1))->method('request')
            ->with(
                'POST',
                Bouncer::LOGIN_ENDPOINT,
                [
                    'password' => TestConstants::PASSWORD,
                    'machine_id' => TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID,
                    'scenarios' => TestConstants::SCENARIOS,
                ],
                [
                    'User-Agent' => Constants::USER_AGENT_PREFIX . '_' . TestConstants::USER_AGENT_SUFFIX
                                    . '/' . Constants::VERSION,
                ]
            );
        $code = 0;
        $message = '';
        try {
            PHPUnitUtil::callMethod(
                $mockClient,
                'ensureAuth',
                []
            );
        } catch (ClientException $e) {
            $message = $e->getMessage();
            $code = $e->getCode();
        }
        $this->assertEquals(401, $code);
        $this->assertEquals('Login response does not contain required token.', $message);
    }

    public function testSignalsParams()
    {
        $mockFileStorage = $this->getFileStorageMock();
        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(
            TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
        );
        $mockFileStorage->method('retrieveToken')->willReturn(
            TestConstants::TOKEN
        );
        $mockFileStorage->method('retrieveScenarios')->willReturn(
            TestConstants::SCENARIOS
        );

        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['request'])
            ->getMock();

        $signals = ['test'];

        $mockClient->expects($this->exactly(1))->method('request')
            ->withConsecutive(
                [
                    'POST',
                    Bouncer::SIGNALS_ENDPOINT,
                    $signals,
                    [
                        'User-Agent' => Constants::USER_AGENT_PREFIX . '_' . TestConstants::USER_AGENT_SUFFIX
                                        . '/' . Constants::VERSION,
                        'Authorization' => 'Bearer ' . TestConstants::TOKEN,
                    ],
                ]
            );
        $mockClient->pushSignals($signals);
    }

    public function testDecisionsStreamParams()
    {
        $mockFileStorage = $this->getFileStorageMock();
        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(
            TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
        );
        $mockFileStorage->method('retrieveToken')->willReturn(
            TestConstants::TOKEN
        );
        $mockFileStorage->method('retrieveScenarios')->willReturn(
            TestConstants::SCENARIOS
        );
        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['request'])
            ->getMock();

        $mockClient->expects($this->exactly(1))->method('request')
            ->withConsecutive(
                [
                    'GET',
                    Bouncer::DECISIONS_STREAM_ENDPOINT,
                    [],
                    [
                        'User-Agent' => Constants::USER_AGENT_PREFIX . '_' . TestConstants::USER_AGENT_SUFFIX
                                        . '/' . Constants::VERSION,
                        'Authorization' => 'Bearer ' . TestConstants::TOKEN,
                    ],
                ]
            );
        $mockClient->getStreamDecisions();
    }

    public function testEnrollParams()
    {
        $mockFileStorage = $this->getFileStorageMock();
        $mockFileStorage->method('retrievePassword')->willReturn(
            TestConstants::PASSWORD
        );
        $mockFileStorage->method('retrieveMachineId')->willReturn(
            TestConstants::MACHINE_ID_PREFIX . TestConstants::MACHINE_ID
        );
        $mockFileStorage->method('retrieveToken')->willReturn(
            TestConstants::TOKEN
        );
        $mockFileStorage->method('retrieveScenarios')->willReturn(
            TestConstants::SCENARIOS
        );
        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['request'])
            ->getMock();

        $testName = 'test-name';
        $testOverwrite = true;
        $testEnrollKey = 'test-enroll-id';
        $testTags = ['tag1', 'tag2'];
        $params = [
            'name' => $testName,
            'overwrite' => $testOverwrite,
            'attachment_key' => $testEnrollKey,
            'tags' => $testTags,
        ];
        $mockClient->expects($this->exactly(1))->method('request')
            ->withConsecutive(
                [
                    'POST',
                    Bouncer::ENROLL_ENDPOINT,
                    $params,
                    [
                        'User-Agent' => Constants::USER_AGENT_PREFIX . '_' . TestConstants::USER_AGENT_SUFFIX
                                        . '/' . Constants::VERSION,
                        'Authorization' => 'Bearer ' . TestConstants::TOKEN,
                    ],
                ]
            );
        $mockClient->enroll($testName, $testOverwrite, $testEnrollKey, $testTags);
    }

    public function testRequest()
    {
        // Test a valid POST request and its return
        $mockFileStorage = $this->getFileStorageMock();

        $mockClient = $this->getMockBuilder('CrowdSec\LapiClient\Bouncer')
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs, 'storage' => $mockFileStorage])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockClient->expects($this->exactly(1))->method('sendRequest')->will($this->returnValue(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, [])
        ));

        $response = $mockClient->request('POST', '', [], []);

        $this->assertEquals(
            json_decode(MockedData::LOGIN_SUCCESS, true),
            $response,
            'Should format response as expected'
        );
        // Test a not allowed request method (PUT)
        $error = '';
        try {
            $mockClient->request('PUT', '', [], []);
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/not allowed/',
            $error,
            'Not allowed method should throw an exception before sending request'
        );
    }

    public function testConfigure()
    {
        $client = new Bouncer($this->configs, new FileStorage());

        $this->assertEquals(
            Constants::ENV_DEV,
            $client->getConfig('env'),
            'Env should be configured to dev by default'
        );
        $this->assertEquals(
            TestConstants::SCENARIOS,
            $client->getConfig('scenarios'),
            'Scenarios should be configured'
        );
        $this->assertEquals(
            TestConstants::MACHINE_ID_PREFIX,
            $client->getConfig('machine_id_prefix'),
            'Machine id prefix should be configured'
        );

        $this->assertEquals(
            TestConstants::USER_AGENT_SUFFIX,
            $client->getConfig('user_agent_suffix'),
            'User agent suffix should be configured'
        );

        $client = new Bouncer(['scenarios' => ['test-scenario', 'test-scenario']],
            new FileStorage()
        );

        $this->assertEquals(
            TestConstants::SCENARIOS,
            $client->getConfig('scenarios'),
            'Scenarios should be array unique'
        );

        $client = new Bouncer(['scenarios' => ['not-numeric-key' => 'test-scenario']], new FileStorage());

        $this->assertEquals(
            TestConstants::SCENARIOS,
            $client->getConfig('scenarios'),
            'Scenarios should be indexed array'
        );

        $error = '';
        try {
            new Bouncer([], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/The child config "scenarios" under "config" must be configured./',
            $error,
            'Scenarios key must be in configs'
        );

        $error = '';
        try {
            new Bouncer(['scenarios' => []], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/should have at least 1 element/',
            $error,
            'Scenarios should have at least 1 element'
        );

        $error = '';
        try {
            new Bouncer(['scenarios' => ['']], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/cannot contain an empty value/',
            $error,
            'Scenarios can not contain empty value'
        );

        $error = '';
        try {
            new Bouncer(['machine_id_prefix' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Length must be <= 16/',
            $error,
            'machine_id_prefix length should be <16'
        );

        $error = '';
        try {
            new Bouncer(['machine_id_prefix' => 'aaaaa  a'], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Allowed chars are/',
            $error,
            'machine_id_prefix should contain allowed chars'
        );

        $client = new Bouncer(['scenarios' => TestConstants::SCENARIOS, 'machine_id_prefix' => ''], new FileStorage());

        $this->assertEquals(
            '',
            $client->getConfig('machine_id_prefix'),
            'machine_id_prefix can be empty'
        );

        $error = '';
        try {
            new Bouncer(['user_agent_suffix' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Length must be <= 16/',
            $error,
            'user_agent_suffix length should be <16'
        );

        $error = '';
        try {
            new Bouncer(['user_agent_suffix' => 'aaaaa  a'], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Allowed chars are/',
            $error,
            'user_agent_suffix should contain allowed chars'
        );

        $client = new Bouncer(['scenarios' => TestConstants::SCENARIOS, 'user_agent_suffix' => ''], new FileStorage());

        $this->assertEquals(
            '',
            $client->getConfig('user_agent_suffix'),
            'user_agent_suffix can be empty'
        );

        $error = '';
        try {
            new Bouncer(['env' => 'preprod'], new FileStorage());
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Permissible values:/',
            $error,
            'env should be dev or prod'
        );
    }

    public function testPrivateOrProtectedMethods()
    {
        $client = new Bouncer($this->configs, new FileStorage());

        // Test areEquals
        $a = ['A', 'B'];
        $b = ['A', 'B'];

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$a, $b]
        );
        $this->assertEquals(
            true,
            $result,
            '$a and $b are equals'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$b, $a]
        );
        $this->assertEquals(
            true,
            $result,
            '$b and $a are equals'
        );

        $a = ['B', 'A'];
        $b = ['A', 'B'];

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$a, $b]
        );
        $this->assertEquals(
            true,
            $result,
            '$a and $b are equals'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$b, $a]
        );
        $this->assertEquals(
            true,
            $result,
            '$b and $a are equals'
        );

        $a = ['B', 'C'];
        $b = ['A', 'B'];

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$a, $b]
        );
        $this->assertEquals(
            false,
            $result,
            '$a and $b are different'
        );

        $a = ['A'];
        $b = ['A', 'B'];

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$a, $b]
        );
        $this->assertEquals(
            false,
            $result,
            '$a and $b are different'
        );

        $a = ['A', 'B'];
        $b = ['A'];

        $result = PHPUnitUtil::callMethod(
            $client,
            'areEquals',
            [$a, $b]
        );
        $this->assertEquals(
            false,
            $result,
            '$a and $b are different'
        );

        // Test generatePassword
        $result = PHPUnitUtil::callMethod(
            $client,
            'generatePassword',
            []
        );

        $this->assertEquals(
            Bouncer::PASSWORD_LENGTH,
            strlen($result),
            'Password should have right length'
        );

        PHPUnitUtil::assertRegExp(
            $this,
            '/^[A-Za-z0-9]+$/',
            $result,
            'Password should be well formatted'
        );

        // Test generateMachineId
        $result = PHPUnitUtil::callMethod(
            $client,
            'generateMachineId',
            []
        );

        $this->assertEquals(
            Bouncer::MACHINE_ID_LENGTH,
            strlen($result),
            'Machine id should have right length'
        );

        PHPUnitUtil::assertRegExp(
            $this,
            '/^[a-z0-9]+$/',
            $result,
            'Machine should be well formatted'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'generateMachineId',
            [['machine_id_prefix' => 'thisisatest']]
        );

        $this->assertEquals(
            Bouncer::MACHINE_ID_LENGTH,
            strlen($result),
            'Machine id should have right length'
        );

        PHPUnitUtil::assertRegExp(
            $this,
            '/^[a-z0-9]+$/',
            $result,
            'Machine should be well formatted'
        );

        $this->assertEquals(
            'thisisatest',
            substr($result, 0, strlen('thisisatest')),
            'Machine id should begin with machine id prefix'
        );

        // Test  generateRandomString
        $error = '';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'generateRandomString',
                [0, 'ab']
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Length must be greater than zero/',
            $error,
            'Random string must have a length greater than 0'
        );

        $error = '';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'generateRandomString',
                [2, '']
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/There must be at least one allowed character./',
            $error,
            'There must be at least one allowed character.'
        );

        // Test shouldRefreshCredentials
        $result = PHPUnitUtil::callMethod(
            $client,
            'shouldRefreshCredentials',
            [null, 'test', []]
        );

        $this->assertEquals(
            true,
            $result,
            'Should refresh if no machine id'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'shouldRefreshCredentials',
            ['test', null, []]
        );

        $this->assertEquals(
            true,
            $result,
            'Should refresh if no password'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'shouldRefreshCredentials',
            ['test-machine-id', 'test-password', []]
        );

        $this->assertEquals(
            false,
            $result,
            'Should not refresh'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'shouldRefreshCredentials',
            ['test-machine-id', 'test-password', ['machine_id_prefix' => 'test-prefix']]
        );

        $this->assertEquals(
            true,
            $result,
            'Should refresh if machine id prefix differs from machine id start'
        );

        $result = PHPUnitUtil::callMethod(
            $client,
            'shouldRefreshCredentials',
            ['test-machine-id', 'test-password', ['machine_id_prefix' => 'test-ma']]
        );

        $this->assertEquals(
            false,
            $result,
            'Should not refresh if machine id starts with machine id prefix'
        );

        // Test handleLogin errors
        $mockCurlRequest = $this->getCurlMock();
        $mockFileStorage = $this->getFileStorageMock();
        $mockCurlRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                MockedData::LOGIN_BAD_CREDENTIALS,
                MockedData::LOGIN_SUCCESS
            )
        );
        $mockCurlRequest->method('getResponseHttpCode')->will(
            $this->onConsecutiveCalls(MockedData::HTTP_200, MockedData::HTTP_200
            )
        );
        $client = new Bouncer($this->configs, $mockFileStorage, $mockCurlRequest);

        $error = '';
        try {
            PHPUnitUtil::callMethod(
                $client,
                'handleLogin',
                []
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/required token/',
            $error,
            'Empty token should throw an error'
        );

        // Test refresh credentials
        $root = vfsStream::setup('/tmp');
        $storage = new FileStorage($root->url());
        $client = new Bouncer($this->configs, $storage);

        $this->assertEquals(
            false,
            file_exists($root->url() . '/' . Constants::ENV_DEV . '-' . FileStorage::MACHINE_ID_FILE),
            'File should not exist'
        );

        $this->assertEquals(
            false,
            file_exists($root->url() . '/' . Constants::ENV_DEV . '-' . FileStorage::PASSWORD_FILE),
            'File should not exist'
        );
        PHPUnitUtil::callMethod(
            $client,
            'refreshCredentials',
            []
        );

        $this->assertEquals(
            true,
            file_exists($root->url() . '/' . Constants::ENV_DEV . '-' . FileStorage::MACHINE_ID_FILE),
            'File should exist'
        );

        $this->assertEquals(
            true,
            file_exists($root->url() . '/' . Constants::ENV_DEV . '-' . FileStorage::PASSWORD_FILE),
            'File should exist'
        );

        $password = $storage->retrievePassword();

        PHPUnitUtil::assertRegExp(
            $this,
            '/^[A-Za-z0-9]+$/',
            $password,
            'Password should be well formatted'
        );

        $machineId = $storage->retrieveMachineId();

        $this->assertEquals(
            Bouncer::MACHINE_ID_LENGTH,
            strlen($machineId),
            'Machine id should have right length'
        );

        PHPUnitUtil::assertRegExp(
            $this,
            '/^[A-Za-z0-9]+$/',
            $machineId,
            'Machine should be well formatted'
        );

        $this->assertEquals(
            TestConstants::MACHINE_ID_PREFIX,
            substr($machineId, 0, strlen(TestConstants::MACHINE_ID_PREFIX)),
            'Machine id should begin with machine id prefix'
        );

        // Test normalizeTags
        $tags = ['tag1', 'tag2', 'tag3'];
        $result = PHPUnitUtil::callMethod(
            $client,
            'normalizeTags',
            [$tags]
        );
        $this->assertEquals(
            $tags,
            $result,
            'Right tags should be unchanged'
        );

        $tags = ['tag1', 'tag1', 'tag3'];
        $result = PHPUnitUtil::callMethod(
            $client,
            'normalizeTags',
            [$tags]
        );
        $this->assertEquals(
            [],
            array_diff($result, ['tag1', 'tag3']),
            'Tags should be unique'
        );

        $tags = ['a' => 'tag1'];
        $result = PHPUnitUtil::callMethod(
            $client,
            'normalizeTags',
            [$tags]
        );
        $this->assertEquals(
            ['tag1'],
            $result,
            'Tags should be indexed array'
        );

        $error = '';
        $tags = ['tag1', ['tag2']];
        try {
            PHPUnitUtil::callMethod(
                $client,
                'normalizeTags',
                [$tags]
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Tag must be a string: array given/',
            $error,
            'Should throw an error if tag is not a string'
        );

        $error = '';
        $tags = ['tag1', '', 'tag3'];
        try {
            PHPUnitUtil::callMethod(
                $client,
                'normalizeTags',
                [$tags]
            );
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Tag must not be empty/',
            $error,
            'Should throw an error if tag is empty'
        );
    }
}
