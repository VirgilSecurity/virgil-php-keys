<?php
/**
 * Copyright (c) 2015-2024 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Tests\Unit\Sdk;


use DateTime;
use Virgil\Crypto\Core\Enum\HashAlgorithms;
use Virgil\Crypto\Core\VirgilKeys\VirgilPrivateKey;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKey;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Http\HttpClientInterface;
use Virgil\Sdk\Http\Requests\GetHttpRequest;
use Virgil\Sdk\Http\Requests\PostHttpRequest;
use Virgil\Sdk\Http\Responses\HttpResponse;
use Virgil\Sdk\Http\Responses\HttpStatusCode;
use Virgil\Sdk\Http\VirgilAgent\HttpVirgilAgent;
use Virgil\Sdk\Card;
use Virgil\Sdk\Exceptions\CardClientException;
use Virgil\Sdk\CardManager;
use Virgil\Sdk\CardParams;
use Virgil\Sdk\CardSignature;
use Virgil\Sdk\Verification\CardVerifier;
use Virgil\Sdk\Web\Authorization\AccessToken;
use Virgil\Sdk\Web\Authorization\AccessTokenProvider;
use Virgil\Sdk\Web\Authorization\TokenContext;
use Virgil\Sdk\Web\CardClient;
use Virgil\Sdk\Web\RawSignature;
use Virgil\Sdk\Web\RawSignedModel;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class CardManagerTest extends TestCase
{

    /**
     * @var CardManager
     */
    protected $cardManager;
    /**
     * @var MockObject
     */
    protected $virgilCrypto;
    /**
     * @var MockObject
     */
    protected $accessTokenProviderMock;
    /**
     * @var MockObject
     */
    protected $cardVerifierMock;
    /**
     * @var MockObject
     */
    protected $httpClientMock;

    /**
     * @var MockObject
     */
    protected $httpVirgilAgentMock;

    /**
     * @var callable|null
     */
    protected $signCallback = null;


    public function setUp(): void
    {
        parent::setUp();

        $this->virgilCrypto = $this->createMock(VirgilCrypto::class);
        $this->accessTokenProviderMock = $this->createMock(AccessTokenProvider::class);
        $this->cardVerifierMock = $this->createMock(CardVerifier::class);
        $this->httpClientMock = $this->createMock(HttpClientInterface::class);
        $this->httpVirgilAgentMock = $this->createMock(HttpVirgilAgent::class);
        $this->httpVirgilAgentMock->method("getFormatString")->willReturn("virgil_agent_string");
        $this->httpVirgilAgentMock->method("getName")->willReturn("Virgil-agent");
    }

    #[Test]
    public function generateRawCard_withCardParams_returnsSelfSignedRawSignedModel()
    {
        $this->virgilCrypto->expects($this->once())
            ->method('generateSignature')
            ->willReturn('expected_signature');


        $rawSignedModel = $this->getCardManager()
            ->generateRawCard(
                CardParams::create(
                    [
                        CardParams::PUBLIC_KEY => $this->createMock(VirgilPublicKey::class),
                        CardParams::PRIVATE_KEY => $this->createMock(VirgilPrivateKey::class),
                        CardParams::IDENTITY => 'Alice',
                        CardParams::PREVIOUS_CARD_ID => '23f23f',
                    ]
                )
            );

        $signatures = $rawSignedModel->getSignatures();
        $this->assertNotNull($rawSignedModel->getContentSnapshot());
        $this->assertCount(1, $signatures);
        $this->assertEquals('self', $signatures[0]->getSigner());
        $this->assertEquals('expected_signature', $signatures[0]->getSignature());
        $this->assertNull($signatures[0]->getSnapshot());
    }


    #[Test]
    public function generateRawCard_withCardParamsExtraFields_returnsSelfSignedRawSignedModel()
    {
        $this->virgilCrypto->expects($this->once())
            ->method('generateSignature')
            ->willReturn('expected_signature');


        $rawSignedModel = $this->getCardManager()
            ->generateRawCard(
                CardParams::create(
                    [
                        CardParams::PUBLIC_KEY => $this->createMock(VirgilPublicKey::class),
                        CardParams::PRIVATE_KEY => $this->createMock(VirgilPrivateKey::class),
                        CardParams::IDENTITY => 'Alice',
                        CardParams::EXTRA_FIELDS => [
                            'extra_a' => 'val_1',
                            'extra_b' => 'val_2',
                        ],
                    ]
                )
            );

        $signatures = $rawSignedModel->getSignatures();
        $this->assertNotNull($rawSignedModel->getContentSnapshot());
        $this->assertCount(1, $signatures);
        $this->assertEquals('self', $signatures[0]->getSigner());
        $this->assertEquals('expected_signature', $signatures[0]->getSignature());
        $this->assertEquals('{"extra_a":"val_1","extra_b":"val_2"}', $signatures[0]->getSnapshot());
    }


    public static function cardManager_withHttpClientErrorResponse_throwsCardClientException_dataProvider()
    {
        return [
            [
                function (CardManager $cardManager) {
                    $cardManager->publishRawSignedModel(new RawSignedModel('{"identity":"alice"}', []));
                },
            ],
            [
                function (CardManager $cardManager) {
                    $cardManager->getCard("01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f");
                },
            ],
            [
                function (CardManager $cardManager) {
                    $cardManager->searchCards("Alice");
                },
            ],
        ];
    }


    #[Test]
    #[DataProvider("cardManager_withHttpClientErrorResponse_throwsCardClientException_dataProvider")]
    public function cardManager_withHttpClientErrorResponse_throwsCardClientException($testFunc)
    {
        $this->expectException('\Virgil\Sdk\Exceptions\CardClientException');

        $this->accessTokenProviderMock->expects($this->once())
            ->method('getToken')
            ->with($this->anything())
            ->willReturn($this->createMock(AccessToken::class));

        $this->httpClientMock->expects($this->once())
            ->method('send')
            ->with($this->anything())
            ->willReturn(new HttpResponse(new HttpStatusCode(500), '', ''));

        try {
            $testFunc($this->getCardManager());
        } catch (CardClientException $e) {
            $this->assertEquals(
                20000,
                $e->getErrorCode()
            );
            $this->assertEquals(
                "error during request serving",
                $e->getErrorMessage()
            );

            throw $e;
        }
    }


    #[Test]
    public function publishRawSignedModel_withAccessToken_returnsCardWithID()
    {
        $this->signCallback = function (RawSignedModel $model) {
            $signatures = $model->getSignatures();
            $signatures[] = new RawSignature("callback", "sign");

            return new RawSignedModel($model->getContentSnapshot(), $signatures);
        };

        $this->cardVerifierMock->expects($this->once())
            ->method("verifyCard")
            ->with($this->anything())
            ->willReturn(true);

        $this->virgilCrypto->expects($this->once())
            ->method("computeHash")
            ->with(
                '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}',
                HashAlgorithms::SHA512()
            )
            ->willReturn(
                base64_decode(
                    "AQVcYCMpp3HfyLx6X/HC7lcdFpw2s8UoFwnl1PeRNV9OOmt6onnlFg9LXqLzihLKcrjcb1zMNqhg8BMcGQfQgQ=="
                )
            );

        $this->virgilCrypto->expects($this->once())
            ->method("importPublicKey")
            ->with(base64_decode("MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0="))
            ->willReturn($this->createMock(VirgilPublicKey::class));

        $this->httpClientMock->expects($this->once())
            ->method('send')
            ->with(
                new PostHttpRequest(
                    "http://service.url/card/v5",
                    '{"content_snapshot":"eyJpZGVudGl0eSI6IkFsaWNlLTZjYWRhYTY4ZjA5MWQzZDM2MjZhIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==","signatures":[{"signature":"MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA=","signer":"self"},{"signature":"c2lnbg==","signer":"callback"}]}',
                    [
                        "Authorization" => "Virgil access_token_string",
                        "Virgil-agent" => "virgil_agent_string",
                    ]
                )
            )
            ->willReturn(
                new HttpResponse(
                    new HttpStatusCode(201),
                    '',
                    '
                                            {
                                              "content_snapshot": "eyJpZGVudGl0eSI6IkFsaWNlLTZjYWRhYTY4ZjA5MWQzZDM2MjZhIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==",
                                              "signatures": [
                                                {
                                                  "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA=",
                                                  "signer": "self"
                                                },
                                                {
                                                  "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc=",
                                                  "signer": "virgil"
                                                }
                                              ]
                                            }'
                )
            );

        $accessTokenMock = $this->createMock(AccessToken::class);
        $accessTokenMock->method("__toString")
            ->willReturn("access_token_string");

        $this->accessTokenProviderMock->expects($this->once())
            ->method('getToken')
            ->with(new TokenContext("Alice-6cadaa68f091d3d3626a", 'publish'))
            ->willReturn($accessTokenMock);

        $contentSnapshot = '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}';
        $signatures = [
            new RawSignature(
                "self",
                base64_decode(
                    "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                )
            ),
        ];

        $card = $this->getCardManager()
            ->publishRawSignedModel(new RawSignedModel($contentSnapshot, $signatures));

        $this->assertEquals("01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f", $card->getID());
    }


    public static function getCardByID_withAccessToken_returnsCard_dataProvider()
    {
        return [
            [
                '',
                false,
            ],
            [
                "
                date: Mon, 30 Apr 2018 13:52:22 GMT \n\r
                content-type: text/html \n\r
                X-Virgil-Is-Superseeded: true \n\r
                ",
                true,
            ],
        ];
    }


    #[Test]
    #[DataProvider("getCardByID_withAccessToken_returnsCard_dataProvider")]
    public function getCardByID_withAccessToken_returnsCard($headers, $isOutdated)
    {
        $this->cardVerifierMock->expects($this->once())
            ->method("verifyCard")
            ->with($this->anything())
            ->willReturn(true);

        $this->virgilCrypto->expects($this->once())
            ->method("computeHash")
            ->with(
                '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}',
                HashAlgorithms::SHA512()
            )
            ->willReturn(
                base64_decode(
                    "AQVcYCMpp3HfyLx6X/HC7lcdFpw2s8UoFwnl1PeRNV9OOmt6onnlFg9LXqLzihLKcrjcb1zMNqhg8BMcGQfQgQ=="
                )
            );

        $this->virgilCrypto->expects($this->once())
            ->method("importPublicKey")
            ->with(base64_decode("MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0="))
            ->willReturn($this->createMock(VirgilPublicKey::class));

        $this->httpClientMock->expects($this->once())
            ->method('send')
            ->with(
                new GetHttpRequest(
                    "http://service.url/card/v5/01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f",
                    null,
                    [
                        "Authorization" => "Virgil access_token_string",
                        "Virgil-agent" => "virgil_agent_string",
                    ]
                )
            )
            ->willReturn(
                new HttpResponse(
                    new HttpStatusCode(200),
                    $headers,
                    '
                                            {
                                              "content_snapshot": "eyJpZGVudGl0eSI6IkFsaWNlLTZjYWRhYTY4ZjA5MWQzZDM2MjZhIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==",
                                              "signatures": [
                                                {
                                                  "signer": "self",
                                                  "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                                                },
                                                {
                                                  "signer": "virgil",
                                                  "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="
                                                }
                                              ]
                                            }'
                )
            );

        $accessTokenMock = $this->createMock(AccessToken::class);
        $accessTokenMock->method("__toString")
            ->willReturn("access_token_string");

        $this->accessTokenProviderMock->expects($this->once())
            ->method('getToken')
            ->with(new TokenContext('', 'get'))
            ->willReturn($accessTokenMock);


        $card = $this->getCardManager()
            ->getCard("01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f");

        $this->assertEquals("01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f", $card->getID());
        $this->assertEquals($isOutdated, $card->isOutdated());
    }


    #[Test]
    public function searchCardByIdentity_withAccessToken_returnsCards()
    {
        $this->cardVerifierMock->expects($this->exactly(3))
            ->method("verifyCard")
            ->with($this->anything())
            ->willReturn(true);

        $this->virgilCrypto->expects($this->exactly(3))
            ->method("computeHash")
            ->willReturnCallback(
                fn($snapshot, $hashAlg) =>
                match ($snapshot) {
                    '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}'
                    => base64_decode("AQVcYCMpp3HfyLx6X/HC7lcdFpw2s8UoFwnl1PeRNV9OOmt6onnlFg9LXqLzihLKcrjcb1zMNqhg8BMcGQfQgQ=="),
                    '{"identity":"Alice-a86060c7007b007c070f","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888, "previous_card_id":"01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f"}'
                    => base64_decode("cAcONe9y5LM/qv0Wtz4HPL3/et2eShDTwBoovlf/4eJgGACC8M45kwj10+jI07R+L3VwYlSPshKLgfJAkkclCg=="),
                    '{"identity":"Alice-6f5dd654af58ff84110c","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}'
                    => base64_decode("vC3MNikrfwU/f4Oaqy3Lag5xVti0nHbbiSQwzjvQbiLu0IO0qWKRTfN8GoPz3PfoewAdUFnI6OCIvwqjWmcwCQ==")
                }
            );

        $this->virgilCrypto->expects($this->exactly(3))
            ->method("importPublicKey")
            ->with(base64_decode("MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0="))
            ->willReturn($this->createMock(VirgilPublicKey::class));

        $this->httpClientMock->expects($this->once())
            ->method('send')
            ->with(
                new PostHttpRequest(
                    "http://service.url/card/v5/actions/search",
                    '{"identity":"Alice"}',
                    [
                        "Authorization" => "Virgil access_token_string",
                        "Virgil-agent" => "virgil_agent_string",
                    ]
                )
            )
            ->willReturn(
                new HttpResponse(
                    new HttpStatusCode(200),
                    '',
                    '
                                            [
                                              {
                                                "content_snapshot": "eyJpZGVudGl0eSI6IkFsaWNlLTZjYWRhYTY4ZjA5MWQzZDM2MjZhIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==",
                                                "signatures": [
                                                  {
                                                    "signer": "self",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                                                  },
                                                  {
                                                    "signer": "virgil",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="
                                                  }
                                                ]
                                              },
                                              {
                                                "content_snapshot": "eyJpZGVudGl0eSI6IkFsaWNlLWE4NjA2MGM3MDA3YjAwN2MwNzBmIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4LCAicHJldmlvdXNfY2FyZF9pZCI6IjAxMDU1YzYwMjMyOWE3NzFkZmM4YmM3YTVmZjFjMmVlNTcxZDE2OWMzNmIzYzUyODE3MDllNWQ0Zjc5MTM1NWYifQ==",
                                                "signatures": [
                                                  {
                                                    "signer": "self",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                                                  },
                                                  {
                                                    "signer": "virgil",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="
                                                  }
                                                ]
                                              },
                                              {
                                                "content_snapshot": "eyJpZGVudGl0eSI6IkFsaWNlLTZmNWRkNjU0YWY1OGZmODQxMTBjIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFEN0JOZVZEYnVaOUZQT0p1Q2Z2UUJWZWxyYWpzcGZUb212UnBOMURZVm4wPSIsInZlcnNpb24iOiI1LjAiLCJjcmVhdGVkX2F0IjoxNTIzODI3ODg4fQ==",
                                                "signatures": [
                                                  {
                                                    "signer": "self",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                                                  },
                                                  {
                                                    "signer": "virgil",
                                                    "signature": "MFEwDQYJYIZIAWUDBAIDBQAEQAOiE0Y29s/rPAtxjV0HZsGf3ETQnjCFSndvac2KPNP4rXUOJ2NOj7VgRAkc3izKQpDs+Bd1YNy0hZeh36GcJQc="
                                                  }
                                                ]
                                              }
                                            ]
                                            '
                )
            );

        $accessTokenMock = $this->createMock(AccessToken::class);
        $accessTokenMock->method("__toString")->willReturn("access_token_string");

        $virgilAgentMock = $this->createMock(HttpVirgilAgent::class);
        $virgilAgentMock->method("getFormatString")->willReturn("virgil_agent_string");

        $this->accessTokenProviderMock->expects($this->once())
            ->method('getToken')
            ->with(new TokenContext('Alice', 'search'))
            ->willReturn($accessTokenMock);

        $cards = $this->getCardManager()
            ->searchCards("Alice");

        $this->assertCount(2, $cards);

        $this->assertEquals('70070e35ef72e4b33faafd16b73e073cbdff7add9e4a10d3c01a28be57ffe1e2', $cards[0]->getID());
        $this->assertEquals('bc2dcc36292b7f053f7f839aab2dcb6a0e7156d8b49c76db892430ce3bd06e22', $cards[1]->getID());
    }


    #[Test]
    public function importCard_fromRawSignedModel_returnsCard()
    {
        $contentSnapshot = '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}';
        $signatures = [
            new RawSignature(
                "self",
                base64_decode(
                    "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                )
            ),
        ];

        $model = new RawSignedModel($contentSnapshot, $signatures);

        $this->cardVerifierMock->expects($this->once())
            ->method("verifyCard")
            ->with($this->anything())
            ->willReturn(true);

        $this->virgilCrypto->expects($this->once())
            ->method("importPublicKey")
            ->with(base64_decode("MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0="))
            ->willReturn($this->createMock(VirgilPublicKey::class));

        $this->virgilCrypto->expects($this->once())
            ->method("computeHash")
            ->with(
                '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}',
                HashAlgorithms::SHA512()
            )
            ->willReturn(
                base64_decode(
                    "AQVcYCMpp3HfyLx6X/HC7lcdFpw2s8UoFwnl1PeRNV9OOmt6onnlFg9LXqLzihLKcrjcb1zMNqhg8BMcGQfQgQ=="
                )
            );

        $card = $this->getCardManager()
            ->importCard($model);


        $this->assertEquals("01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f", $card->getID());
        $this->assertEquals($this->createMock(VirgilPublicKey::class), $card->getPublicKey());
        $this->assertEquals('Alice-6cadaa68f091d3d3626a', $card->getIdentity());
        $this->assertEquals('5.0', $card->getVersion());
        $this->assertEquals(new DateTime("2018-04-15 21:31:28"), $card->getCreatedAt());
        $this->assertEquals(false, $card->isOutdated());
        $this->assertEquals(
            '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}',
            $card->getContentSnapshot()
        );
        $this->assertEquals(
            [
                new CardSignature(
                    "self",
                    base64_decode(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                    )
                ),
            ],
            $card->getSignatures()
        );

        $this->assertNull($card->getPreviousCard());
        $this->assertNull($card->getPreviousCardId());
    }


    #[Test]
    public function exportCard_asRawSignedModel_returnsRawSignedModel()
    {
        $expectedContentSnapshot = '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}';
        $expectedSignatures = [
            new RawSignature(
                "self",
                base64_decode(
                    "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                )
            ),
        ];

        $card = new Card(
            '01055c602329a771dfc8bc7a5ff1c2ee571d169c36b3c5281709e5d4f791355f',
            'Alice-6cadaa68f091d3d3626a',
            $this->createMock(VirgilPublicKey::class),
            '5.0',
            new DateTime("2018-04-15 21:31:28"),
            false,
            [
                new CardSignature(
                    "self",
                    base64_decode(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQDBbYZkTu7vt5AKTcCPJ685nMuQCivQZeMR+6jmmJY21/k5B4xEs5A7HF293fbYV/6ZlqdTAsPjjQuMXPNU6pwA="
                    )
                ),
            ],
            '{"identity":"Alice-6cadaa68f091d3d3626a","public_key":"MCowBQYDK2VwAyEAD7BNeVDbuZ9FPOJuCfvQBVelrajspfTomvRpN1DYVn0=","version":"5.0","created_at":1523827888}'
        );

        $rawSignedModel = $this->getCardManager()
            ->exportCardAsRawCard($card);

        $this->assertEquals($expectedContentSnapshot, $rawSignedModel->getContentSnapshot());
        $this->assertEquals($expectedSignatures, $rawSignedModel->getSignatures());
    }


    /**
     * @return CardManager
     */
    protected function getCardManager()
    {
        $cardClient = new CardClient($this->httpVirgilAgentMock, "http://service.url", $this->httpClientMock);

        return new CardManager(
            $this->virgilCrypto,
            $this->accessTokenProviderMock,
            $this->cardVerifierMock,
            $cardClient,
            $this->signCallback
        );
    }
}
