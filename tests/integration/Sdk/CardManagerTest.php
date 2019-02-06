<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

namespace Tests\Integration\Virgil\Sdk\Web;

use DateTime;

use Virgil\CryptoImpl\VirgilPublicKey;

use Virgil\Sdk\Card;
use Virgil\Sdk\CardParams;
use Virgil\Sdk\CardSignature;

use Virgil\Sdk\Verification\NullCardVerifier;

use Virgil\Tests\IntegrationBaseTestCase;

class CardManagerTest extends IntegrationBaseTestCase
{
    /**
     * @test
     */
    public function STC3()
    {
        $this->cardVerifier = null;
        $cardManager = $this->getCardManager();

        $stc3AsJson = $this->fixtures->STC3__As_Json();
        $stc3AsString = $this->fixtures->STC3__As_String();

        $cardFromString = $cardManager->importCardFromString($stc3AsString);
        $cardFromJson = $cardManager->importCardFromJson($stc3AsJson);

        /** @var Card $card */
        foreach ([$cardFromString, $cardFromJson] as $card) {
            /** @var VirgilPublicKey $publicKey */
            $publicKey = $card->getPublicKey();

            $this->assertEquals($this->fixtures->STC3__Card_Id(), $card->getID());
            $this->assertEquals('test', $card->getIdentity());
            $this->assertEquals(
                $this->fixtures->STC3__Public_Key_Base64(),
                base64_encode($publicKey->getValue())
            );
            $this->assertEquals('5.0', $card->getVersion());
            $this->assertEquals(new DateTime('2018-01-11T15:57:25'), $card->getCreatedAt());
            $this->assertNull($card->getPreviousCard());
            $this->assertNull($card->getPreviousCardId());
            $this->assertEmpty($card->getSignatures());

            $this->assertEquals($stc3AsJson, $cardManager->exportCardAsJson($card));
            $this->assertEquals($stc3AsString, $cardManager->exportCardAsString($card));
        }
    }


    /**
     * @test
     */
    public function STC4()
    {
        $this->cardVerifier = null;
        $cardManager = $this->getCardManager();

        $stc4AsJson = $this->fixtures->STC4__As_Json();
        $stc4AsString = $this->fixtures->STC4__As_String();

        $cardFromString = $cardManager->importCardFromString($stc4AsString);
        $cardFromJson = $cardManager->importCardFromJson($stc4AsJson);

        /** @var Card $card */
        foreach ([$cardFromString, $cardFromJson] as $card) {
            /** @var VirgilPublicKey $publicKey */
            $publicKey = $card->getPublicKey();

            $this->assertEquals($this->fixtures->STC4__Card_Id(), $card->getID());
            $this->assertEquals('test', $card->getIdentity());
            $this->assertEquals(
                $this->fixtures->STC4__Public_Key_Base64(),
                base64_encode($publicKey->getValue())
            );
            $this->assertEquals('5.0', $card->getVersion());
            $this->assertEquals(new DateTime('2018-01-11T15:57:25'), $card->getCreatedAt());
            $this->assertNull($card->getPreviousCard());
            $this->assertNull($card->getPreviousCardId());

            $signatures = $card->getSignatures();
            $this->assertCount(3, $signatures);

            $this->assertEquals(
                new CardSignature(
                    'self', base64_decode(
                              $this->fixtures->STC4__Signature_Self_Base64()
                          )
                ),
                $signatures[0]
            );

            $this->assertEquals(
                new CardSignature(
                    'virgil', base64_decode(
                                $this->fixtures->STC4__Signature_Virgil_Base64()
                            )
                ),
                $signatures[1]
            );

            $this->assertEquals(
                new CardSignature(
                    'extra', base64_decode(
                               $this->fixtures->STC4__Signature_Extra_Base64()
                           )
                ),
                $signatures[2]
            );

            $this->assertEquals($stc4AsJson, $cardManager->exportCardAsJson($card));
            $this->assertEquals($stc4AsString, $cardManager->exportCardAsString($card));
        }
    }


    /**
     * @test
     */
    public function STC17()
    {
        $cardManager = $this->getCardManager();
        $identity = $this->baseIdentityGenerator('Alice')();

        $this->cardVerifier = null;
        $cardManagerNoVerify = $this->getCardManager();

        $keys = $this->virgilCrypto->generateKeys();
        $cardParams = CardParams::create(
            [
                CardParams::Identity   => $identity,
                CardParams::PublicKey  => $keys->getPublicKey(),
                CardParams::PrivateKey => $keys->getPrivateKey(),
            ]
        );

        $rawCard = $cardManagerNoVerify->generateRawCard($cardParams);

        $expectedCard = $cardManagerNoVerify->importCard($rawCard);

        $card = $cardManager->publishCard($cardParams);

        $getCard = $cardManager->getCard($card->getID());

        $this->assertEquals($card, $getCard);

        $this->assertEquals($expectedCard->getID(), $card->getID());
        $this->assertEquals($expectedCard->getPublicKey(), $card->getPublicKey());
        $this->assertEquals($expectedCard->getIdentity(), $card->getIdentity());
        $this->assertEquals($expectedCard->getVersion(), $card->getVersion());
        $this->assertEquals($expectedCard->getCreatedAt(), $card->getCreatedAt());
        $this->assertEquals($expectedCard->isOutdated(), $card->isOutdated());
        $this->assertEquals($expectedCard->getContentSnapshot(), $card->getContentSnapshot());
        $this->assertEquals($expectedCard->getPreviousCardId(), $card->getPreviousCardId());
        $this->assertEquals($expectedCard->getPreviousCard(), $card->getPreviousCard());

        $this->assertCount(2, $card->getSignatures());
        $this->assertCount(1, $expectedCard->getSignatures());
    }


    /**
     * @test
     */
    public function STC18()
    {
        $cardManager = $this->getCardManager();
        $identity = $this->baseIdentityGenerator('Alice')();

        $this->cardVerifier = null;
        $cardManagerNoVerify = $this->getCardManager();

        $keys = $this->virgilCrypto->generateKeys();
        $cardParams = CardParams::create(
            [
                CardParams::Identity    => $identity,
                CardParams::PublicKey   => $keys->getPublicKey(),
                CardParams::PrivateKey  => $keys->getPrivateKey(),
                CardParams::ExtraFields => [
                    'john' => 'doe',
                    'fire' => 'fox',
                ],
            ]
        );

        $rawCard = $cardManagerNoVerify->generateRawCard($cardParams);

        $expectedCard = $cardManagerNoVerify->importCard($rawCard);

        $card = $cardManager->publishCard($cardParams);

        $getCard = $cardManager->getCard($card->getID());

        $this->assertEquals($card, $getCard);

        $this->assertEquals($expectedCard->getID(), $card->getID());
        $this->assertEquals($expectedCard->getPublicKey(), $card->getPublicKey());
        $this->assertEquals($expectedCard->getIdentity(), $card->getIdentity());
        $this->assertEquals($expectedCard->getVersion(), $card->getVersion());
        $this->assertEquals($expectedCard->getCreatedAt(), $card->getCreatedAt());
        $this->assertEquals($expectedCard->isOutdated(), $card->isOutdated());
        $this->assertEquals($expectedCard->getContentSnapshot(), $card->getContentSnapshot());
        $this->assertEquals($expectedCard->getPreviousCardId(), $card->getPreviousCardId());
        $this->assertEquals($expectedCard->getPreviousCard(), $card->getPreviousCard());

        $this->assertCount(2, $card->getSignatures());
        $this->assertCount(1, $expectedCard->getSignatures());
    }


    /**
     * @test
     */
    public function STC19()
    {
        $cardManager = $this->getCardManager();
        $identity = $this->baseIdentityGenerator('Alice')();

        $keys1 = $this->virgilCrypto->generateKeys();
        $card1 = $cardManager->publishCard(
            CardParams::create(
                [
                    CardParams::Identity    => $identity,
                    CardParams::PublicKey   => $keys1->getPublicKey(),
                    CardParams::PrivateKey  => $keys1->getPrivateKey(),
                    CardParams::ExtraFields => [
                        'john' => 'doe',
                        'fire' => 'fox',
                    ],
                ]
            )
        );


        $keys2 = $this->virgilCrypto->generateKeys();
        $card2 = $cardManager->publishCard(
            CardParams::create(
                [
                    CardParams::Identity       => $identity,
                    CardParams::PublicKey      => $keys2->getPublicKey(),
                    CardParams::PrivateKey     => $keys2->getPrivateKey(),
                    CardParams::PreviousCardID => $card1->getID(),
                ]
            )
        );

        $this->assertFalse($card1->isOutdated());

        $card1 = $cardManager->getCard($card1->getID());

        $this->assertTrue($card1->isOutdated());
        $this->assertFalse($card2->isOutdated());

        $this->assertEquals($card1->getID(), $card2->getPreviousCardId());
    }


    /**
     * @test
     */
    public function STC20()
    {
        $cardManager = $this->getCardManager();
        $identity = $this->baseIdentityGenerator('Alice')();

        $keys1 = $this->virgilCrypto->generateKeys();
        $card1 = $cardManager->publishCard(
            CardParams::create(
                [
                    CardParams::Identity    => $identity,
                    CardParams::PublicKey   => $keys1->getPublicKey(),
                    CardParams::PrivateKey  => $keys1->getPrivateKey(),
                    CardParams::ExtraFields => [
                        'john' => 'doe',
                        'fire' => 'fox',
                    ],
                ]
            )
        );


        $keys2 = $this->virgilCrypto->generateKeys();
        $card2 = $cardManager->publishCard(
            CardParams::create(
                [
                    CardParams::Identity       => $identity,
                    CardParams::PublicKey      => $keys2->getPublicKey(),
                    CardParams::PrivateKey     => $keys2->getPrivateKey(),
                    CardParams::PreviousCardID => $card1->getID(),
                ]
            )
        );

        $keys3 = $this->virgilCrypto->generateKeys();
        $card3 = $cardManager->publishCard(
            CardParams::create(
                [
                    CardParams::Identity   => $identity,
                    CardParams::PublicKey  => $keys3->getPublicKey(),
                    CardParams::PrivateKey => $keys3->getPrivateKey(),
                ]
            )
        );

        $cards = $cardManager->searchCards($identity);

        $this->assertCount(2, $cards);

        foreach ($cards as $c) {
            if ($c->getID() == $card2->getID()) {
                $card2Search = $c;
            }
            if ($c->getID() == $card3->getID()) {
                $card3Search = $c;
            }
        }

        //update card1
        $card1 = $cardManager->getCard($card1->getID());
        $this->assertTrue($card1->isOutdated());

        $this->assertEquals($card2Search->getID(), $card2->getID());
        $this->assertEquals($card2Search->getPreviousCardId(), $card1->getID());
        $this->assertEquals($card2Search->getPreviousCard(), $card1);
        $this->assertFalse($card2Search->isOutdated());

        $this->assertEquals($card3Search->getID(), $card3->getID());
        $this->assertEquals($card3Search->getPreviousCardId(), "");
        $this->assertEquals($card3Search->getPreviousCard(), null);
        $this->assertFalse($card3Search->isOutdated());
    }

    /**
     * @test
     * @expectedException \Virgil\Sdk\CardClientException
     */
    public function STC34()
    {
        $this->cardVerifier =  new NullCardVerifier();

        $cardManager = $this->getCardManager();

        $cardManager->getCard('375f795bf6799b18c4836d33dce5208daf0895a3f7aacbcd0366529aed2345d4');
    }
}
