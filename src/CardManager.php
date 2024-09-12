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

declare(strict_types=1);

namespace Virgil\Sdk;

use DateTime;
use Virgil\Crypto\Core\Enum\HashAlgorithms;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Exceptions\CardClientException;
use Virgil\Sdk\Exceptions\CardVerificationException;
use Virgil\Sdk\Exceptions\VirgilException;
use Virgil\Sdk\Http\VirgilAgent\HttpVirgilAgent;
use Virgil\Sdk\Signer\ModelSigner;
use Virgil\Sdk\Verification\CardVerifier;
use Virgil\Sdk\Verification\NullCardVerifier;
use Virgil\Sdk\Web\ErrorResponseModel;
use Virgil\Sdk\Web\CardClient;
use Virgil\Sdk\Web\RawCardContent;
use Virgil\Sdk\Web\RawSignature;
use Virgil\Sdk\Web\RawSignedModel;
use Virgil\Sdk\Web\Authorization\AccessToken;
use Virgil\Sdk\Web\Authorization\AccessTokenProvider;
use Virgil\Sdk\Web\Authorization\TokenContext;
use \Virgil\Crypto\Exceptions\VirgilCryptoException;

/**
 * Class CardManager
 */
class CardManager
{
    /**
     * @var (RawSignedModel) -> RawSignedModel callable|null
     */
    private $signCallback;
    /**
     * @var ModelSigner
     */
    private ModelSigner $modelSigner;
    /**
     * @var NullCardVerifier|CardVerifier|null
     */
    private NullCardVerifier|null|CardVerifier $cardVerifier;
    /**
     * @var CardClient|null
     */
    private ?CardClient $cardClient;

    public function __construct(
        private readonly VirgilCrypto $virgilCrypto,
        private readonly AccessTokenProvider $accessTokenProvider,
        CardVerifier $cardVerifier = null,
        CardClient $cardClient = null,
        callable $signCallback = null
    ) {
        if ($cardClient === null) {
            $cardClient = new CardClient(new HttpVirgilAgent());
        }

        if ($cardVerifier === null) {
            $cardVerifier = new NullCardVerifier();
        }

        $this->modelSigner = new ModelSigner($virgilCrypto);
        $this->cardClient = $cardClient;
        $this->signCallback = $signCallback;
        $this->cardVerifier = $cardVerifier;
    }


    /**
     * @throws VirgilCryptoException
     */
    public function generateRawCard(CardParams $cardParams): RawSignedModel
    {
        $now = new DateTime();
        $publicKeyString = $this->virgilCrypto->exportPublicKey($cardParams->getPublicKey());

        $rawCardContent = new RawCardContent(
            $cardParams->getIdentity(),
            base64_encode($publicKeyString),
            '5.0',
            $now->getTimestamp(),
            $cardParams->getPreviousCardID()
        );

        $rawCardContentSnapshot = json_encode($rawCardContent, JSON_UNESCAPED_SLASHES);
        $rawSignedModel = new RawSignedModel($rawCardContentSnapshot, []);

        try {
            $privateKey = $cardParams->getPrivateKey();
            $extraFields = $cardParams->getExtraFields();
            $this->modelSigner->selfSign($rawSignedModel, $privateKey, $extraFields);
        } catch (VirgilException $e) {
            // Ignoring exception for models with empty signatures
        }

        return $rawSignedModel;
    }


    /**
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function publishRawSignedModel(RawSignedModel $rawSignedModel): Card
    {
        $contentSnapshot = json_decode($rawSignedModel->getContentSnapshot(), true);

        $tokenContext = new TokenContext($contentSnapshot['identity'], 'publish');
        $token = $this->accessTokenProvider->getToken($tokenContext);

        $card = $this->publishRawSignedModelWithToken($rawSignedModel, $token);
        if (!$this->cardVerifier->verifyCard($card)) {
            throw new CardVerificationException('Validation errors have been detected');
        }

        return $card;
    }


    /**
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function publishCard(CardParams $cardParams): Card
    {
        $tokenContext = new TokenContext($cardParams->getIdentity(), 'publish');
        $token = $this->accessTokenProvider->getToken($tokenContext);

        $rawSignedModel = $this->generateRawCard(
            CardParams::create(
                [
                    CardParams::IDENTITY => $token->identity(),
                    CardParams::PRIVATE_KEY => $cardParams->getPrivateKey(),
                    CardParams::PUBLIC_KEY => $cardParams->getPublicKey(),
                    CardParams::EXTRA_FIELDS => $cardParams->getExtraFields(),
                    CardParams::PREVIOUS_CARD_ID => $cardParams->getPreviousCardID(),
                ]
            )
        );

        $card = $this->publishRawSignedModelWithToken($rawSignedModel, $token);

        if (!$this->cardVerifier->verifyCard($card)) {
            throw new CardVerificationException('Validation errors have been detected');
        }

        return $card;
    }


    /**
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function getCard(string $cardID): Card
    {
        $tokenContext = new TokenContext("", 'get');
        $token = $this->accessTokenProvider->getToken($tokenContext);

        $responseModel = $this->cardClient->getCard($cardID, (string) $token);
        if ($responseModel instanceof ErrorResponseModel) {
            throw new CardClientException(
                "error response from card service",
                $responseModel->getCode(),
                $responseModel->getMessage()
            );
        }

        $card = $this->parseRawCard($responseModel->getRawSignedModel(), $responseModel->isOutdated());

        if (!$this->cardVerifier->verifyCard($card)) {
            throw new CardVerificationException('Validation errors have been detected');
        }

        return $card;
    }


    /**
     * @return Card[]
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function searchCards(string $identity): array
    {
        $tokenContext = new TokenContext($identity, 'search');
        $token = $this->accessTokenProvider->getToken($tokenContext);

        $responseModel = $this->cardClient->searchCards($identity, (string) $token);
        if ($responseModel instanceof ErrorResponseModel) {
            throw new CardClientException(
                "error response from card service",
                $responseModel->getCode(),
                $responseModel->getMessage()
            );
        }

        $cards = [];
        foreach ($responseModel as $model) {
            $card = $this->parseRawCard($model, false);
            if (!$this->cardVerifier->verifyCard($card)) {
                throw new CardVerificationException('Validation errors have been detected');
            }

            $cards[] = $card;
        }

        return $this->linkCards($cards);
    }


    /**
     * @throws CardClientException
     */
    public function revokeCard(string $cardID): void
    {
        $tokenContext = new TokenContext("", 'revoke');
        $token = $this->accessTokenProvider->getToken($tokenContext);

        $responseModel = $this->cardClient->revokeCard($cardID, (string) $token);
        if ($responseModel instanceof ErrorResponseModel) {
            throw new CardClientException(
                "error response from card service",
                $responseModel->getCode(),
                $responseModel->getMessage()
            );
        }
    }


    /**
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function importCardFromString(string $stringCard): Card
    {
        return $this->importCard(RawSignedModel::rawSignedModelFromBase64String($stringCard));
    }


    /**
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function importCard(RawSignedModel $rawSignedModel): Card
    {
        $card = $this->parseRawCard($rawSignedModel);

        if (!$this->cardVerifier->verifyCard($card)) {
            throw new CardVerificationException('Validation errors have been detected');
        }

        return $card;
    }


    /**
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function importCardFromJson(string $json): Card
    {
        return $this->importCard(RawSignedModel::rawSignedModelFromJson($json));
    }


    public function exportCardAsString(Card $card): string
    {
        return $this->exportCardAsRawCard($card)->exportAsBase64String();
    }


    public function exportCardAsJson(Card $card): string
    {
        return $this->exportCardAsRawCard($card)->exportAsJson();
    }


    public function exportCardAsRawCard(Card $card): RawSignedModel
    {
        $modelSignatures = [];
        foreach ($card->getSignatures() as $cardSignature) {
            $modelSignatures[] = new RawSignature(
                $cardSignature->getSigner(),
                $cardSignature->getSignature(),
                $cardSignature->getSnapshot()
            );
        }

        return new RawSignedModel($card->getContentSnapshot(), $modelSignatures);
    }


    /**
     * @throws CardClientException
     * @throws VirgilCryptoException
     */
    private function publishRawSignedModelWithToken(RawSignedModel $model, AccessToken $token): Card
    {
        if (is_callable($this->signCallback)) {
            $signCallback = $this->signCallback;
            $model = $signCallback($model);
        }

        $responseModel = $this->cardClient->publishCard($model, (string) $token);
        if ($responseModel instanceof ErrorResponseModel) {
            throw new CardClientException(
                "error response from card service",
                $responseModel->getCode(),
                $responseModel->getMessage()
            );
        }

        return $this->parseRawCard($responseModel);
    }


    private function generateCardID(VirgilCrypto $virgilCrypto, string $snapshot): string
    {
        return bin2hex(substr($virgilCrypto->computeHash($snapshot, HashAlgorithms::SHA512()), 0, 32));
    }


    /**
     * @throws VirgilCryptoException
     */
    private function parseRawCard(RawSignedModel $rawSignedModel, bool $isOutdated = false): Card
    {
        $contentSnapshotArray = json_decode($rawSignedModel->getContentSnapshot(), true);

        $cardSignatures = [];
        foreach ($rawSignedModel->getSignatures() as $signature) {
            $extraFields = null;
            if ($signature->getSnapshot() !== null) {
                $extraFields = json_decode($signature->getSnapshot(), true);
            }

            $cardSignatures[] = new CardSignature(
                $signature->getSigner(),
                $signature->getSignature(),
                $signature->getSnapshot(),
                $extraFields
            );
        }

        $publicKey = $this->virgilCrypto->importPublicKey(base64_decode($contentSnapshotArray['public_key']));

        $previousCardID = null;
        if (array_key_exists('previous_card_id', $contentSnapshotArray)) {
            $previousCardID = $contentSnapshotArray['previous_card_id'];
        }

        return new Card(
            $this->generateCardID($this->virgilCrypto, $rawSignedModel->getContentSnapshot()),
            $contentSnapshotArray['identity'],
            $publicKey,
            $contentSnapshotArray['version'],
            (new DateTime())->setTimestamp($contentSnapshotArray['created_at']),
            $isOutdated,
            $cardSignatures,
            $rawSignedModel->getContentSnapshot(),
            $previousCardID
        );
    }


    /**
     * @param Card[] $cards
     * @return Card[]
     */
    private function linkCards(array $cards): array
    {
        /** @var Card[] $linkedCards */
        $linkedCards = [];
        foreach ($cards as $card) {
            if ($card->getID() === '') {
                continue;
            }
            foreach ($cards as $previousCard) {
                if ($card->getPreviousCardId() === $previousCard->getID()) {
                    $linkedCards[] = new Card(
                        $card->getID(),
                        $card->getIdentity(),
                        $card->getPublicKey(),
                        $card->getVersion(),
                        $card->getCreatedAt(),
                        $card->isOutdated(),
                        $card->getSignatures(),
                        $card->getContentSnapshot(),
                        $card->getPreviousCardId(),
                        new Card(
                            $previousCard->getID(),
                            $previousCard->getIdentity(),
                            $previousCard->getPublicKey(),
                            $previousCard->getVersion(),
                            $previousCard->getCreatedAt(),
                            true,
                            $previousCard->getSignatures(),
                            $previousCard->getContentSnapshot()
                        )
                    );

                    break;
                }
            }
        }

        foreach ($cards as $card) {
            $isCardAdded = false;
            foreach ($linkedCards as $linkedCard) {
                if ($card->getID() === '') {
                    break;
                }

                if ($linkedCard->getID() === $card->getID()) {
                    $isCardAdded = true;
                } else {
                    $previousCard = $linkedCard->getPreviousCard();
                    if (null !== $previousCard && $previousCard->getID() === $card->getID()) {
                        $isCardAdded = true;
                    }
                }
            }
            if (!$isCardAdded) {
                $linkedCards[] = $card;
            }
        }

        return $linkedCards;
    }
}
