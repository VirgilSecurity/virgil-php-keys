<?php

declare(strict_types=1);

require '../vendor/autoload.php';

use Virgil\Crypto\Core\VirgilKeys\VirgilKeyPair;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Card;
use Virgil\Sdk\CardManager;
use Virgil\Sdk\CardParams;
use Virgil\Sdk\Exceptions\CardClientException;
use Virgil\Sdk\Exceptions\CardVerificationException;
use Virgil\Sdk\Exceptions\VirgilException;
use Virgil\Sdk\Http\VirgilAgent\HttpVirgilAgent;
use Virgil\Sdk\Storage\PrivateKeyStorage;
use Virgil\Sdk\Verification\VirgilCardVerifier;
use Virgil\Sdk\Web\Authorization\CallbackJwtProvider;
use Virgil\Sdk\Web\Authorization\JwtGenerator;
use \Virgil\Crypto\Core\VirgilKeys\VirgilPublicKeyCollection;
use Virgil\Sdk\Web\CardClient;
use \Virgil\Sdk\Storage\PrivateKeyEntry;

/**
 * Class VirgilCryptoSample
 */
class VirgilCryptoSample
{
    private array $auth;

    private string $identity;

    private VirgilKeyPair $keyPair;

    private PrivateKeyStorage $privateKeyStorage;

    private string $storagePath = "./keys/";

    /**
     * @throws VirgilException
     */
    public function __construct()
    {
        $this->auth = [
            'serviceAddress' => $_ENV["SERVICE_ADDRESS"],
            'serviceKey' => $_ENV["SERVICE_KEY"],
            'apiKey' => $_ENV["SAMPLE_API_KEY"],
            'apiKeyId' => $_ENV["SAMPLE_API_KEY_ID"],
            'appId' => $_ENV["SAMPLE_APP_ID"],
            'ttl' => (int)$_ENV["SAMPLE_JWT_TTL"]
        ];

        $this->keyPair = $this->generateKeys();

        $this->privateKeyStorage = new PrivateKeyStorage($this->getVirgilCrypto(), $this->storagePath);
    }

    // PUBLIC FUNCTIONS:

    /**
     * @param string $identity
     * @return void
     */
    public function setIdentity(string $identity): void
    {
        $this->identity = $identity;
    }

    /**
     * @return Card
     * @throws VirgilException
     * @throws CardClientException
     * @throws CardVerificationException
     */
    public function storePrivateKeyAndCreateCard(): Card
    {
        $this->storePrivateKey($this->identity);
        return $this->createCard();
    }

    /**
     * @param string $recipientIdentity
     * @param string $dataToEncrypt
     * @return string|null
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilException
     * @throws VirgilCryptoException
     */
    public function signThenEncryptData(string $recipientIdentity, string $dataToEncrypt): ?string
    {
        $cards = $this->getUserCardsByIdentity($recipientIdentity);

        $keyCollection = new VirgilPublicKeyCollection();
        foreach ($cards as $card) {
            $keyCollection->addPublicKey($card->getPublicKey());
        }

        return $this->getVirgilCrypto()->signAndEncrypt(
            $dataToEncrypt,
            $this->loadPrivateKey($this->identity)->getPrivateKey(),
            $keyCollection
        );
    }

    /**
     * @param string $senderIdentity
     * @param string $dataToDecrypt
     * @return string|null
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     * @throws VirgilException
     */
    public function decryptDataThenVerifySignature(string $senderIdentity, string $dataToDecrypt): ?string
    {
        $senderCards = $this->getUserCardsByIdentity($senderIdentity);
        $keyCollection = new VirgilPublicKeyCollection();

        foreach ($senderCards as $card) {
            $keyCollection->addPublicKey($card->getPublicKey());
        }

        return $this->getVirgilCrypto()->decryptAndVerify(
            $dataToDecrypt,
            $this->loadPrivateKey($this->identity)->getPrivateKey(),
            $keyCollection
        );
    }

    /**
     * @param string $identity
     * @return void
     * @throws VirgilCryptoException
     * @throws VirgilException
     */
    public function storePrivateKey(string $identity): void
    {
        $this->privateKeyStorage->store($this->keyPair->getPrivateKey(), $identity);
    }

    /**
     * @param string $identity
     * @return PrivateKeyEntry
     * @throws VirgilCryptoException
     * @throws VirgilException
     */
    public function loadPrivateKey(string $identity): PrivateKeyEntry
    {
        return $this->privateKeyStorage->load($identity);
    }

    /**
     * @param string $identity
     * @return void
     * @throws VirgilException
     */
    public function deletePrivateKey(string $identity): void
    {
        $this->privateKeyStorage->delete($identity);
    }

    /**
     * @param string $identity
     * @return array
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function getUserCardsByIdentity(string $identity): array
    {
        return $this->getCardManager()->searchCards($identity);
    }

    /**
     * @param string $id
     * @return Card
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    public function getUserCardById(string $id): Card
    {
        return $this->getCardManager()->getCard($id);
    }

    // PRIVATE FUNCTIONS:

    /**
     * @return VirgilCrypto
     */
    private function getVirgilCrypto(): VirgilCrypto
    {
        return new VirgilCrypto();
    }

    /**
     * @return VirgilCardVerifier
     * @throws VirgilCryptoException
     */
    private function getCardVerifier(): VirgilCardVerifier
    {
        return new VirgilCardVerifier(
            $this->getVirgilCrypto(),
            true,
            true,
            [],
            $this->auth['serviceKey']
        );
    }

    /**
     * @return CardManager
     * @throws VirgilCryptoException
     */
    private function getCardManager(): CardManager
    {
        return new CardManager(
            $this->getVirgilCrypto(),
            $this->setUpJWTProvider(),
            $this->getCardVerifier(),
            new CardClient(new HttpVirgilAgent(), $this->auth['serviceAddress'])
        );
    }

    /**
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    private function generateKeys(): VirgilKeyPair
    {
        return $this->getVirgilCrypto()->generateKeyPair();
    }

    /**
     * @return string
     * @throws VirgilCryptoException
     */
    private function getGeneratedJWT(): string
    {
        $privateKeyStr = $this->auth['apiKey'];
        $apiKeyData = base64_decode($privateKeyStr);

        $privateKey = $this->getVirgilCrypto()->importPrivateKey($apiKeyData);

        $jwtGenerator = new JwtGenerator($privateKey->getPrivateKey(), $this->auth['apiKeyId'],
            $this->getVirgilCrypto(), $this->auth['appId'],
            $this->auth['ttl']);

        $token = $jwtGenerator->generateToken($this->identity);

        return $token->__toString();
    }

    /**
     * @return CallbackJwtProvider
     * @throws VirgilCryptoException
     */
    private function setUpJWTProvider(): CallbackJwtProvider
    {
        $jwt = $this->getGeneratedJWT();

        $authenticatedQueryToServerSide = function () use ($jwt) {
            return $jwt;
        };

        return new CallbackJwtProvider($authenticatedQueryToServerSide);
    }

    /**
     * @return Card
     * @throws CardClientException
     * @throws CardVerificationException
     * @throws VirgilCryptoException
     */
    private function createCard(): Card
    {
        return $this->getCardManager()->publishCard(
            CardParams::create(
                [
                    CardParams::IDENTITY => $this->identity,
                    CardParams::PUBLIC_KEY => $this->keyPair->getPublicKey(),
                    CardParams::PRIVATE_KEY => $this->keyPair->getPrivateKey(),
                ]
            )
        );
    }
}
