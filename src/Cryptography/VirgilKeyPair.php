<?php

namespace Virgil\SDK\Cryptography;


class VirgilKeyPair implements KeyPair
{
    /** @var VirgilKey */
    protected $publicKey;

    /** @var VirgilKey */
    protected $privateKey;

    /**
     * VirgilKeyPair constructor.
     * @param VirgilKey $publicKey
     * @param VirgilKey $privateKey
     */
    public function __construct(VirgilKey $publicKey, VirgilKey $privateKey)
    {
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    /**
     * @return VirgilKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return VirgilKey
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }
}