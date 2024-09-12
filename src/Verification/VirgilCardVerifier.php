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

namespace Virgil\Sdk\Verification;

use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKey;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Card;

/**
 * Class VirgilCardVerifier
 */
class VirgilCardVerifier implements CardVerifier
{
    private const string VIRGIL_PUBLIC_KEY = "MCowBQYDK2VwAyEAljOYGANYiVq1WbvVvoYIKtvZi2ji9bAhxyu6iV/LF8M=";

    /**
     * @var VirgilPublicKey
     */
    private VirgilPublicKey $virgilPublicKey;

    /**
     * @throws VirgilCryptoException
     */
    public function __construct(
        private readonly VirgilCrypto $virgilCrypto,
        private readonly bool $verifySelfSignature = true,
        private readonly bool $verifyVirgilSignature = true,
        private readonly array $whiteLists = [],
        string $virgilPublicKey = self::VIRGIL_PUBLIC_KEY
    ) {
        if ($verifyVirgilSignature) {
            $this->virgilPublicKey = $virgilCrypto->importPublicKey(base64_decode($virgilPublicKey));
        }
    }


    /**
     * @throws VirgilCryptoException
     */
    public function verifyCard(Card $card): bool
    {
        if ($this->verifySelfSignature) {
            if (!$this->validateSignerSignature($card, 'self', $card->getPublicKey())) {
                return false;
            }
        }

        if ($this->verifyVirgilSignature) {
            if (!$this->validateSignerSignature($card, 'virgil', $this->virgilPublicKey)) {
                return false;
            }
        }

        foreach ($this->whiteLists as $whiteList) {
            $isOk = false;
            foreach ($whiteList->getCredentials() as $credentials) {
                if ($this->validateSignerSignature($card, $credentials->getSigner(), $credentials->getPublicKey())) {
                    $isOk = true;
                    break;
                }
            }

            if (!$isOk) {
                return false;
            }
        }

        return true;
    }


    /**
     * @throws VirgilCryptoException
     */
    private function validateSignerSignature(Card $card, string $signer, VirgilPublicKey $publicKey): bool
    {
        foreach ($card->getSignatures() as $cardSignature) {
            if ($cardSignature->getSigner() === $signer) {
                $snapshot = $card->getContentSnapshot();
                if ($cardSignature->getSnapshot() !== "") {
                    $snapshot .= $cardSignature->getSnapshot();
                }

                return $this->virgilCrypto->verifySignature($cardSignature->getSignature(), $snapshot, $publicKey);
            }
        }

        return false;
    }
}
