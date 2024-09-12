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

use Virgil\Crypto\Core\VirgilKeys\VirgilPrivateKey;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKey;

/**
 * Class CardParams
 */
class CardParams
{
    public const string PUBLIC_KEY = 'public_key';
    public const string PRIVATE_KEY = 'private_key';
    public const string IDENTITY = 'identity';
    public const string PREVIOUS_CARD_ID = 'previous_card_ID';
    public const string EXTRA_FIELDS = 'extra_fields';

    public function __construct(
        private readonly VirgilPublicKey $publicKey,
        private readonly VirgilPrivateKey $privateKey,
        private ?string $identity = null,
        private ?string $previousCardID = null,
        private ?array $extraFields = null
    ) {
    }


    public static function create(array $params): CardParams
    {
        $publicKey = $params[self::PUBLIC_KEY];
        $privateKey = $params[self::PRIVATE_KEY];

        $cardParams = new self($publicKey, $privateKey);

        if (array_key_exists(self::IDENTITY, $params)) {
            $cardParams->identity = $params[self::IDENTITY];
        }
        if (array_key_exists(self::PREVIOUS_CARD_ID, $params)) {
            $cardParams->previousCardID = $params[self::PREVIOUS_CARD_ID];
        }
        if (array_key_exists(self::EXTRA_FIELDS, $params)) {
            $cardParams->extraFields = $params[self::EXTRA_FIELDS];
        }

        return $cardParams;
    }


    public function getPublicKey(): VirgilPublicKey
    {
        return $this->publicKey;
    }


    public function getPrivateKey(): VirgilPrivateKey
    {
        return $this->privateKey;
    }


    public function getIdentity(): ?string
    {
        return $this->identity;
    }


    public function getPreviousCardID(): ?string
    {
        return $this->previousCardID;
    }


    public function getExtraFields(): ?array
    {
        return $this->extraFields;
    }
}
