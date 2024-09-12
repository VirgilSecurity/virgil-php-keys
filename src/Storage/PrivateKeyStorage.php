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

namespace Virgil\Sdk\Storage;

use Virgil\Crypto\Core\VirgilKeys\VirgilPrivateKey;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Sdk\Exceptions\VirgilException;

/**
 * Class PrivateKeyStorage
 */
class PrivateKeyStorage
{
    /**
     * @var KeyStorage
     */
    protected KeyStorage $keyStorage;


    /**
     * @throws VirgilException
     */
    public function __construct(private readonly VirgilCrypto $virgilCrypto, string $storagePath)
    {
        $this->keyStorage = new KeyStorage($storagePath);
    }

    /**
     * @param VirgilPrivateKey $privateKey
     * @param string $name
     * @param array|null $meta
     * @return void
     * @throws VirgilCryptoException
     * @throws VirgilException
     */
    public function store(VirgilPrivateKey $privateKey, string $name, ?array $meta = null): void
    {
        $exportedData = $this->virgilCrypto->exportPrivateKey($privateKey);

        $this->keyStorage->store(new KeyEntry($name, $exportedData, $meta));
    }


    /**
     * @throws VirgilException
     * @throws VirgilCryptoException
     */
    public function load(string $name): PrivateKeyEntry
    {
        $keyEntry = $this->keyStorage->load($name);
        $privateKey = $this->virgilCrypto->importPrivateKey($keyEntry->getValue());

        return new PrivateKeyEntry($privateKey->getPrivateKey(), $keyEntry->getMeta());
    }


    /**
     * @throws VirgilException
     */
    public function delete(string $name): void
    {
        $this->keyStorage->delete($name);
    }
}
