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

use Virgil\Sdk\Exceptions\VirgilException;

/**
 * Class KeyStorage
 */
class KeyStorage
{
    /** @var string */
    private string $keysPath;

    /**
     * @throws VirgilException
     */
    public function __construct(string $keysPath)
    {
        if (!file_exists($keysPath)) {
            mkdir($keysPath, 0755, true);
        }

        if (!is_dir($keysPath)) {
            throw new VirgilException('Provided keys storage path should be directory');
        }

        if (!is_readable($keysPath)) {
            throw new VirgilException('Provided keys storage path should be readable');
        }

        if (!is_writeable($keysPath)) {
            throw new VirgilException('Provided keys storage path should be writable');
        }

        $this->keysPath = $keysPath;
    }


    /**
     * @throws VirgilException
     */
    public function store(KeyEntry $keyEntry): KeyStorage
    {
        $file = $this->buildFilePath($keyEntry->getName());

        $wroteBytes = file_put_contents($file, json_encode($keyEntry));

        if ($wroteBytes === false) {
            throw new VirgilException('Could not write key.');
        }

        return $this;
    }


    /**
     * @throws VirgilException
     */
    public function load(string $keyName): KeyEntry
    {
        $file = $this->buildFilePath($keyName);

        $keyValue = file_get_contents($file);

        if ($keyValue === false) {
            throw new VirgilException('Could not read key.');
        }

        $keyValueData = json_decode($keyValue, true);

        return new KeyEntry($keyName, base64_decode($keyValueData['value']), $keyValueData['meta']);
    }


    public function exists(string $keyName): bool
    {
        $file = $this->buildFilePath($keyName);

        return file_exists($file);
    }


    /**
     * @throws VirgilException
     */
    public function delete(string $keyName): KeyStorage
    {
        $file = $this->buildFilePath($keyName);

        $isKeyDeleted = unlink($file);

        if (!$isKeyDeleted) {
            throw new VirgilException('Could not delete key.');
        }

        return $this;
    }


    /**
     * Builds file path to virgil key by name.
     */
    protected function buildFilePath(string $keyName): string
    {
        return rtrim($this->keysPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . md5($keyName);
    }
}
